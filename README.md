# Chrome Password Decryptor (Red Team Lab)

This project demonstrates how to extract and decrypt saved passwords from **Google Chrome** on Windows, using Go. It is intended for **educational use only** in controlled, safe environments such as red team labs, penetration testing labs, or malware analysis sandboxes.

> 🚨 For ethical hacking & training purposes only. Do **not** use this code outside a legal lab or test environment.

---

## 🔍 Overview

Chrome stores user credentials encrypted on disk using Windows DPAPI and AES-GCM. This tool performs:

- **Step 1**: Extracts and decrypts Chrome’s AES encryption key using DPAPI
- **Step 2**: Reads the `Login Data` SQLite database and decrypts saved credentials

---

## ⚙️ Requirements

- Go 1.18+
- Kali Linux (for building)
- Windows 10+ (for running)

---

## 🛠 Usage

### 🔐 Step 1: Extract Chrome Master Key

```bash
GOOS=windows GOARCH=amd64 go build -o step1_key_extract.exe step1_key_extract.go
```
Run step1_key_extract.exe on a Windows system with Chrome installed to get the decrypted AES key.


### 🔓 Step 2: Dump & Decrypt Chrome Passwords

- Replace aesKeyHex in step2_decrypt_passwords.go with your decrypted key
- Build:
```
GOOS=windows GOARCH=amd64 go build -o step2_decrypt_passwords.exe step2_decrypt_passwords.go
```
- Run on the same Windows target

### 💡 Educational Use Only
This code is not intended for illegal use. It is built for:

Certified Ethical Hacker (CEH) students

- Red Team training
- Malware simulation labs
- CRTP / OSCP practice

### 📁 Repo Structure
```
.
├── step1_key_extract.go         # Extracts and decrypts Chrome master key
├── step2_decrypt_passwords.go  # Reads login data and decrypts saved passwords
├── go.mod / go.sum              # Dependencies
```
## 🙏 Credits
Inspired by red team lab techniques & real-world malware analysis.
Built with ❤️ for learning, not harm.

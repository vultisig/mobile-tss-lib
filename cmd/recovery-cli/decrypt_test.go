package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// Backup vectors produced by the iOS, web and extension clients
// (vultisig-android: data/src/test/resources/ios-backup-vectors).
var pbkdf2Vectors = []struct {
	name, password, plaintext, ciphertext string
}{
	{"ios", "ios-backup-test", "ios-vault-data-abc", "VkxUAhEREREREREREREREREREREiIiIiIiIiIiIiIiKkVKfBB781udjJZHri5f/jKie5Xsb4+QMQYZXgRTguEaj9"},
	{"web", "web-backup-test", "web-vault-data-123", "VkxUAlVVVVVVVVVVVVVVVVVVVVVmZmZmZmZmZmZmZmZr4T5NonTmP8O9liQ+wr3stndn68X5KkNDL2uuXdQCsSTO"},
	{"extension", "ext-backup-test", "extension-vault-data-xyz", "VkxUAjMzMzMzMzMzMzMzMzMzMzNERERERERERERERESValWh59NN5UIkkUqX4A+zulYM8mK8YPoD507DzKedPieXIywb8OeX"},
}

func TestDecryptVaultPbkdf2Vectors(t *testing.T) {
	for _, v := range pbkdf2Vectors {
		data, err := base64.StdEncoding.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("%s: bad vector: %v", v.name, err)
		}
		got, err := DecryptVault(v.password, data)
		if err != nil {
			t.Fatalf("%s: decrypt failed: %v", v.name, err)
		}
		if string(got) != v.plaintext {
			t.Fatalf("%s: got %q, want %q", v.name, got, v.plaintext)
		}
		if _, err := DecryptVault(v.password+"x", data); err == nil {
			t.Fatalf("%s: wrong password accepted", v.name)
		}
	}
}

func TestDecryptVaultLegacyStillWorks(t *testing.T) {
	password, msg := "legacy-pass", []byte("legacy vault bytes")
	key := sha256.Sum256([]byte(password))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	data := append(nonce, gcm.Seal(nil, nonce, msg, nil)...)

	got, err := DecryptVault(password, data)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("legacy: %v %q", err, got)
	}
}

func TestDecryptVaultPbkdf2TooShort(t *testing.T) {
	if _, err := DecryptVault("x", append([]byte("VLT\x02"), make([]byte, 10)...)); err == nil {
		t.Fatal("short payload accepted")
	}
}

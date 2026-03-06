package crypto

import (
	"strings"
	"testing"
)

func TestAESEncryptDecrypt(t *testing.T) {
	m := &AESModule{}
	key := []byte("test-key-32-bytes-long-padding!!")
	plaintext := []byte("hello world")

	ct, err := m.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(string(ct), aesPrefix) {
		t.Errorf("expected ENC: prefix, got %s", ct[:4])
	}

	pt, err := m.Decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("got %s, want %s", pt, plaintext)
	}
}

func TestAESRandomNonce(t *testing.T) {
	m := &AESModule{}
	key := []byte("key")
	plaintext := []byte("same plaintext")
	ct1, _ := m.Encrypt(plaintext, key)
	ct2, _ := m.Encrypt(plaintext, key)
	if string(ct1) == string(ct2) {
		t.Error("expected different ciphertexts for same plaintext (random nonce)")
	}
}

func TestAESDecryptNonEncrypted(t *testing.T) {
	m := &AESModule{}
	key := []byte("key")
	data := []byte("not encrypted")
	result, err := m.Decrypt(data, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "not encrypted" {
		t.Errorf("expected pass-through, got %s", result)
	}
}

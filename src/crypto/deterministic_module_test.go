package crypto

import (
	"strings"
	"testing"
)

func TestDeterministicEncryptDecrypt(t *testing.T) {
	m := &DeterministicModule{}
	key := []byte("test-key")
	plaintext := []byte("hello world")

	ct, err := m.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(string(ct), detPrefix) {
		t.Errorf("expected DET: prefix")
	}

	pt, err := m.Decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("got %s, want %s", pt, plaintext)
	}
}

func TestDeterministicSamePlaintextSameCiphertext(t *testing.T) {
	m := &DeterministicModule{}
	key := []byte("key")
	plaintext := []byte("same")
	ct1, _ := m.Encrypt(plaintext, key)
	ct2, _ := m.Encrypt(plaintext, key)
	if string(ct1) != string(ct2) {
		t.Error("deterministic encryption should produce same ciphertext for same plaintext+key")
	}
}

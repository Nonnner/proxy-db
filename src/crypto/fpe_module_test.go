package crypto

import (
	"strings"
	"testing"
)

func TestFPEDigitPreservation(t *testing.T) {
	m := &FPEModule{}
	key := []byte("test-key")
	plaintext := []byte("1234567890")

	ct, err := m.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ctStr := string(ct)
	if !strings.HasPrefix(ctStr, fpePrefix) {
		t.Errorf("expected FPE: prefix, got %s", ctStr)
	}
	inner := ctStr[len(fpePrefix):]
	if !isDigitString(inner) {
		t.Errorf("expected digit-only ciphertext for digit plaintext, got %s", inner)
	}
	if len(inner) != len(plaintext) {
		t.Errorf("expected same length %d, got %d", len(plaintext), len(inner))
	}

	pt, err := m.Decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("got %s, want %s", pt, plaintext)
	}
}

func TestFPENonDigitFallback(t *testing.T) {
	m := &FPEModule{}
	key := []byte("test-key")
	plaintext := []byte("hello@example.com")
	ct, err := m.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := m.Decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("got %s, want %s", pt, plaintext)
	}
}

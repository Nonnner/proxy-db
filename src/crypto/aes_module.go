package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const aesPrefix = "ENC:"

type AESModule struct{}

func (a *AESModule) Name() string { return "aes" }

func normalizeKey(key []byte) []byte {
	k := make([]byte, 32)
	copy(k, key)
	return k
}

func (a *AESModule) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	k := normalizeKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	encoded := aesPrefix + base64.StdEncoding.EncodeToString(ct)
	return []byte(encoded), nil
}

func (a *AESModule) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	s := string(ciphertext)
	if !strings.HasPrefix(s, aesPrefix) {
		return ciphertext, nil // not encrypted, return as-is
	}
	data, err := base64.StdEncoding.DecodeString(s[len(aesPrefix):])
	if err != nil {
		return nil, fmt.Errorf("aes decrypt base64: %w", err)
	}
	k := normalizeKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const detPrefix = "DET:"

type DeterministicModule struct{}

func (d *DeterministicModule) Name() string { return "deterministic" }

func deriveIV(key, plaintext []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(plaintext)
	sum := mac.Sum(nil)
	return sum[:aes.BlockSize]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	return padded
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-pad], nil
}

func (d *DeterministicModule) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	k := normalizeKey(key)
	iv := deriveIV(k, plaintext)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)
	combined := append(iv, ct...)
	encoded := detPrefix + base64.StdEncoding.EncodeToString(combined)
	return []byte(encoded), nil
}

func (d *DeterministicModule) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	s := string(ciphertext)
	if !strings.HasPrefix(s, detPrefix) {
		return ciphertext, nil
	}
	data, err := base64.StdEncoding.DecodeString(s[len(detPrefix):])
	if err != nil {
		return nil, fmt.Errorf("det decrypt base64: %w", err)
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("data too short")
	}
	iv := data[:aes.BlockSize]
	ct := data[aes.BlockSize:]
	k := normalizeKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pt, ct)
	return pkcs7Unpad(pt)
}

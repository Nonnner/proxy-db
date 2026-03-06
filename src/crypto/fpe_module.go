package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

const fpePrefix = "FPE:"

type FPEModule struct{}

func (f *FPEModule) Name() string { return "fpe" }

func generateDigitKeystream(key []byte, n int) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("fpe-iv"))
	iv := mac.Sum(nil)[:aes.BlockSize]

	block, err := aes.NewCipher(normalizeKey(key))
	if err != nil {
		return nil, err
	}
	needed := n * 4
	stream := make([]byte, needed)
	cipher.NewCTR(block, iv).XORKeyStream(stream, stream)

	digits := make([]byte, 0, n)
	for _, b := range stream {
		d := b % 10
		digits = append(digits, d)
		if len(digits) == n {
			break
		}
	}
	return digits, nil
}

func isDigitString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (f *FPEModule) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	s := string(plaintext)
	if isDigitString(s) {
		ks, err := generateDigitKeystream(normalizeKey(key), len(s))
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(s))
		for i, c := range s {
			d := (int(c-'0') + int(ks[i])) % 10
			result[i] = byte('0' + d)
		}
		return []byte(fpePrefix + string(result)), nil
	}
	a := &AESModule{}
	ct, err := a.Encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}
	return []byte(fpePrefix + string(ct[len(aesPrefix):])), nil
}

func (f *FPEModule) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	s := string(ciphertext)
	if !strings.HasPrefix(s, fpePrefix) {
		return ciphertext, nil
	}
	inner := s[len(fpePrefix):]
	if isDigitString(inner) {
		ks, err := generateDigitKeystream(normalizeKey(key), len(inner))
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(inner))
		for i, c := range inner {
			d := (int(c-'0') - int(ks[i]) + 10) % 10
			result[i] = byte('0' + d)
		}
		return result, nil
	}
	a := &AESModule{}
	return a.Decrypt([]byte(aesPrefix+inner), key)
}

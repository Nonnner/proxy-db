package crypto

import "fmt"

type EncryptionModule interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
	Name() string
}

type EncryptionEngine struct {
	modules map[string]EncryptionModule
}

func NewEncryptionEngine() *EncryptionEngine {
	return &EncryptionEngine{modules: make(map[string]EncryptionModule)}
}

func (e *EncryptionEngine) Register(module EncryptionModule) {
	e.modules[module.Name()] = module
}

func (e *EncryptionEngine) Get(name string) (EncryptionModule, error) {
	m, ok := e.modules[name]
	if !ok {
		return nil, fmt.Errorf("encryption module %q not found", name)
	}
	return m, nil
}

func (e *EncryptionEngine) Encrypt(moduleName string, plaintext []byte, key []byte) ([]byte, error) {
	m, err := e.Get(moduleName)
	if err != nil {
		return nil, err
	}
	return m.Encrypt(plaintext, key)
}

func (e *EncryptionEngine) Decrypt(moduleName string, ciphertext []byte, key []byte) ([]byte, error) {
	m, err := e.Get(moduleName)
	if err != nil {
		return nil, err
	}
	return m.Decrypt(ciphertext, key)
}

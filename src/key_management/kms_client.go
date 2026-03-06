package key_management

import (
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

type KeyManager interface {
	GetKey(keyID string) ([]byte, error)
	RotateKey(keyID string) error
}

type cachedKey struct {
	key       []byte
	expiresAt time.Time
}

type LocalKeyManager struct {
	keys     map[string][]byte
	cacheTTL time.Duration
	cache    map[string]cachedKey
	mu       sync.RWMutex
}

func NewLocalKeyManager(ttl time.Duration) *LocalKeyManager {
	return &LocalKeyManager{
		keys:     make(map[string][]byte),
		cacheTTL: ttl,
		cache:    make(map[string]cachedKey),
	}
}

func (l *LocalKeyManager) SetKey(keyID string, key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys[keyID] = key
}

func (l *LocalKeyManager) GetKey(keyID string) ([]byte, error) {
	l.mu.RLock()
	if c, ok := l.cache[keyID]; ok && time.Now().Before(c.expiresAt) {
		l.mu.RUnlock()
		return c.key, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()

	envKey := "PROXY_KEY_" + sanitizeKeyID(keyID)
	if val := os.Getenv(envKey); val != "" {
		key, err := hex.DecodeString(val)
		if err != nil {
			return nil, fmt.Errorf("invalid key in env %s: %w", envKey, err)
		}
		l.cache[keyID] = cachedKey{key: key, expiresAt: time.Now().Add(l.cacheTTL)}
		return key, nil
	}

	key, ok := l.keys[keyID]
	if !ok {
		key = deriveTestKey(keyID)
		l.keys[keyID] = key
	}
	l.cache[keyID] = cachedKey{key: key, expiresAt: time.Now().Add(l.cacheTTL)}
	return key, nil
}

func (l *LocalKeyManager) RotateKey(keyID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.cache, keyID)
	delete(l.keys, keyID)
	return nil
}

func sanitizeKeyID(keyID string) string {
	result := make([]byte, len(keyID))
	for i, c := range keyID {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result[i] = byte(c)
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}

// deriveTestKey generates a weak deterministic key from a keyID for local/test use only.
// WARNING: never use in production; configure real keys via environment variables or a KMS.
func deriveTestKey(keyID string) []byte {
	key := make([]byte, 32)
	for i, c := range []byte(keyID) {
		key[i%32] ^= c
	}
	return key
}

type KMSKeyManager struct {
	keyID string
	local *LocalKeyManager
}

func NewKMSKeyManager(keyID string, ttl time.Duration) *KMSKeyManager {
	return &KMSKeyManager{
		keyID: keyID,
		local: NewLocalKeyManager(ttl),
	}
}

func (k *KMSKeyManager) GetKey(keyID string) ([]byte, error) {
	return k.local.GetKey(keyID)
}

func (k *KMSKeyManager) RotateKey(keyID string) error {
	return k.local.RotateKey(keyID)
}

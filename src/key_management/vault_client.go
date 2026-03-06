package key_management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type VaultKeyManager struct {
	addr     string
	token    string
	cache    map[string]cachedKey
	cacheMu  sync.RWMutex
	cacheTTL time.Duration
	client   *http.Client
}

func NewVaultKeyManager(addr, token string, ttl time.Duration) *VaultKeyManager {
	return &VaultKeyManager{
		addr:     addr,
		token:    token,
		cache:    make(map[string]cachedKey),
		cacheTTL: ttl,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *VaultKeyManager) GetKey(keyID string) ([]byte, error) {
	v.cacheMu.RLock()
	if c, ok := v.cache[keyID]; ok && time.Now().Before(c.expiresAt) {
		v.cacheMu.RUnlock()
		return c.key, nil
	}
	v.cacheMu.RUnlock()

	url := fmt.Sprintf("%s/v1/secret/data/%s", v.addr, keyID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault get key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("vault parse response: %w", err)
	}

	val, ok := result.Data.Data["value"]
	if !ok {
		return nil, fmt.Errorf("key %q not found in vault", keyID)
	}

	key := []byte(val)
	v.cacheMu.Lock()
	v.cache[keyID] = cachedKey{key: key, expiresAt: time.Now().Add(v.cacheTTL)}
	v.cacheMu.Unlock()

	return key, nil
}

func (v *VaultKeyManager) RotateKey(keyID string) error {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	delete(v.cache, keyID)
	return nil
}

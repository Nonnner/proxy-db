package resultset

import (
	"fmt"

	"github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
)

type DecryptPipeline struct {
	policy *policy.Policy
	crypto *crypto.EncryptionEngine
	keyMgr key_management.KeyManager
}

func NewDecryptPipeline(p *policy.Policy, e *crypto.EncryptionEngine, km key_management.KeyManager) *DecryptPipeline {
	return &DecryptPipeline{policy: p, crypto: e, keyMgr: km}
}

func (d *DecryptPipeline) DecryptRow(table string, row map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(row))
	for col, val := range row {
		cp, ok := d.policy.GetColumnPolicy(table, col)
		if !ok {
			result[col] = val
			continue
		}
		key, err := d.keyMgr.GetKey(cp.KeyID)
		if err != nil {
			return nil, fmt.Errorf("get key %s: %w", cp.KeyID, err)
		}
		pt, err := d.crypto.Decrypt(cp.Encryption, []byte(val), key)
		if err != nil {
			result[col] = val
			continue
		}
		result[col] = string(pt)
	}
	return result, nil
}

func (d *DecryptPipeline) DecryptRows(table string, rows []map[string]string) ([]map[string]string, error) {
	result := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		decrypted, err := d.DecryptRow(table, row)
		if err != nil {
			return nil, err
		}
		result = append(result, decrypted)
	}
	return result, nil
}

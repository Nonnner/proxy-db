package policy

import (
	"testing"

	"github.com/Nonnner/proxy-db/src/config"
)

func TestPolicyLookup(t *testing.T) {
	tables := map[string]config.TablePolicy{
		"users": {
			Columns: map[string]config.ColumnPolicy{
				"email": {Encryption: "deterministic", KeyID: "key-1"},
				"name":  {Encryption: "aes", KeyID: "key-2"},
			},
		},
	}
	p := NewPolicy(tables)

	cp, ok := p.GetColumnPolicy("users", "email")
	if !ok {
		t.Fatal("expected policy for users.email")
	}
	if cp.Encryption != "deterministic" {
		t.Errorf("expected deterministic, got %s", cp.Encryption)
	}

	if !p.IsEncrypted("users", "name") {
		t.Error("users.name should be encrypted")
	}

	if p.IsEncrypted("users", "id") {
		t.Error("users.id should not be encrypted")
	}

	cols := p.EncryptedColumns("users")
	if len(cols) != 2 {
		t.Errorf("expected 2 encrypted columns, got %d", len(cols))
	}
}

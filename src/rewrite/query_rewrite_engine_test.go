package rewrite

import (
	"strings"
	"testing"
	"time"

	"github.com/Nonnner/proxy-db/src/config"
	cryptopkg "github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
)

func setupEngine(t *testing.T) *RewriteEngine {
	tables := map[string]config.TablePolicy{
		"users": {
			Columns: map[string]config.ColumnPolicy{
				"email": {Encryption: "deterministic", KeyID: "key-email"},
				"name":  {Encryption: "aes", KeyID: "key-name"},
			},
		},
	}
	pol := policy.NewPolicy(tables)
	enc := cryptopkg.NewEncryptionEngine()
	enc.Register(&cryptopkg.AESModule{})
	enc.Register(&cryptopkg.DeterministicModule{})
	enc.Register(&cryptopkg.FPEModule{})
	km := key_management.NewLocalKeyManager(5 * time.Minute)
	return NewRewriteEngine(pol, enc, km)
}

func TestRewriteInsert(t *testing.T) {
	engine := setupEngine(t)
	sql := "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')"
	result, err := engine.Rewrite(sql)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if strings.Contains(result, "Alice") {
		t.Error("expected name to be encrypted, but found plaintext 'Alice'")
	}
	if strings.Contains(result, "alice@example.com") {
		t.Error("expected email to be encrypted")
	}
	if !strings.Contains(strings.ToUpper(result), "INSERT INTO") {
		t.Error("expected result to still be an INSERT statement")
	}
}

func TestRewriteSelect(t *testing.T) {
	engine := setupEngine(t)
	sql := "SELECT id, name, email FROM users WHERE id = '1'"
	result, err := engine.Rewrite(sql)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if result != sql {
		t.Errorf("expected SELECT to pass through, got %s", result)
	}
}

func TestRewriteUnknownTable(t *testing.T) {
	engine := setupEngine(t)
	sql := "INSERT INTO products (name, price) VALUES ('Widget', '9.99')"
	result, err := engine.Rewrite(sql)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "INSERT INTO") {
		t.Error("expected INSERT statement")
	}
}

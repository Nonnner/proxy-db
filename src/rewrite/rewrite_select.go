package rewrite

import (
	"github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
	"github.com/Nonnner/proxy-db/src/sqlparser"
)

func rewriteSelect(stmt *sqlparser.Statement, pol *policy.Policy, enc *crypto.EncryptionEngine, km key_management.KeyManager) (string, error) {
	_ = pol
	_ = enc
	_ = km
	return stmt.RawSQL, nil
}

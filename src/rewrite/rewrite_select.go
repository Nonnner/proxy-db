package rewrite

import (
	"github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
	"github.com/Nonnner/proxy-db/src/sqlparser"
)

// rewriteSelect passes SELECT queries through unchanged.
// TODO: future implementation should decrypt WHERE clause values for deterministic/FPE columns
// so that encrypted values stored in the DB can be matched against plaintext query predicates.
func rewriteSelect(stmt *sqlparser.Statement, pol *policy.Policy, enc *crypto.EncryptionEngine, km key_management.KeyManager) (string, error) {
	_ = pol
	_ = enc
	_ = km
	return stmt.RawSQL, nil
}

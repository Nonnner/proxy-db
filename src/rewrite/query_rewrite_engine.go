package rewrite

import (
	"fmt"
	"time"

	"github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
	"github.com/Nonnner/proxy-db/src/sqlparser"
)

type RewriteEngine struct {
	policy  *policy.Policy
	crypto  *crypto.EncryptionEngine
	keyMgr  key_management.KeyManager
	metrics *Metrics
}

type Metrics struct {
	RewriteLatency []time.Duration
	EncryptCount   int
	ErrorCount     int
}

func NewRewriteEngine(p *policy.Policy, e *crypto.EncryptionEngine, km key_management.KeyManager) *RewriteEngine {
	return &RewriteEngine{
		policy:  p,
		crypto:  e,
		keyMgr:  km,
		metrics: &Metrics{},
	}
}

func (r *RewriteEngine) Rewrite(sql string) (string, error) {
	start := time.Now()
	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		r.metrics.ErrorCount++
		return sql, nil
	}

	var result string
	switch stmt.Type {
	case sqlparser.StmtInsert:
		result, err = rewriteInsert(stmt, r.policy, r.crypto, r.keyMgr)
	case sqlparser.StmtUpdate:
		result, err = rewriteUpdate(stmt, r.policy, r.crypto, r.keyMgr)
	case sqlparser.StmtSelect:
		result, err = rewriteSelect(stmt, r.policy, r.crypto, r.keyMgr)
	default:
		result = sql
	}

	if err != nil {
		r.metrics.ErrorCount++
		return sql, fmt.Errorf("rewrite: %w", err)
	}

	r.metrics.RewriteLatency = append(r.metrics.RewriteLatency, time.Since(start))
	return result, nil
}

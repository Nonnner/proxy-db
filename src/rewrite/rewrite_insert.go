package rewrite

import (
	"fmt"
	"strings"

	"github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
	"github.com/Nonnner/proxy-db/src/sqlparser"
)

func rewriteInsert(stmt *sqlparser.Statement, pol *policy.Policy, enc *crypto.EncryptionEngine, km key_management.KeyManager) (string, error) {
	if len(stmt.Values) == 0 {
		return stmt.RawSQL, nil
	}

	newValues := make([][]string, len(stmt.Values))
	for rowIdx, row := range stmt.Values {
		newRow := make([]string, len(row))
		copy(newRow, row)
		for colIdx, col := range stmt.Columns {
			if colIdx >= len(row) {
				break
			}
			cp, ok := pol.GetColumnPolicy(stmt.Table, col)
			if !ok {
				continue
			}
			key, err := km.GetKey(cp.KeyID)
			if err != nil {
				return "", fmt.Errorf("get key %s: %w", cp.KeyID, err)
			}
			ct, err := enc.Encrypt(cp.Encryption, []byte(row[colIdx]), key)
			if err != nil {
				return "", fmt.Errorf("encrypt col %s: %w", col, err)
			}
			newRow[colIdx] = string(ct)
		}
		newValues[rowIdx] = newRow
	}

	return buildInsertSQL(stmt.Table, stmt.Columns, newValues), nil
}

func buildInsertSQL(table string, columns []string, values [][]string) string {
	cols := make([]string, len(columns))
	for i, c := range columns {
		cols[i] = "`" + c + "`"
	}

	var rowStrings []string
	for _, row := range values {
		quoted := make([]string, len(row))
		for i, v := range row {
			quoted[i] = "'" + escapeSQLString(v) + "'"
		}
		rowStrings = append(rowStrings, "("+strings.Join(quoted, ", ")+")")
	}

	return fmt.Sprintf("INSERT INTO `%s` (%s) VALUES %s",
		table,
		strings.Join(cols, ", "),
		strings.Join(rowStrings, ", "))
}

func escapeSQLString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}

func rewriteUpdate(stmt *sqlparser.Statement, pol *policy.Policy, enc *crypto.EncryptionEngine, km key_management.KeyManager) (string, error) {
	newAssign := make(map[string]string)
	for col, val := range stmt.Assignments {
		cp, ok := pol.GetColumnPolicy(stmt.Table, col)
		if !ok {
			newAssign[col] = val
			continue
		}
		key, err := km.GetKey(cp.KeyID)
		if err != nil {
			return "", fmt.Errorf("get key %s: %w", cp.KeyID, err)
		}
		ct, err := enc.Encrypt(cp.Encryption, []byte(val), key)
		if err != nil {
			return "", fmt.Errorf("encrypt col %s: %w", col, err)
		}
		newAssign[col] = string(ct)
	}

	return buildUpdateSQL(stmt.Table, newAssign, stmt.WhereExprs), nil
}

func buildUpdateSQL(table string, assignments map[string]string, wheres []sqlparser.WhereExpr) string {
	var setParts []string
	for col, val := range assignments {
		setParts = append(setParts, fmt.Sprintf("`%s` = '%s'", col, escapeSQLString(val)))
	}

	sql := fmt.Sprintf("UPDATE `%s` SET %s", table, strings.Join(setParts, ", "))

	if len(wheres) > 0 {
		var whereParts []string
		for _, w := range wheres {
			whereParts = append(whereParts, fmt.Sprintf("`%s` %s '%s'", w.Column, w.Operator, escapeSQLString(w.Value)))
		}
		sql += " WHERE " + strings.Join(whereParts, " AND ")
	}

	return sql
}

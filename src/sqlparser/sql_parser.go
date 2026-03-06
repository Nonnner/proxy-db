package sqlparser

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	insertRe = regexp.MustCompile(`(?i)^\s*INSERT\s+INTO\s+` + "`?" + `(\w+)` + "`?" + `\s*\(([^)]+)\)\s*VALUES\s*(.+)`)
	selectRe = regexp.MustCompile(`(?i)^\s*SELECT\s+(.+?)\s+FROM\s+` + "`?" + `(\w+)` + "`?")
	updateRe = regexp.MustCompile(`(?i)^\s*UPDATE\s+` + "`?" + `(\w+)` + "`?" + `\s+SET\s+(.+?)(?:\s+WHERE\s+(.+))?$`)
	deleteRe = regexp.MustCompile(`(?i)^\s*DELETE\s+FROM\s+` + "`?" + `(\w+)` + "`?")
	whereRe  = regexp.MustCompile(`(?i)(\w+)\s*(=|!=|<>|<=|>=|<|>|LIKE)\s*('[^']*'|"[^"]*"|\S+)`)
)

func Parse(sql string) (*Statement, error) {
	sql = strings.TrimSpace(sql)
	stmt := &Statement{RawSQL: sql}

	upper := strings.ToUpper(strings.TrimSpace(sql))
	switch {
	case strings.HasPrefix(upper, "INSERT"):
		return parseInsert(sql, stmt)
	case strings.HasPrefix(upper, "SELECT"):
		return parseSelect(sql, stmt)
	case strings.HasPrefix(upper, "UPDATE"):
		return parseUpdate(sql, stmt)
	case strings.HasPrefix(upper, "DELETE"):
		return parseDelete(sql, stmt)
	default:
		stmt.Type = StmtOther
		return stmt, nil
	}
}

func parseInsert(sql string, stmt *Statement) (*Statement, error) {
	m := insertRe.FindStringSubmatch(sql)
	if m == nil {
		return nil, fmt.Errorf("failed to parse INSERT: %q", sql)
	}
	stmt.Type = StmtInsert
	stmt.Table = m[1]
	stmt.Columns = splitAndTrim(m[2])
	stmt.Values = parseValuesList(m[3])
	return stmt, nil
}

func parseSelect(sql string, stmt *Statement) (*Statement, error) {
	stmt.Type = StmtSelect
	m := selectRe.FindStringSubmatch(sql)
	if m != nil {
		stmt.Columns = splitAndTrim(m[1])
		stmt.Table = m[2]
	}
	stmt.WhereExprs = parseWhere(sql)
	return stmt, nil
}

func parseUpdate(sql string, stmt *Statement) (*Statement, error) {
	stmt.Type = StmtUpdate
	m := updateRe.FindStringSubmatch(sql)
	if m == nil {
		return nil, fmt.Errorf("failed to parse UPDATE: %q", sql)
	}
	stmt.Table = m[1]
	stmt.Assignments = parseAssignments(m[2])
	if m[3] != "" {
		stmt.WhereExprs = parseWhere("WHERE " + m[3])
	}
	return stmt, nil
}

func parseDelete(sql string, stmt *Statement) (*Statement, error) {
	stmt.Type = StmtDelete
	m := deleteRe.FindStringSubmatch(sql)
	if m != nil {
		stmt.Table = m[1]
	}
	stmt.WhereExprs = parseWhere(sql)
	return stmt, nil
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.Trim(strings.TrimSpace(p), "`\"")
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseValuesList(s string) [][]string {
	s = strings.TrimSpace(s)
	var result [][]string
	for {
		start := strings.Index(s, "(")
		end := strings.Index(s, ")")
		if start < 0 || end < 0 || end < start {
			break
		}
		inner := s[start+1 : end]
		result = append(result, parseValueRow(inner))
		s = s[end+1:]
		s = strings.TrimLeft(s, " ,")
	}
	return result
}

func parseValueRow(s string) []string {
	var values []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else if c == '\'' || c == '"' {
			inQuote = true
			quoteChar = c
		} else if c == ',' {
			values = append(values, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 || len(values) > 0 {
		values = append(values, strings.TrimSpace(current.String()))
	}
	return values
}

func parseAssignments(s string) map[string]string {
	result := make(map[string]string)
	parts := strings.Split(s, ",")
	for _, part := range parts {
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		col := strings.Trim(strings.TrimSpace(part[:eqIdx]), "`\"")
		val := strings.Trim(strings.TrimSpace(part[eqIdx+1:]), "'\"")
		result[col] = val
	}
	return result
}

func parseWhere(sql string) []WhereExpr {
	whereIdx := strings.Index(strings.ToUpper(sql), "WHERE")
	if whereIdx < 0 {
		return nil
	}
	wherePart := sql[whereIdx+5:]
	matches := whereRe.FindAllStringSubmatch(wherePart, -1)
	var exprs []WhereExpr
	for _, m := range matches {
		val := strings.Trim(m[3], "'\"")
		exprs = append(exprs, WhereExpr{
			Column:   m[1],
			Operator: m[2],
			Value:    val,
		})
	}
	return exprs
}

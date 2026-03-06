package sqlparser

import (
	"testing"
)

func TestParseInsert(t *testing.T) {
	sql := "INSERT INTO users (name, email, phone) VALUES ('Alice', 'alice@example.com', '1234567890')"
	stmt, err := Parse(sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stmt.Type != StmtInsert {
		t.Errorf("expected StmtInsert, got %d", stmt.Type)
	}
	if stmt.Table != "users" {
		t.Errorf("expected table users, got %s", stmt.Table)
	}
	if len(stmt.Columns) != 3 {
		t.Errorf("expected 3 columns, got %d", len(stmt.Columns))
	}
	if len(stmt.Values) != 1 || len(stmt.Values[0]) != 3 {
		t.Errorf("expected 1 row with 3 values, got %v", stmt.Values)
	}
	if stmt.Values[0][0] != "Alice" {
		t.Errorf("expected Alice, got %s", stmt.Values[0][0])
	}
}

func TestParseSelect(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = '1'"
	stmt, err := Parse(sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stmt.Type != StmtSelect {
		t.Errorf("expected StmtSelect")
	}
	if stmt.Table != "users" {
		t.Errorf("expected table users, got %s", stmt.Table)
	}
}

func TestParseUpdate(t *testing.T) {
	sql := "UPDATE users SET name = 'Bob', email = 'bob@example.com' WHERE id = '1'"
	stmt, err := Parse(sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stmt.Type != StmtUpdate {
		t.Errorf("expected StmtUpdate")
	}
	if stmt.Table != "users" {
		t.Errorf("expected table users")
	}
	if stmt.Assignments["name"] != "Bob" {
		t.Errorf("expected name=Bob, got %s", stmt.Assignments["name"])
	}
}

func TestParseOther(t *testing.T) {
	sql := "CREATE TABLE foo (id INT)"
	stmt, err := Parse(sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stmt.Type != StmtOther {
		t.Errorf("expected StmtOther")
	}
}

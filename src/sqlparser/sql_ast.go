package sqlparser

type StatementType int

const (
	StmtSelect StatementType = iota
	StmtInsert
	StmtUpdate
	StmtDelete
	StmtOther
)

type Statement struct {
	Type        StatementType
	Table       string
	Columns     []string
	Values      [][]string
	Assignments map[string]string
	WhereExprs  []WhereExpr
	RawSQL      string
}

type WhereExpr struct {
	Column   string
	Operator string
	Value    string
}

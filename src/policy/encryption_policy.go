package policy

import "github.com/Nonnner/proxy-db/src/config"

type Policy struct {
	tables map[string]config.TablePolicy
}

func NewPolicy(tables map[string]config.TablePolicy) *Policy {
	if tables == nil {
		tables = make(map[string]config.TablePolicy)
	}
	return &Policy{tables: tables}
}

func (p *Policy) GetColumnPolicy(table, column string) (*config.ColumnPolicy, bool) {
	tp, ok := p.tables[table]
	if !ok {
		return nil, false
	}
	cp, ok := tp.Columns[column]
	if !ok {
		return nil, false
	}
	return &cp, true
}

func (p *Policy) IsEncrypted(table, column string) bool {
	_, ok := p.GetColumnPolicy(table, column)
	return ok
}

func (p *Policy) EncryptedColumns(table string) []string {
	tp, ok := p.tables[table]
	if !ok {
		return nil
	}
	cols := make([]string, 0, len(tp.Columns))
	for col := range tp.Columns {
		cols = append(cols, col)
	}
	return cols
}

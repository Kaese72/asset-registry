package database

import "errors"

const (
	EQ string = "eq"
)

type Filter struct {
	Key      string
	Value    string
	Operator string
}

func (f Filter) Number() (string, error) {
	if f.Operator == EQ {
		return f.Key + " = ?", nil
	}
	return "", errors.New("unsupported operator")
}

func (f Filter) String() (string, error) {
	if f.Operator == EQ {
		return f.Key + " = ?", nil
	}
	return "", errors.New("unsupported operator")
}

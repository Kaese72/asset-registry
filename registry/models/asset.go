package models

import (
	"encoding/json"
	"errors"
)

type ReportScopes []ReportScope

func (scopes *ReportScopes) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(b, &scopes)
}

type Asset struct {
	Name         string       `json:"name" db:"name"`
	ReportScopes ReportScopes `json:"reportScopes,omitempty" db:"reportScopes"`
}

type RegistryAsset struct {
	Asset
	ID             int `json:"id" db:"id"`
	OrganizationId int `json:"organizationId" db:"organizationId"`
}

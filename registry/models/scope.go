package models

type ReportScope struct {
	Type          string `json:"type" db:"type"`
	Value         string `json:"value" db:"value"`
	Distinguisher string `json:"distinguisher" db:"distinguisher"`
}

type RegistryReportScope struct {
	ReportScope
	ID             int `json:"id" db:"id"`
	OrganizationId int `json:"organizationId" db:"organizationId"`
}

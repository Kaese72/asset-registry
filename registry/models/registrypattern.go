package models

type Asset struct {
	Name string `json:"name"`
}

type RegistryAsset struct {
	Asset
	ID             int `json:"id"`
	OrganizationId int `json:"organizationId"`
}

package database

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/Kaese72/asset-registry/apierrors"
	"github.com/Kaese72/asset-registry/registry/models"
	"github.com/georgysavva/scany/v2/sqlscan"
)

var registryAssetFilterConverters = map[string]func(Filter) (string, error){}

func init() {
	registryAssetFilterConverters["name"] = func(f Filter) (string, error) {
		return f.String()
	}
	registryAssetFilterConverters["id"] = func(f Filter) (string, error) {
		return f.Number()
	}

}

func DBRegistryAssetFilter(filters []Filter) (string, []interface{}, error) {
	queryFragments := []string{}
	args := []interface{}{}
	for _, filter := range filters {
		converter, ok := registryAssetFilterConverters[filter.Key]
		if !ok {
			return "", nil, apierrors.APIError{Code: 400, WrappedError: errors.New("attribute may not be filtered on")}
		}
		converted, err := converter(filter)
		if err != nil {
			return "", nil, apierrors.APIError{Code: 400, WrappedError: err}
		}
		queryFragments = append(queryFragments, converted)
		args = append(args, filter.Value)
	}
	return strings.Join(queryFragments, " AND "), args, nil
}

func DBReadRegistryAssets(db *sql.DB, filters []Filter) ([]models.RegistryAsset, error) {
	assets := []models.RegistryAsset{}
	fields := []string{
		"id",
		"organizationId",
		"name",
		"(select COALESCE(JSON_ARRAYAGG(JSON_OBJECT(\"type\", type, \"value\", value)), JSON_ARRAY()) FROM assetReportScopeAssetMap INNER JOIN assetReportScope ON assetReportScopeAssetMap.assetReportScopeId = assetReportScope.id  WHERE assetId = assets.id) as reportScopes",
	}
	query := `SELECT ` + strings.Join(fields, ",") + ` FROM assets`
	variables := []interface{}{}
	if queryQuery, queryVariables, err := DBRegistryAssetFilter(filters); err == nil {
		if queryQuery != "" {
			query += " WHERE " + queryQuery
			variables = queryVariables
		}
	} else {
		return nil, err
	}
	err := sqlscan.Select(context.TODO(), db, &assets, query, variables...)
	return assets, err
}

func DBReadRegistryAsset(db *sql.DB, id int, organizationId int) (models.RegistryAsset, error) {
	assets, err := DBReadRegistryAssets(db, []Filter{{Key: "id", Value: strconv.Itoa(id), Operator: EQ}, {Key: "organizationId", Value: strconv.Itoa(organizationId), Operator: EQ}})
	if err != nil {
		return models.RegistryAsset{}, err
	}
	if len(assets) == 0 {
		return models.RegistryAsset{}, apierrors.APIError{Code: 404, WrappedError: errors.New("asset not found")}
	}
	return assets[0], nil
}

func DBInsertRegistryAsset(db *sql.DB, inputAsset models.Asset, organizationId int) (models.RegistryAsset, error) {
	resAssets := []models.RegistryAsset{}
	// FIXME correct insert statement
	result, err := db.Query(`INSERT INTO assets (name, organizationId) VALUES (?, ?) RETURNING *`, inputAsset.Name, organizationId)
	if err != nil {
		return models.RegistryAsset{}, err
	}
	err = sqlscan.ScanAll(&resAssets, result)
	if err != nil {
		return models.RegistryAsset{}, err
	}
	if len(resAssets) == 0 {
		return models.RegistryAsset{}, errors.New("no asset returned from insert")
	}
	return resAssets[0], nil
}

func DBUpdateRegistryAsset(db *sql.DB, asset models.Asset, id int, organizationId int) (models.RegistryAsset, error) {
	_, err := db.Exec(`UPDATE assets SET name = ? WHERE id = ? AND organizationId = ?`, asset.Name, id, organizationId)
	if err != nil {
		return models.RegistryAsset{}, err
	}
	return DBReadRegistryAsset(db, id, organizationId)
}

func DBDeleteRegistryAsset(db *sql.DB, id int, organizationId int) error {
	res, err := db.Exec(`DELETE FROM assets WHERE id = ? AND organizationId = ?`, id, organizationId)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return apierrors.APIError{Code: 404, WrappedError: errors.New("asset not found")}
	}
	return nil
}

var registryReportScopeFilterConverters = map[string]func(Filter) (string, error){}

func init() {
	registryReportScopeFilterConverters["type"] = func(f Filter) (string, error) {
		return f.String()
	}
	registryReportScopeFilterConverters["value"] = func(f Filter) (string, error) {
		return f.String()
	}
	registryReportScopeFilterConverters["organizationId"] = func(f Filter) (string, error) {
		return f.Number()
	}
}

func DBRegistryReportScopeFilter(filters []Filter) (string, []interface{}, error) {
	queryFragments := []string{}
	args := []interface{}{}
	for _, filter := range filters {
		converter, ok := registryReportScopeFilterConverters[filter.Key]
		if !ok {
			return "", nil, apierrors.APIError{Code: 400, WrappedError: errors.New("attribute may not be filtered on")}
		}
		converted, err := converter(filter)
		if err != nil {
			return "", nil, apierrors.APIError{Code: 400, WrappedError: err}
		}
		queryFragments = append(queryFragments, converted)
		args = append(args, filter.Value)
	}
	return strings.Join(queryFragments, " AND "), args, nil
}

func DBReadReportScopes(db *sql.DB, filters []Filter) ([]models.RegistryReportScope, error) {
	scopes := []models.RegistryReportScope{}
	query := `SELECT * FROM assetReportScope`
	variables := []interface{}{}
	if queryQuery, queryVariables, err := DBRegistryReportScopeFilter(filters); err == nil {
		if queryQuery != "" {
			query += " WHERE " + queryQuery
			variables = queryVariables
		}
	} else {
		return nil, err
	}
	err := sqlscan.Select(context.TODO(), db, &scopes, query, variables...)
	return scopes, err
}

func DBReadReportScope(db *sql.DB, id int, organizationId int) (models.RegistryReportScope, error) {
	scopes := []models.RegistryReportScope{}
	err := sqlscan.Select(context.TODO(), db, &scopes, `SELECT * FROM assetReportScope WHERE id = ? AND organizationId = ?`, id, organizationId)
	if err != nil {
		return models.RegistryReportScope{}, err
	}
	if len(scopes) == 0 {
		return models.RegistryReportScope{}, apierrors.APIError{Code: 404, WrappedError: errors.New("scope not found")}
	}
	return scopes[0], nil
}

func DBPutReportScope(db *sql.DB, inputScope models.ReportScope, organizationId int) (models.RegistryReportScope, error) {
	resScopes := []models.RegistryReportScope{}
	// When we trigger the unique constraint, its fine to ignore the error
	result, err := db.Query(`INSERT IGNORE INTO assetReportScope (type, value, organizationId) VALUES (?, ?, ?) RETURNING *`, inputScope.Type, inputScope.Value, organizationId)
	if err != nil {
		return models.RegistryReportScope{}, err
	}
	err = sqlscan.ScanAll(&resScopes, result)
	if err != nil {
		return models.RegistryReportScope{}, err
	}
	if len(resScopes) > 0 {
		return resScopes[0], nil

	} else {
		resScopes, err := DBReadReportScopes(db, []Filter{
			{Key: "type", Value: inputScope.Type, Operator: EQ},
			{Key: "value", Value: inputScope.Value, Operator: EQ},
			{Key: "organizationId", Value: strconv.Itoa(organizationId), Operator: EQ},
		})
		if err != nil {
			return models.RegistryReportScope{}, err
		}
		if len(resScopes) > 0 {
			return resScopes[0], nil
		}
	}

	return models.RegistryReportScope{}, errors.New("no scope returned from insert")
}

func DBDeleteReportScope(db *sql.DB, id int, organizationId int) error {
	res, err := db.Exec(`DELETE FROM assetReportScope WHERE id = ? AND organizationId = ?`, id, organizationId)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return apierrors.APIError{Code: 404, WrappedError: errors.New("scope not found")}
	}
	return nil
}

func DBLinkReportScopeToAsset(db *sql.DB, assetId int, scopeId int) error {
	_, err := db.Exec(`INSERT INTO assetReportScopeAssetMap (assetId, assetReportScopeId) VALUES (?, ?)`, assetId, scopeId)
	return err
}

package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/Kaese72/asset-registry/apierrors"
	"github.com/Kaese72/asset-registry/registry/models"
	"github.com/georgysavva/scany/v2/sqlscan"
)

var registryAssetFilterConverters = map[string]func(Filter) (string, error){}

func init() {
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
	query := `SELECT * FROM assets`
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
	assets := []models.RegistryAsset{}
	err := sqlscan.Select(context.TODO(), db, &assets, `SELECT * FROM assets WHERE id = ? AND organizationId = ?`, id, organizationId)
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

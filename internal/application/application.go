package application

import (
	"context"
	"database/sql"

	"github.com/Kaese72/asset-registry/internal/database"
	"github.com/Kaese72/asset-registry/registry/models"
)

type Application struct {
	db *sql.DB
}

func NewApplication(db *sql.DB) Application {
	return Application{db: db}
}

func (app Application) ReadAssets(ctx context.Context, filters []database.Filter, organizationId int) ([]models.RegistryAsset, error) {
	return database.DBReadRegistryAssets(ctx, app.db, filters, organizationId)
}

func (app Application) CreateAsset(ctx context.Context, asset models.Asset, organizationId int) (models.RegistryAsset, error) {
	reportedScopes := []models.RegistryReportScope{}
	for _, model := range asset.ReportScopes {
		scope, _, err := app.PutReportScope(ctx, model, organizationId)
		if err != nil {
			return models.RegistryAsset{}, err
		}
		reportedScopes = append(reportedScopes, scope)
	}
	createdAsset, err := database.DBInsertRegistryAsset(ctx, app.db, asset, organizationId)
	if err != nil {
		return models.RegistryAsset{}, err
	}
	for _, scope := range reportedScopes {
		err := app.LinkReportScopeToAsset(ctx, createdAsset.ID, scope.ID)
		if err != nil {
			return models.RegistryAsset{}, err
		}
	}
	createdAsset.ReportScopes = []models.ReportScope{}
	for _, scope := range reportedScopes {
		createdAsset.ReportScopes = append(createdAsset.ReportScopes, scope.ReportScope)
	}

	return createdAsset, nil
}

func (app Application) ReadAsset(ctx context.Context, id int, organizationId int) (models.RegistryAsset, error) {
	return database.DBReadRegistryAsset(ctx, app.db, id, organizationId)
}

func (app Application) UpdateAsset(ctx context.Context, asset models.Asset, id int, organizationId int) (models.RegistryAsset, error) {
	if len(asset.ReportScopes) > 0 {
		shouldHaveIds := []int{}
		for _, model := range asset.ReportScopes {
			scope, _, err := app.PutReportScope(ctx, model, organizationId)
			if err != nil {
				return models.RegistryAsset{}, err
			}
			shouldHaveIds = append(shouldHaveIds, scope.ID)
			// This makes sure links that should be present are present
			database.DBLinkReportScopeToAsset(ctx, app.db, id, scope.ID)
		}
		// This deletes all report scope links except those we should have
		err := database.DBDeleteReportScopesExcept(ctx, app.db, id, organizationId, shouldHaveIds)
		if err != nil {
			return models.RegistryAsset{}, err
		}
	}
	return database.DBUpdateRegistryAsset(ctx, app.db, asset, id, organizationId)
}

func (app Application) DeleteAsset(ctx context.Context, id int, organizationId int) error {
	return database.DBDeleteRegistryAsset(ctx, app.db, id, organizationId)
}

func (app Application) PutReportScope(ctx context.Context, reportScope models.ReportScope, organizationId int) (models.RegistryReportScope, bool, error) {
	return database.DBPutReportScope(ctx, app.db, reportScope, organizationId)
}

func (app Application) ReadReportScopes(ctx context.Context, filters []database.Filter) ([]models.RegistryReportScope, error) {
	return database.DBReadReportScopes(ctx, app.db, filters)
}

func (app Application) ReadReportScope(ctx context.Context, id int, organizationId int) (models.RegistryReportScope, error) {
	return database.DBReadReportScope(ctx, app.db, id, organizationId)
}

func (app Application) DeleteReportScope(ctx context.Context, id int, organizationId int) error {
	return database.DBDeleteReportScope(ctx, app.db, id, organizationId)
}

func (app Application) LinkReportScopeToAsset(ctx context.Context, assetId int, reportScopeId int) error {
	return database.DBLinkReportScopeToAsset(ctx, app.db, assetId, reportScopeId)
}

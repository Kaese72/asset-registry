ALTER TABLE assetReportScope ADD COLUMN distinguisher VARCHAR(255) NOT NULL DEFAULT('global');
ALTER TABLE assetReportScope ADD CONSTRAINT unique_asset_report_scope_2 UNIQUE (organizationId, type, value, distinguisher);
ALTER TABLE assetReportScope DROP INDEX unique_asset_report_scope;
ALTER TABLE assetReportScope RENAME INDEX unique_asset_report_scope_2 TO unique_asset_report_scope
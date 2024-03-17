CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    organizationId INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS assetReportScope (
    id SERIAL PRIMARY KEY,
    organizationId INTEGER NOT NULL,
    type VARCHAR(64) NOT NULL,
    value VARCHAR(1024) NOT NULL,

    CONSTRAINT unique_asset_report_scope UNIQUE (organizationId, type, value)
);

CREATE TABLE IF NOT EXISTS assetReportScopeAssetMap (
    assetReportScopeId BIGINT UNSIGNED NOT NULL,
    assetId BIGINT UNSIGNED NOT NULL,
    
    PRIMARY KEY(assetReportScopeId, assetId),
    FOREIGN KEY (assetReportScopeId) REFERENCES assetReportScope(id),
    FOREIGN KEY (assetId) REFERENCES assets(id)
);

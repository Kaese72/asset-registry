ALTER TABLE assetReportScopeAssetMap ADD CONSTRAINT assetReportScopeAssetMap_ibfk_1_2 FOREIGN KEY (`assetReportScopeId`) REFERENCES `assetReportScope` (`id`) ON DELETE NO ACTION;
ALTER TABLE assetReportScopeAssetMap ADD CONSTRAINT assetReportScopeAssetMap_ibfk_2_2 FOREIGN KEY (`assetId`) REFERENCES `assets` (`id`) ON DELETE CASCADE;
ALTER TABLE assetReportScopeAssetMap DROP FOREIGN KEY assetReportScopeAssetMap_ibfk_1;
ALTER TABLE assetReportScopeAssetMap DROP FOREIGN KEY assetReportScopeAssetMap_ibfk_2;
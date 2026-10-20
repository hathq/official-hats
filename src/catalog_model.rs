// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogIndex {
    pub schema: String,
    pub specification_schema: String,
    pub signing_key_id: String,
    pub origin: String,
    pub categories: Vec<CatalogCategory>,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCategory {
    pub id: String,
    pub term_id: String,
    pub ja: LocalizedText,
    pub en: LocalizedText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedText {
    pub name: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub repository_id: String,
    pub package_id: String,
    pub version: String,
    pub specification_version: String,
    pub artifact_ref: String,
    pub artifact_path: String,
    pub package_sha256: String,
    pub category_id: String,
    pub assurance: String,
    #[serde(default)]
    pub residence_scopes: Vec<String>,
    pub ja: LocalizedText,
    pub en: LocalizedText,
}

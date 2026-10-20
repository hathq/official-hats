use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndex {
    pub schema: String,
    pub specification_schema: String,
    pub signing_key_id: String,
    pub entries: Vec<ReleaseEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEntry {
    pub repository_id: String,
    pub package_id: String,
    pub version: String,
    pub specification_version: String,
    pub artifact_ref: String,
    pub package_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexError(pub String);

impl fmt::Display for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for IndexError {}

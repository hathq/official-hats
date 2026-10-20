// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationDirectory {
    pub schema: String,
    pub directory_id: String,
    pub signing_key_id: String,
    pub origin: String,
    pub catalog_digest_sha256: String,
    pub revision: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub maximum_child_depth: u8,
    pub children: Vec<FederationChildDirectory>,
    pub location_sets: Vec<FederationLocationSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationChildDirectory {
    pub directory_id: String,
    pub document_path: String,
    pub public_key_hex: String,
    pub valid_from_epoch_s: u64,
    pub valid_until_epoch_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationLocationSet {
    pub package_id: String,
    pub package_digest_sha256: String,
    pub document_path: String,
    pub document_digest_sha256: String,
    pub location_count: u16,
}

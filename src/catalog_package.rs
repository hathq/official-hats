// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::{CatalogEntry, IndexError, PACKAGE_SCHEMA};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Correlate one external package artifact with its signed catalog entry.
///
/// # Errors
///
/// Returns an error for size, digest, schema, repository, package, or version drift.
pub fn verify_catalog_package_bytes(entry: &CatalogEntry, bytes: &[u8]) -> Result<(), IndexError> {
    if bytes.len() > 1_048_576 {
        return Err(IndexError("catalog package exceeds its byte limit".into()));
    }
    let digest = hex::encode(Sha256::digest(bytes));
    let identity: PackageIdentity =
        serde_json::from_slice(bytes).map_err(|error| IndexError(error.to_string()))?;
    if digest != entry.package_sha256
        || identity.schema != PACKAGE_SCHEMA
        || identity.package_id != entry.package_id
        || identity.repository_id != entry.repository_id
        || identity.version != entry.version
        || identity.specification_version != entry.specification_version
    {
        return Err(IndexError(
            "catalog package identity or digest differs".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct PackageIdentity {
    schema: String,
    package_id: String,
    repository_id: String,
    version: String,
    specification_version: String,
}

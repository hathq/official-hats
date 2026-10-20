// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::{IndexError, PACKAGE_SCHEMA, ReleaseEntry};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Verify external package bytes against one signed catalog entry.
///
/// # Errors
///
/// Returns an error when the digest or package identity differs from the entry.
pub fn verify_package_bytes(entry: &ReleaseEntry, bytes: &[u8]) -> Result<(), IndexError> {
    if bytes.len() > 1_048_576 {
        return Err(IndexError("package exceeds its byte limit".into()));
    }
    let digest = hex::encode(Sha256::digest(bytes));
    if digest != entry.package_sha256 {
        return Err(IndexError(
            "package digest does not match signed index".into(),
        ));
    }
    let identity: PackageIdentity =
        serde_json::from_slice(bytes).map_err(|error| IndexError(error.to_string()))?;
    if identity.schema != PACKAGE_SCHEMA
        || identity.package_id != entry.package_id
        || identity.repository_id != entry.repository_id
        || identity.version != entry.version
        || identity.specification_version != entry.specification_version
    {
        return Err(IndexError(
            "package identity does not match signed index".into(),
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

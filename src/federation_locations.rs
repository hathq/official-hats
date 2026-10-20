// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::{FederationLocationSet, IndexError};
use sha2::{Digest, Sha256};

/// Verify one location-set document against its signed directory entry.
///
/// # Errors
///
/// Returns an error for size, digest, package, count, freshness, or member drift.
pub fn verify_federation_location_set_bytes_at(
    entry: &FederationLocationSet,
    bytes: &[u8],
    now: u64,
) -> Result<hat_specifications::HatExecutionLocationSet, IndexError> {
    if bytes.len() > 1_048_576 || hex::encode(Sha256::digest(bytes)) != entry.document_digest_sha256
    {
        return Err(IndexError("federation location document differs".into()));
    }
    let value: hat_specifications::HatExecutionLocationSet =
        serde_json::from_slice(bytes).map_err(|error| IndexError(error.to_string()))?;
    let validation = hat_specifications::validate_execution_location_set(&value, now);
    if !validation.valid
        || value.package_id != entry.package_id
        || value.package_digest_sha256 != entry.package_digest_sha256
        || value.locations.len() != usize::from(entry.location_count)
    {
        return Err(IndexError(format!(
            "federation location set is invalid: {}",
            validation.findings.join("; ")
        )));
    }
    Ok(value)
}

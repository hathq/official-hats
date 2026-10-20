// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::signature::verify_signature;
use crate::{IndexError, ReleaseIndex};

/// Verify an externally acquired release index under an explicit trust root.
///
/// # Errors
///
/// Returns an error for signature, schema, identity, ordering, or size drift.
pub fn verify_index_bytes(
    bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
    expected_signing_key_id: &str,
) -> Result<ReleaseIndex, IndexError> {
    if bytes.len() > 1_048_576 {
        return Err(IndexError("release index exceeds its byte limit".into()));
    }
    verify_signature(bytes, signature_hex, public_key_hex)?;
    let index: ReleaseIndex =
        serde_json::from_slice(bytes).map_err(|error| IndexError(error.to_string()))?;
    crate::release_validation::validate_index(&index, expected_signing_key_id)?;
    Ok(index)
}

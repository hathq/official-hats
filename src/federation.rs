// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::signature::decode_fixed;
use crate::{FederationDirectory, IndexError};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify the closed directory against an explicit source's trust identity.
/// This makes no official-assurance claim and performs no acquisition.
///
/// # Errors
/// Rejects signature, source identity, structure, bounds or freshness drift.
pub fn verify_federation_directory_bytes_for_source_at(
    bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
    expected_origin: &str,
    expected_signing_key_id: &str,
    now: u64,
) -> Result<FederationDirectory, IndexError> {
    if bytes.len() > 1_048_576 {
        return Err(IndexError("federation directory exceeds 1 MiB".into()));
    }
    let public = decode_fixed::<32>(public_key_hex, "federation public key")?;
    let signature = decode_fixed::<64>(signature_hex, "federation signature")?;
    let key = VerifyingKey::from_bytes(&public).map_err(|error| IndexError(error.to_string()))?;
    key.verify_strict(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| IndexError("federation directory signature is invalid".into()))?;
    let value: FederationDirectory =
        serde_json::from_slice(bytes).map_err(|error| IndexError(error.to_string()))?;
    crate::federation_validation::validate(&value, expected_origin, expected_signing_key_id, now)?;
    Ok(value)
}

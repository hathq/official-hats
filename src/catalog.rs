// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::signature::decode_fixed;
use crate::{CatalogIndex, IndexError};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify external catalog bytes under one explicitly configured source identity.
///
/// The acquisition location is intentionally not part of this API. A caller may
/// obtain the same signed catalog from HTTPS or a local mirror, while the signed
/// logical origin and signing-key identity remain exact.
///
/// # Errors
///
/// Returns an error when signature verification, source identity, or closed
/// catalog validation fails.
pub fn verify_catalog_bytes_for_source(
    bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
    expected_origin: &str,
    expected_signing_key_id: &str,
) -> Result<CatalogIndex, IndexError> {
    if bytes.len() > 1_048_576 {
        return Err(IndexError("catalog exceeds its byte limit".into()));
    }
    let public = decode_fixed::<32>(public_key_hex, "catalog public key")?;
    let signature = decode_fixed::<64>(signature_hex, "catalog signature")?;
    let key = VerifyingKey::from_bytes(&public).map_err(|error| IndexError(error.to_string()))?;
    key.verify_strict(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| IndexError("catalog signature is invalid".into()))?;
    let catalog: CatalogIndex =
        serde_json::from_slice(bytes).map_err(|error| IndexError(error.to_string()))?;
    crate::catalog_validation::validate_catalog(
        &catalog,
        expected_origin,
        expected_signing_key_id,
    )?;
    Ok(catalog)
}

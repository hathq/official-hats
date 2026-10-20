// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::IndexError;
use ed25519_dalek::{Signature, VerifyingKey};

pub(crate) fn verify_signature(
    bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), IndexError> {
    let public = decode_fixed::<32>(public_key_hex, "public key")?;
    let signature = decode_fixed::<64>(signature_hex, "signature")?;
    let key = VerifyingKey::from_bytes(&public).map_err(|error| IndexError(error.to_string()))?;
    key.verify_strict(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| IndexError("release index signature is invalid".into()))
}

pub(crate) fn decode_fixed<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], IndexError> {
    let value = value.trim();
    if value.len() != N * 2 {
        return Err(IndexError(format!("invalid {label} length")));
    }
    let mut decoded = [0; N];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| IndexError(format!("invalid {label}")))?;
    Ok(decoded)
}

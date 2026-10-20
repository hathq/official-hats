// Hatter downstream 2026: synthetic trust only; never production defaults.
mod common;
use common::federation::*;
use common::signed;
use ed25519_dalek::SigningKey;
#[test]
fn untrusted_signature_and_unknown_fields_fail_closed() {
    let mut value = directory();
    value["endpoint"] = serde_json::json!("203.0.113.9:443");
    let (bytes, signature, public) = signed(&value);
    assert!(verify_federation_directory_bytes_at(&bytes, &signature, &public, 1_200).is_err());
    let (bytes, signature, _) = signed(&directory());
    let other = SigningKey::from_bytes(&[9; 32]);
    assert!(
        verify_federation_directory_bytes_at(
            &bytes,
            &signature,
            &hex::encode(other.verifying_key().to_bytes()),
            1_200,
        )
        .is_err()
    );
}

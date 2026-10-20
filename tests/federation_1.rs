// Hatter downstream 2026: synthetic trust only; never production defaults.
mod common;
use common::federation::*;
use common::signed;
use official_hats::verify_federation_directory_bytes_for_source_at;
#[test]
fn signed_directory_is_fresh_closed_and_relative_to_the_pinned_origin() {
    let (bytes, signature, public) = signed(&directory());
    let value = verify_federation_directory_bytes_at(&bytes, &signature, &public, 1_200)
        .expect("valid signed directory");
    assert_eq!(value.location_sets.len(), 1);
    assert!(verify_federation_directory_bytes_at(&bytes, &signature, &public, 1_600).is_err());
    let mut custom = directory();
    custom["directory_id"] = serde_json::json!("personal-registry");
    custom["origin"] = serde_json::json!("https://registry.example.test");
    custom["signing_key_id"] = serde_json::json!("owner-federation-key");
    let (bytes, signature, public) = signed(&custom);
    assert!(verify_federation_directory_bytes_at(&bytes, &signature, &public, 1_200).is_err());
    let verify = |origin, key_id, now| {
        verify_federation_directory_bytes_for_source_at(
            &bytes, &signature, &public, origin, key_id, now,
        )
    };
    let value = verify(
        "https://registry.example.test",
        "owner-federation-key",
        1_200,
    )
    .expect("explicit source");
    assert_eq!(serde_json::to_value(value).expect("directory"), custom);
    assert!(verify("https://other.example.test", "owner-federation-key", 1_200).is_err());
    assert!(verify("https://registry.example.test", "different-key", 1_200).is_err());
    assert!(
        verify(
            "https://registry.example.test",
            "owner-federation-key",
            1_600
        )
        .is_err()
    );
    custom["directory_id"] = serde_json::json!("../escape");
    let (bytes, signature, public) = signed(&custom);
    assert!(
        verify_federation_directory_bytes_for_source_at(
            &bytes,
            &signature,
            &public,
            "https://registry.example.test",
            "owner-federation-key",
            1_200
        )
        .is_err()
    );
}

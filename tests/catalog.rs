// Hatter downstream 2026: synthetic trust only; never production defaults.
mod common;
use common::{KEY_ID, ORIGIN, catalog, signed, verify};
use official_hats::verify_catalog_bytes_for_source;
#[test]
fn explicit_trust_is_required_and_signature_binds_all_bytes() {
    let (bytes, signature, public) = signed(&catalog());
    assert!(verify_catalog_bytes_for_source(&bytes, &signature, &public, ORIGIN, KEY_ID).is_ok());
    for (origin, id) in [
        ("https://other.example.test", KEY_ID),
        (ORIGIN, "other-key"),
    ] {
        assert!(verify_catalog_bytes_for_source(&bytes, &signature, &public, origin, id).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(
        verify_catalog_bytes_for_source(&changed, &signature, &public, ORIGIN, KEY_ID).is_err()
    );
    assert!(
        verify_catalog_bytes_for_source(&bytes, &signature, &"00".repeat(32), ORIGIN, KEY_ID)
            .is_err()
    );
}
#[test]
fn size_and_fixed_key_bounds_precede_parsing() {
    let (bytes, signature, public) = signed(&catalog());
    assert_eq!(
        verify_catalog_bytes_for_source(&vec![0; 1_048_577], "", "", ORIGIN, KEY_ID)
            .unwrap_err()
            .0,
        "catalog exceeds its byte limit"
    );
    for invalid in ["ab".repeat(1_048_576), "z".repeat(64), "00".repeat(31)] {
        assert!(
            verify_catalog_bytes_for_source(&bytes, &signature, &invalid, ORIGIN, KEY_ID).is_err()
        );
    }
    assert!(
        verify_catalog_bytes_for_source(&bytes, &"00".repeat(63), &public, ORIGIN, KEY_ID).is_err()
    );
}
#[test]
fn closed_schema_identity_paths_and_category_membership_fail_closed() {
    for (field, value) in [
        ("package_id", "hat/substituted"),
        ("repository_id", "hat-"),
        ("artifact_path", "/catalog/v2/../secret"),
        ("package_sha256", "invalid"),
        ("category_id", "missing"),
        ("version", "01.0.0"),
        ("assurance", "unsigned"),
    ] {
        let mut candidate = catalog();
        candidate["entries"][0][field] = value.into();
        assert!(verify(&candidate).is_err(), "{field}");
    }
    let mut candidate = catalog();
    candidate["unexpected"] = true.into();
    assert!(verify(&candidate).is_err());
    let mut candidate = catalog();
    candidate["entries"][0]["unexpected"] = true.into();
    assert!(verify(&candidate).is_err());
}
#[test]
fn duplicates_ordering_counts_and_residence_are_validated() {
    let mut candidate = catalog();
    let duplicate = candidate["entries"][0].clone();
    candidate["entries"].as_array_mut().unwrap().push(duplicate);
    assert!(verify(&candidate).is_err());
    for entries in [
        serde_json::json!([]),
        serde_json::json!(vec![catalog()["entries"][0].clone(); 257]),
    ] {
        let mut candidate = catalog();
        candidate["entries"] = entries;
        assert!(verify(&candidate).is_err());
    }
    for scopes in [serde_json::json!(["JP", "JP"]), serde_json::json!(["jp"])] {
        let mut candidate = catalog();
        candidate["entries"][0]["residence_scopes"] = scopes;
        assert!(verify(&candidate).is_err());
    }
}

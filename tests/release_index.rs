// Hatter downstream 2026: synthetic trust only; never production defaults.
mod common;
use common::{DIGEST, signed};
use official_hats::{verify_index_bytes, verify_package_bytes};
use sha2::Digest;
#[test]
fn external_release_index_uses_the_shared_closed_verifier() {
    let value = serde_json::json!({
        "schema": "hathq://official-hats/release-index/v1",
        "specification_schema": "hathq://hat/package/v2",
        "signing_key_id": common::KEY_ID,
        "entries": [{
            "repository_id": "hat-example",
            "package_id": "hat/example",
            "version": "1.0.0",
            "specification_version": "1.0.0",
            "artifact_ref": "hathq://official-hats/package/hat-example/1.0.0",
            "package_sha256": DIGEST
        }]
    });
    let (bytes, signature, public) = signed(&value);
    assert!(verify_index_bytes(&bytes, &signature, &public, common::KEY_ID).is_ok());
    let mut open = value;
    open["endpoint"] = serde_json::json!("https://example.invalid");
    let (bytes, signature, public) = signed(&open);
    assert!(verify_index_bytes(&bytes, &signature, &public, common::KEY_ID).is_err());
}

#[test]
fn package_repository_identity_cannot_be_substituted() {
    let entry = official_hats::ReleaseEntry {
        repository_id: "hat-example".into(),
        package_id: "hat/example".into(),
        version: "1.0.0".into(),
        specification_version: "1.0.0".into(),
        artifact_ref: "hathq://official-hats/package/hat-example/1.0.0".into(),
        package_sha256: String::new(),
    };
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "hathq://hat/package/v2",
        "package_id": "hat/example",
        "repository_id": "hat-substitute",
        "version": "1.0.0",
        "specification_version": "1.0.0"
    }))
    .expect("package");
    let entry = official_hats::ReleaseEntry {
        package_sha256: hex::encode(sha2::Sha256::digest(&bytes)),
        ..entry
    };
    assert!(verify_package_bytes(&entry, &bytes).is_err());
    assert_eq!(
        verify_package_bytes(&entry, &vec![b' '; 1_048_577])
            .expect_err("package size before digest or JSON")
            .0,
        "package exceeds its byte limit"
    );
}

#[test]
fn release_key_identity_and_size_cannot_be_inferred_from_document() {
    let value = serde_json::json!({"schema": official_hats::INDEX_SCHEMA,
        "specification_schema":official_hats::PACKAGE_SCHEMA,
        "signing_key_id":common::KEY_ID,"entries":[]});
    let (bytes, sig, key) = signed(&value);
    assert!(verify_index_bytes(&bytes, &sig, &key, "other-key").is_err());
    assert_eq!(
        verify_index_bytes(&vec![0; 1_048_577], "", "", common::KEY_ID)
            .unwrap_err()
            .0,
        "release index exceeds its byte limit"
    );
}

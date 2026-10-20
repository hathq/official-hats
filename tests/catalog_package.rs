// Hatter downstream 2026: package digest/identity acceptance with synthetic data.
mod common;
use official_hats::verify_catalog_package_bytes;
use sha2::{Digest, Sha256};
#[test]
fn catalog_package_requires_exact_digest_and_every_identity_field() {
    let original = serde_json::json!({"schema":official_hats::PACKAGE_SCHEMA,
        "repository_id":"hat-example","package_id":"hat/example",
        "version":"1.0.0","specification_version":"1.0.0"});
    let bytes = serde_json::to_vec(&original).unwrap();
    let mut catalog = common::catalog();
    catalog["entries"][0]["package_sha256"] = hex::encode(Sha256::digest(&bytes)).into();
    let mut entry = common::verify(&catalog).unwrap().entries.remove(0);
    assert!(verify_catalog_package_bytes(&entry, &bytes).is_ok());
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(verify_catalog_package_bytes(&entry, &changed).is_err());
    for field in [
        "schema",
        "repository_id",
        "package_id",
        "version",
        "specification_version",
    ] {
        let mut value = original.clone();
        value[field] = "substituted".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        entry.package_sha256 = hex::encode(Sha256::digest(&bytes));
        assert!(
            verify_catalog_package_bytes(&entry, &bytes).is_err(),
            "{field}"
        );
    }
    assert_eq!(
        verify_catalog_package_bytes(&entry, &vec![0; 1_048_577])
            .unwrap_err()
            .0,
        "catalog package exceeds its byte limit"
    );
}

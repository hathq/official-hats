// Hatter downstream 2026: synthetic trust only; never production defaults.
#![allow(dead_code)]
use ed25519_dalek::{Signer, SigningKey};
pub const ORIGIN: &str = "https://registry.example.test";
pub const KEY_ID: &str = "test-catalog-key";
pub const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub fn signed(value: &serde_json::Value) -> (Vec<u8>, String, String) {
    let bytes = serde_json::to_vec(value).expect("synthetic JSON");
    let key = SigningKey::from_bytes(&[7; 32]);
    (
        bytes.clone(),
        hex::encode(key.sign(&bytes).to_bytes()),
        hex::encode(key.verifying_key().to_bytes()),
    )
}
pub fn catalog() -> serde_json::Value {
    serde_json::json!({
        "schema": official_hats::CATALOG_SCHEMA,
        "specification_schema": official_hats::PACKAGE_SCHEMA,
        "signing_key_id": KEY_ID, "origin": ORIGIN,
        "categories": [{"id":"tools", "term_id":"hathq://vocabulary/data-domain/tools/v1",
            "ja":{"name":"Example", "summary":"Synthetic example"},
            "en":{"name":"Example", "summary":"Synthetic example"}}],
        "entries": [{"repository_id":"hat-example", "package_id":"hat/example",
            "version":"1.0.0", "specification_version":"1.0.0",
            "artifact_ref":"hathq://official-hats/package/hat-example/1.0.0",
            "artifact_path":"/catalog/v2/packages/hat-example/1.0.0/hat.package.json",
            "package_sha256":DIGEST,"category_id":"tools","assurance":"official",
            "ja":{"name":"Example", "summary":"Synthetic example"},
            "en":{"name":"Example", "summary":"Synthetic example"}}]
    })
}
pub fn verify(
    value: &serde_json::Value,
) -> Result<official_hats::CatalogIndex, official_hats::IndexError> {
    let (bytes, sig, key) = signed(value);
    official_hats::verify_catalog_bytes_for_source(&bytes, &sig, &key, ORIGIN, KEY_ID)
}

pub mod federation;

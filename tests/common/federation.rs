// Hatter downstream 2026: synthetic trust only; never production defaults.
use super as common;
use common::DIGEST;
use official_hats::{FEDERATION_DIRECTORY_SCHEMA, verify_federation_directory_bytes_for_source_at};
pub fn verify_federation_directory_bytes_at(
    bytes: &[u8],
    sig: &str,
    key: &str,
    now: u64,
) -> Result<official_hats::FederationDirectory, official_hats::IndexError> {
    let value = verify_federation_directory_bytes_for_source_at(
        bytes,
        sig,
        key,
        common::ORIGIN,
        common::KEY_ID,
        now,
    )?;
    if value.directory_id != "official-hats" {
        return Err(official_hats::IndexError("test directory differs".into()));
    }
    Ok(value)
}
pub fn directory() -> serde_json::Value {
    serde_json::json!({
        "schema": FEDERATION_DIRECTORY_SCHEMA,
        "directory_id": "official-hats",
        "signing_key_id": common::KEY_ID,
        "origin": common::ORIGIN,
        "catalog_digest_sha256": DIGEST,
        "revision": 1,
        "issued_at_epoch_s": 1_000,
        "expires_at_epoch_s": 1_600,
        "maximum_child_depth": 3,
        "children": [],
        "location_sets": [{
            "package_id": "hat/source-curator",
            "package_digest_sha256": DIGEST,
            "document_path": "/federation/v1/locations/hat-source-curator.json",
            "document_digest_sha256": DIGEST,
            "location_count": 1
        }]
    })
}

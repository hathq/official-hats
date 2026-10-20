// Hatter downstream 2026: synthetic trust only; never production defaults.
mod common;
use common::federation::*;
use common::signed;
#[test]
fn directory_rejects_redirect_shaped_paths_depth_and_duplicates() {
    for (field, replacement) in [
        ("document_path", "https://worker.example/location.json"),
        ("document_path", "/federation/v1/../secret.json"),
    ] {
        let mut value = directory();
        value["location_sets"][0][field] = serde_json::json!(replacement);
        let (bytes, signature, public) = signed(&value);
        assert!(verify_federation_directory_bytes_at(&bytes, &signature, &public, 1_200).is_err());
    }
    let mut value = directory();
    value["maximum_child_depth"] = serde_json::json!(4);
    let duplicate = value["location_sets"][0].clone();
    value["location_sets"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let (bytes, signature, public) = signed(&value);
    assert!(verify_federation_directory_bytes_at(&bytes, &signature, &public, 1_200).is_err());
}

// Hatter downstream 2026: synthetic trust only; never production defaults.
mod common;
use common::federation::*;
use common::{DIGEST, signed};
use official_hats::verify_federation_location_set_bytes_at;
use sha2::{Digest, Sha256};
#[test]
fn directory_entry_closes_the_exact_location_set_document() {
    let locations = serde_json::json!({
        "schema": "hathq://hat/execution-location-set/v1",
        "package_id": "hat/source-curator",
        "package_digest_sha256": DIGEST,
        "revision": 1,
        "issued_at_epoch_s": 1_000,
        "expires_at_epoch_s": 1_600,
        "locations": [{
            "schema": "hathq://hat/execution-location/v1",
            "location_id": "tokyo-owner-node",
            "package_id": "hat/source-curator",
            "package_digest_sha256": DIGEST,
            "publisher_id": "hathq",
            "execution_kind": "federated-managed",
            "worker_service_id": "source-curator-tokyo",
            "identity_authority_ref": "ihat/service/source-curator-tokyo",
            "evidence_recovery": hat_specifications::HatEvidenceRecovery::Unrecoverable {},
            "transport_profile_ref": "crowsi/mtls-authority-v1",
            "route_ref": "crowsi/route/source-curator-tokyo",
            "region": "jp-east",
            "jurisdictions": ["jp"],
            "data_residencies": ["jp"],
            "operation_ids": ["hathq://hat/action/review-source/v1"],
            "accepted_classifications": ["internal"],
            "capability_ids": ["review-source"],
            "assurance": "official",
            "issued_at_epoch_s": 1_000,
            "expires_at_epoch_s": 1_600,
            "revocation_epoch": 1
        }]
    });
    let bytes = serde_json::to_vec(&locations).expect("locations");
    let mut index = directory();
    index["location_sets"][0]["document_digest_sha256"] =
        serde_json::json!(hex::encode(Sha256::digest(&bytes)));
    let (directory_bytes, signature, public) = signed(&index);
    let directory =
        verify_federation_directory_bytes_at(&directory_bytes, &signature, &public, 1_200)
            .expect("directory");
    let actual =
        verify_federation_location_set_bytes_at(&directory.location_sets[0], &bytes, 1_200)
            .expect("exact current location set");
    assert_eq!(
        serde_json::to_value(actual).expect("location set"),
        locations
    );
    let mut changed = bytes;
    changed.push(b' ');
    assert!(
        verify_federation_location_set_bytes_at(&directory.location_sets[0], &changed, 1_200,)
            .is_err()
    );
}

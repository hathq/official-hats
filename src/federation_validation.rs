// Hatter downstream 2026: shared bounded structure, explicit source identity.
use std::collections::BTreeSet;

use crate::{FEDERATION_DIRECTORY_SCHEMA, FederationDirectory, IndexError};

pub(crate) fn validate(
    value: &FederationDirectory,
    origin: &str,
    signing_key_id: &str,
    now: u64,
) -> Result<(), IndexError> {
    if origin.is_empty()
        || origin.len() > 2048
        || origin.trim() != origin
        || value.schema != FEDERATION_DIRECTORY_SCHEMA
        || !token(&value.directory_id)
        || !token(&value.signing_key_id)
        || value.signing_key_id != signing_key_id
        || value.origin != origin
        || !digest(&value.catalog_digest_sha256)
        || value.revision == 0
        || value.issued_at_epoch_s > now
        || now >= value.expires_at_epoch_s
        || value.expires_at_epoch_s <= value.issued_at_epoch_s
        || value.expires_at_epoch_s - value.issued_at_epoch_s > 86_400
        || !(1..=3).contains(&value.maximum_child_depth)
        || value.children.len() > 32
        || value.location_sets.len() > 256
    {
        return Err(IndexError("federation directory header is invalid".into()));
    }
    validate_children(value)?;
    validate_locations(value)
}

fn validate_children(value: &FederationDirectory) -> Result<(), IndexError> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut previous = None;
    for child in &value.children {
        if !token(&child.directory_id)
            || !path(&child.document_path, "directories")
            || !hex_bytes(&child.public_key_hex, 32)
            || child.valid_from_epoch_s < value.issued_at_epoch_s
            || child.valid_until_epoch_s > value.expires_at_epoch_s
            || child.valid_from_epoch_s >= child.valid_until_epoch_s
            || previous.is_some_and(|item| item >= child.directory_id.as_str())
            || !ids.insert(child.directory_id.as_str())
            || !paths.insert(child.document_path.as_str())
        {
            return Err(IndexError("federation child directory is invalid".into()));
        }
        previous = Some(child.directory_id.as_str());
    }
    Ok(())
}

fn validate_locations(value: &FederationDirectory) -> Result<(), IndexError> {
    let mut packages = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut previous = None;
    for item in &value.location_sets {
        if !item.package_id.strip_prefix("hat/").is_some_and(token)
            || !digest(&item.package_digest_sha256)
            || !path(&item.document_path, "locations")
            || !digest(&item.document_digest_sha256)
            || !(1..=64).contains(&item.location_count)
            || previous.is_some_and(|value| value >= item.package_id.as_str())
            || !packages.insert(item.package_id.as_str())
            || !paths.insert(item.document_path.as_str())
        {
            return Err(IndexError("federation location set is invalid".into()));
        }
        previous = Some(item.package_id.as_str());
    }
    Ok(())
}

fn path(value: &str, kind: &str) -> bool {
    value.starts_with(&format!("/federation/v1/{kind}/"))
        && std::path::Path::new(value)
            .extension()
            .is_some_and(|extension| extension == "json")
        && value.len() <= 256
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains(['\\', '?', '#', '%'])
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'/' | b'-' | b'.')
        })
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn digest(value: &str) -> bool {
    hex_bytes(value, 32)
}

fn hex_bytes(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::{INDEX_SCHEMA, IndexError, PACKAGE_SCHEMA, ReleaseEntry, ReleaseIndex};
use std::collections::BTreeSet;

pub(crate) fn validate_index(
    index: &ReleaseIndex,
    expected_key_id: &str,
) -> Result<(), IndexError> {
    if index.schema != INDEX_SCHEMA
        || index.specification_schema != PACKAGE_SCHEMA
        || index.signing_key_id != expected_key_id
        || expected_key_id.is_empty()
        || expected_key_id.len() > 128
        || index.entries.is_empty()
        || index.entries.len() > 256
    {
        return Err(IndexError("release index header is invalid".into()));
    }
    let mut repositories = BTreeSet::new();
    let mut packages = BTreeSet::new();
    let mut previous = None;
    for entry in &index.entries {
        validate_entry(entry)?;
        if previous.is_some_and(|value| value >= entry.repository_id.as_str())
            || !repositories.insert(entry.repository_id.as_str())
            || !packages.insert(entry.package_id.as_str())
        {
            return Err(IndexError(
                "release entries must be unique and sorted".into(),
            ));
        }
        previous = Some(entry.repository_id.as_str());
    }
    Ok(())
}

fn validate_entry(entry: &ReleaseEntry) -> Result<(), IndexError> {
    let suffix = entry
        .repository_id
        .strip_prefix("hat-")
        .ok_or_else(|| IndexError("invalid repository id".into()))?;
    let expected_package = format!("hat/{suffix}");
    let expected_artifact = format!(
        "hathq://official-hats/package/{}/{}",
        entry.repository_id, entry.version
    );
    if !identifier(suffix)
        || entry.package_id != expected_package
        || !version(&entry.version)
        || !version(&entry.specification_version)
        || entry.artifact_ref != expected_artifact
        || !lower_hex_32(&entry.package_sha256)
    {
        return Err(IndexError(format!(
            "invalid release entry: {}",
            entry.repository_id
        )));
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 124
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
}

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

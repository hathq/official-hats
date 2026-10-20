// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::catalog_fields::{localized, lower_hex, residence_scopes, token, version};
use crate::{CATALOG_SCHEMA, CatalogIndex, IndexError, PACKAGE_SCHEMA};
use std::collections::BTreeSet;

pub(crate) fn validate_catalog(
    catalog: &CatalogIndex,
    expected_origin: &str,
    expected_signing_key_id: &str,
) -> Result<(), IndexError> {
    if expected_origin.is_empty()
        || expected_origin.len() > 2048
        || expected_origin.trim() != expected_origin
        || expected_signing_key_id.is_empty()
        || expected_signing_key_id.len() > 128
        || catalog.schema != CATALOG_SCHEMA
        || catalog.specification_schema != PACKAGE_SCHEMA
        || catalog.signing_key_id != expected_signing_key_id
        || catalog.origin != expected_origin
        || catalog.categories.is_empty()
        || catalog.categories.len() > 32
        || catalog.entries.is_empty()
        || catalog.entries.len() > 256
    {
        return Err(IndexError("catalog header is invalid".into()));
    }
    let mut ids = BTreeSet::new();
    let mut previous = None;
    for category in &catalog.categories {
        if !token(&category.id)
            || category.term_id != format!("hathq://vocabulary/data-domain/{}/v1", category.id)
            || !localized(&category.ja)
            || !localized(&category.en)
            || previous.is_some_and(|value| value >= category.id.as_str())
            || !ids.insert(category.id.as_str())
        {
            return Err(IndexError("catalog category is invalid or unsorted".into()));
        }
        previous = Some(category.id.as_str());
    }
    validate_entries(catalog, &ids)
}

fn validate_entries(catalog: &CatalogIndex, ids: &BTreeSet<&str>) -> Result<(), IndexError> {
    let mut repositories = BTreeSet::new();
    let mut previous = None;
    for entry in &catalog.entries {
        let suffix = entry.repository_id.strip_prefix("hat-");
        let expected = suffix.map(|value| format!("hat/{value}"));
        let path = format!(
            "/catalog/v2/packages/{}/{}/hat.package.json",
            entry.repository_id, entry.version
        );
        let reference = format!(
            "hathq://official-hats/package/{}/{}",
            entry.repository_id, entry.version
        );
        if suffix.is_none()
            || !token(&entry.repository_id)
            || expected.as_deref() != Some(entry.package_id.as_str())
            || !version(&entry.version)
            || !version(&entry.specification_version)
            || entry.artifact_ref != reference
            || entry.artifact_path != path
            || !lower_hex(&entry.package_sha256)
            || !ids.contains(entry.category_id.as_str())
            || entry.assurance != "official"
            || !residence_scopes(&entry.residence_scopes)
            || !localized(&entry.ja)
            || !localized(&entry.en)
            || previous.is_some_and(|value| value >= entry.repository_id.as_str())
            || !repositories.insert(entry.repository_id.as_str())
        {
            return Err(IndexError("catalog entry is invalid or unsorted".into()));
        }
        previous = Some(entry.repository_id.as_str());
    }
    Ok(())
}

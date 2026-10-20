// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
#![forbid(unsafe_code)]
//! Pure signed-document verification. Callers supply trust; this crate never acquires it.
mod catalog;
mod catalog_fields;
mod catalog_model;
mod catalog_package;
mod catalog_validation;
mod federation;
mod federation_locations;
mod federation_model;
mod federation_validation;
mod index;
mod model;
mod package;
mod release_validation;
mod signature;
pub use catalog::verify_catalog_bytes_for_source;
pub use catalog_model::{CatalogCategory, CatalogEntry, CatalogIndex, LocalizedText};
pub use catalog_package::verify_catalog_package_bytes;
pub use federation::verify_federation_directory_bytes_for_source_at;
pub use federation_locations::verify_federation_location_set_bytes_at;
pub use federation_model::{FederationChildDirectory, FederationDirectory, FederationLocationSet};
pub use index::verify_index_bytes;
pub use model::{IndexError, ReleaseEntry, ReleaseIndex};
pub use package::verify_package_bytes;
/// Signed release-index schema.
pub const INDEX_SCHEMA: &str = "hathq://official-hats/release-index/v1";
/// Package schema governed by hat-specifications.
pub const PACKAGE_SCHEMA: &str = "hathq://hat/package/v2";
/// Signed marketplace catalog schema.
pub const CATALOG_SCHEMA: &str = "hathq://official-hats/catalog/v2";
/// Signed bounded federation-directory schema.
pub const FEDERATION_DIRECTORY_SCHEMA: &str = "hathq://official-hats/federation-directory/v1";

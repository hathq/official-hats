# Signed HAT verification

Apache-2.0 Rust library for explicit-source signature, schema, digest and
identity verification. All inputs are supplied as bytes; no network, filesystem,
process execution, credential storage, catalog acquisition or signing occurs.

Callers pin their public key and expected signing-key identity, plus logical
origin for catalogs/federation and current time for federation. A valid signature
does not confer permission to execute or install a package. Runtime trust and
revocation belong to the application, not the verifier.

Documents are limited to 1 MiB before decoding. Keys/signatures have exact sizes.
Unknown fields, identity substitution, invalid ordering, duplicate entries,
expired federation documents and digest changes are rejected.

There is no bundled catalog, default production key, default origin, signer,
installer or filesystem CLI. Synthetic signing seeds occur only in tests and
must never be adopted as application trust.

## Development

Run `cargo test --locked --all-targets --all-features` and Clippy. Existing CI
also checks formatting and an independent packaged consumer. The JSON schemas
express structural constraints; Rust validation additionally binds fields to
caller-supplied trust, enforces ordering and verifies signatures and digests.

## Migration from 0.10

Use explicit catalog/federation source APIs. `verify_index_bytes` now requires
an expected signing-key identity. Built-in catalog and trust convenience APIs
are removed. Applications must supply reviewed data and preserve their trust
policy explicitly. This source-only extraction does not activate a new origin,
accept live signed catalogs, or publish a product runtime.

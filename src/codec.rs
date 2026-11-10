/// Binary record encoding using `postcard`.
///
/// Replaces `serde_json` for all records persisted to the storage engine,
/// eliminating field-name overhead (~30–40% per value). The helper is
/// intentionally kept crate-internal so that every layer (identity, audit,
/// rbac) serialises through a single choke-point — format changes land here.
///
/// # Format
///
/// `postcard` encodes structs in declaration order with no field names and
/// compact integer encoding (ULEB128). The format is NOT self-describing:
/// the schema is implicit in the Rust type, and a record carries no version.
/// A change that makes this build misread a record an earlier build wrote
/// MUST bump `crate::storage::format::STORE_FORMAT_VERSION` in the same
/// change. The fixture test `tests/store_format_fixture.rs` fails until it
/// does. Hearth does not migrate stores between format versions.
use serde::{de::DeserializeOwned, Serialize};

/// Encodes `value` using `postcard` into a `Vec<u8>`.
///
/// Returns the serialized byte vector, or an error string on failure.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(value).map_err(|e| e.to_string())
}

/// Decodes bytes produced by [`encode`] back into `T`.
///
/// Returns an error string if the bytes are invalid or the schema has changed
/// in a backward-incompatible way.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    postcard::from_bytes(bytes).map_err(|e| e.to_string())
}

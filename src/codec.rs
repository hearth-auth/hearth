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
/// the schema is implicit in the Rust type. Hearth has no backward-compat
/// obligation for on-disk formats (see CLAUDE.md §Greenfield), so the
/// encoding can be changed freely between versions.
use serde::{de::DeserializeOwned, Serialize};

/// Encodes `value` using `postcard` into a `Vec<u8>`.
///
/// Returns the serialized byte vector, or an error string on failure.
pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(value).map_err(|e| e.to_string())
}

/// Decodes bytes produced by [`encode`] back into `T`.
///
/// Returns an error string if the bytes are invalid or the schema has changed
/// in a backward-incompatible way.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    postcard::from_bytes(bytes).map_err(|e| e.to_string())
}

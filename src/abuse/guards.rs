//! Request-body guards: JSON parse-bomb (A-21) and decompression-bomb (A-22).
//!
//! # A-21 — JSON parse-bomb guard
//!
//! `serde_json` will faithfully traverse arbitrarily deep nesting in a JSON
//! body, consuming stack proportional to depth.  A 1 MiB body of `{"a":{"a":…`
//! hundreds of levels deep can exhaust thread stack.  [`check_json_depth`]
//! measures nesting depth before full deserialization and rejects bodies that
//! exceed [`MAX_JSON_DEPTH`].
//!
//! # A-22 — Decompression-bomb cap
//!
//! `Content-Encoding: gzip` requests are decompressed by the server before
//! reaching handlers.  A 1 MiB compressed bomb can expand to hundreds of MiB.
//! [`check_decompressed_size`] caps the decompressed stream at
//! `4 × BODY_LIMIT_DEFAULT` bytes, aborting if the decompressor attempts to
//! yield more.

use std::io::Read as _;

use flate2::read::GzDecoder;

/// Maximum nesting depth of a JSON value (objects + arrays combined).
///
/// Depth ≥ 512 on a 1 MiB body is almost certainly an attack.  Legitimate
/// API payloads rarely exceed 10–20 levels of nesting.
pub const MAX_JSON_DEPTH: usize = 128;

/// Maximum number of items allowed in any single JSON array.
///
/// Protects against `["x","x","x",… × 1_000_000]` parse-bombs that exploit
/// serde_json's linear array allocation.
pub const MAX_JSON_ARRAY_LEN: usize = 65_536;

/// Bytes cap for the decompressed body (4 × default 1 MiB body limit).
///
/// Adjusted to stay sane relative to whatever the server's body limit is.
/// Hard-coding 4 MiB here is safe because the body limit itself (1 MiB
/// compressed) provides a secondary backstop.
pub const MAX_DECOMPRESSED_SIZE: usize = 4 * 1024 * 1024;

/// Error returned by body-guard functions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyGuardError {
    #[error("JSON nesting depth exceeds maximum ({MAX_JSON_DEPTH})")]
    JsonDepthExceeded,
    #[error("JSON array length exceeds maximum ({MAX_JSON_ARRAY_LEN})")]
    JsonArrayTooLong,
    #[error("decompressed body exceeds maximum size ({MAX_DECOMPRESSED_SIZE} bytes)")]
    DecompressedSizeExceeded,
    #[error("decompression failed: {0}")]
    DecompressError(String),
}

/// Validates the nesting depth and maximum array length of a JSON byte slice.
///
/// Counts raw bracket tokens rather than fully deserializing; this is O(n)
/// and safe against UTF-8 multi-byte sequences because `{`, `}`, `[`, `]`,
/// and `"` are all ASCII and never appear as UTF-8 continuation bytes.
///
/// # Errors
///
/// Returns `BodyGuardError::JsonDepthExceeded` or `BodyGuardError::JsonArrayTooLong`
/// if the document violates the limits.
pub fn check_json_depth(bytes: &[u8]) -> Result<(), BodyGuardError> {
    check_json_depth_raw(bytes)
}

/// Raw bracket-counting implementation.
fn check_json_depth_raw(bytes: &[u8]) -> Result<(), BodyGuardError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut array_lens: Vec<usize> = Vec::new();

    for &b in bytes {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escape_next = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(BodyGuardError::JsonDepthExceeded);
                }
                array_lens.push(usize::MAX); // sentinel: not counting array items
            }
            b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(BodyGuardError::JsonDepthExceeded);
                }
                // Start at 1: the first element is already "present" upon
                // opening the bracket; each subsequent `,` adds one more.
                array_lens.push(1);
            }
            b',' => {
                // If we're directly inside an array (last entry in array_lens
                // is a real count, not the sentinel), increment.
                if let Some(top) = array_lens.last_mut() {
                    if *top != usize::MAX {
                        *top += 1;
                        // Reject once count reaches the cap (exclusive upper bound).
                        if *top >= MAX_JSON_ARRAY_LEN {
                            return Err(BodyGuardError::JsonArrayTooLong);
                        }
                    }
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                array_lens.pop();
            }
            _ => {}
        }
    }
    Ok(())
}

/// Decompresses `gzip_bytes` into a buffer, aborting if the output exceeds
/// [`MAX_DECOMPRESSED_SIZE`].
///
/// Returns the decompressed bytes on success.
///
/// # Errors
///
/// Returns [`BodyGuardError::DecompressedSizeExceeded`] if the output would
/// exceed the cap, or [`BodyGuardError::DecompressError`] on an I/O error.
pub fn check_decompressed_size(gzip_bytes: &[u8]) -> Result<Vec<u8>, BodyGuardError> {
    let mut decoder = GzDecoder::new(gzip_bytes);
    // Read at most MAX_DECOMPRESSED_SIZE + 1 bytes.  If we get exactly
    // MAX_DECOMPRESSED_SIZE + 1, the stream would exceed the cap.
    let mut buf = Vec::with_capacity(std::cmp::min(gzip_bytes.len() * 4, MAX_DECOMPRESSED_SIZE));
    let cap_plus_one = MAX_DECOMPRESSED_SIZE + 1;
    let mut limited = (&mut decoder).take(cap_plus_one as u64);
    limited
        .read_to_end(&mut buf)
        .map_err(|e| BodyGuardError::DecompressError(e.to_string()))?;
    if buf.len() > MAX_DECOMPRESSED_SIZE {
        return Err(BodyGuardError::DecompressedSizeExceeded);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_json_passes() {
        let json = br#"{"key": "value", "n": 42}"#;
        assert!(check_json_depth(json).is_ok());
    }

    #[test]
    fn nested_json_within_limit() {
        // Build depth-10 nesting.
        let mut s = String::new();
        for _ in 0..10 {
            s.push_str(r#"{"x":"#);
        }
        s.push('1');
        for _ in 0..10 {
            s.push('}');
        }
        assert!(check_json_depth(s.as_bytes()).is_ok());
    }

    #[test]
    fn deeply_nested_json_rejected() {
        // Build depth-(MAX_JSON_DEPTH + 1) nesting.
        let mut s = String::new();
        for _ in 0..=MAX_JSON_DEPTH {
            s.push_str(r#"{"x":"#);
        }
        s.push('1');
        for _ in 0..=MAX_JSON_DEPTH {
            s.push('}');
        }
        assert_eq!(
            check_json_depth(s.as_bytes()),
            Err(BodyGuardError::JsonDepthExceeded)
        );
    }

    #[test]
    fn huge_array_rejected() {
        // Array with MAX_JSON_ARRAY_LEN elements.
        let elements = (0..MAX_JSON_ARRAY_LEN)
            .map(|i| i.to_string())
            .collect::<Vec<_>>();
        let json = format!("[{}]", elements.join(","));
        assert_eq!(
            check_json_depth(json.as_bytes()),
            Err(BodyGuardError::JsonArrayTooLong)
        );
    }

    #[test]
    fn decompression_roundtrip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"hello world").expect("encode");
        let compressed = encoder.finish().expect("finish");
        let result = check_decompressed_size(&compressed).expect("decompress");
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn decompression_bomb_rejected() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        // Create a gzip of (MAX_DECOMPRESSED_SIZE + 1) zero bytes.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        let bomb = vec![0u8; MAX_DECOMPRESSED_SIZE + 1];
        encoder.write_all(&bomb).expect("encode");
        let compressed = encoder.finish().expect("finish");
        assert_eq!(
            check_decompressed_size(&compressed),
            Err(BodyGuardError::DecompressedSizeExceeded)
        );
    }
}

//! Constant-time comparison of the PKCE challenge and the refresh-token hash.
//!
//! Both checks used to be a plain `!=`, which returns at the first differing
//! byte. They now go through [`crate::core::ct_eq_secret_str`]. Timing is not
//! measured here; these tests pin the *equality semantics* the swap must keep:
//! a match accepts, a same-length mismatch rejects, and a different-length
//! value rejects.

use super::*;

/// A 53-character verifier and its S256 challenge, computed independently
/// (Python `hashlib.sha256` + `base64.urlsafe_b64encode`, padding stripped).
const VERIFIER: &str = "hearth-pkce-test-verifier-0123456789-abcdefghijklmnop";
const CHALLENGE: &str = "tkhZrXs-8UahTymveqbA_ABOqYwnNNwlb8osSyUgRoc";

#[test]
fn pkce_s256_matching_verifier_is_accepted() {
    assert!(EmbeddedIdentityEngine::pkce_s256_verifier_matches(
        VERIFIER, CHALLENGE
    ));
}

#[test]
fn pkce_s256_same_length_mismatch_is_rejected() {
    // Same length as the real challenge, last character changed.
    let mut forged = CHALLENGE[..CHALLENGE.len() - 1].to_string();
    forged.push('A');
    assert_eq!(forged.len(), CHALLENGE.len());
    assert_ne!(forged, CHALLENGE);
    assert!(!EmbeddedIdentityEngine::pkce_s256_verifier_matches(
        VERIFIER, &forged
    ));
    // A wrong verifier against the right challenge is rejected too.
    assert!(!EmbeddedIdentityEngine::pkce_s256_verifier_matches(
        "hearth-pkce-test-verifier-0123456789-abcdefghijklmnoq",
        CHALLENGE
    ));
}

#[test]
fn pkce_s256_different_length_challenge_is_rejected() {
    // A prefix and an extension of the real challenge: neither may match.
    assert!(!EmbeddedIdentityEngine::pkce_s256_verifier_matches(
        VERIFIER,
        &CHALLENGE[..CHALLENGE.len() - 1]
    ));
    assert!(!EmbeddedIdentityEngine::pkce_s256_verifier_matches(
        VERIFIER,
        &format!("{CHALLENGE}A")
    ));
    assert!(!EmbeddedIdentityEngine::pkce_s256_verifier_matches(
        VERIFIER, ""
    ));
}

#[test]
fn refresh_token_matching_hash_is_accepted() {
    let token = "rt-opaque-value";
    let stored = EmbeddedIdentityEngine::sha256_hex(token.as_bytes());
    assert!(EmbeddedIdentityEngine::refresh_token_matches_hash(
        token, &stored
    ));
}

#[test]
fn refresh_token_same_length_mismatch_is_rejected() {
    let stored = EmbeddedIdentityEngine::sha256_hex(b"rt-opaque-value");
    // A different token of the same length hashes to a same-length digest.
    assert!(!EmbeddedIdentityEngine::refresh_token_matches_hash(
        "rt-opaque-valuf",
        &stored
    ));
    // The stored digest with its last hex digit flipped.
    let mut flipped = stored[..stored.len() - 1].to_string();
    flipped.push(if stored.ends_with('0') { '1' } else { '0' });
    assert_eq!(flipped.len(), stored.len());
    assert!(!EmbeddedIdentityEngine::refresh_token_matches_hash(
        "rt-opaque-value",
        &flipped
    ));
}

#[test]
fn refresh_token_different_length_hash_is_rejected() {
    let stored = EmbeddedIdentityEngine::sha256_hex(b"rt-opaque-value");
    assert!(!EmbeddedIdentityEngine::refresh_token_matches_hash(
        "rt-opaque-value",
        &stored[..stored.len() - 2]
    ));
    assert!(!EmbeddedIdentityEngine::refresh_token_matches_hash(
        "rt-opaque-value",
        &format!("{stored}00")
    ));
    assert!(!EmbeddedIdentityEngine::refresh_token_matches_hash(
        "rt-opaque-value",
        ""
    ));
}

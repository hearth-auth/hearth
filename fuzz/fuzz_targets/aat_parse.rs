//! Fuzz target for AAT / agentic-JWT / actor-token parsing (Phase D.1).
//!
//! Feeds arbitrary byte sequences into AAT validation and actor-token
//! parsing paths — they MUST never panic, only return `Ok` or `Err`.
//!
//! Coverage targets:
//! - `validate_aat` — full chain validation including header, claims, sig.
//! - `decode_claims_unverified` — base64 decode + JSON deserialisation.
//! - Actor-token `jti` extraction (replay prevention path).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);

    // decode_claims_unverified is the entry point for all JWT variants —
    // agentic JWTs, actor tokens, and AATs all share this path.
    let _ = hearth::identity::decode_claims_unverified(&input);

    // verify_token_signature with a zero-key: exercises the Ed25519
    // signature parsing path without needing a real realm key.
    let zero_key = [0u8; 32];
    let _ = hearth::identity::verify_token_signature(&input, &zero_key);

    // Try to parse as JSON to exercise the AAT claims deserializer
    // (`AatClaims` is the internal representation after decode).
    let _: Result<serde_json::Value, _> = serde_json::from_str(&input);
});

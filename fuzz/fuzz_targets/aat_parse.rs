//! Fuzz target for agentic-JWT / actor-token / AAT **claim** parsing.
//!
//! ## What this reaches, and what it does not (audit 2026-09-21, task 23.13)
//!
//! `validate_aat` is a method on the `IdentityEngine` trait
//! (`src/identity/mod.rs:2678`, implemented at `src/identity/engine/mod.rs`).
//! It needs a live engine with storage, a realm, and a signing key, so no
//! `libfuzzer` target can call it. The previous version of this file claimed
//! "Coverage targets: `validate_aat` — full chain validation including header,
//! claims, sig" and then ran exactly the same three statements as
//! `jwt_parse.rs` plus a bare `serde_json::from_str::<Value>` — two of the
//! eleven CI matrix legs fuzzing the identical two functions, with one of them
//! spending a third of its budget fuzzing `serde_json` rather than Hearth.
//! The claim is removed rather than faked.
//!
//! What this target does instead is reach the part of the token pipeline that
//! `jwt_parse.rs` structurally **cannot**: the claims deserializers.
//!
//! * `decode_claims_unverified` is the hot-path entry point, so the raw bytes
//!   still go in verbatim.
//! * `verify_token_signature` / `verify_assertion_signature` reject on the
//!   Ed25519 `verify` call *before* they decode `parts[1]`
//!   (`src/identity/tokens.rs:906` and `:975`). With the all-zero key the old
//!   targets used, the `TokenClaims` and `JwtAssertionClaims` deserializers
//!   behind them are unreachable for every input, forever.
//! * So this target also assembles the fuzz bytes into a *syntactically valid*
//!   three-segment JWT (`b64url(a).b64url(b).b64url(c)`) and feeds that to
//!   `decode_claims_unverified`. Random mutation essentially never produces a
//!   dot-separated base64url triple on its own, so without this step the
//!   claims JSON parser sees an input approximately never.

#![no_main]

use libfuzzer_sys::fuzz_target;

use hearth::identity::{decode_claims_unverified, verify_assertion_signature, verify_token_signature};

/// URL-safe base64 alphabet, no padding — the JWT segment encoding.
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `bytes` as unpadded base64url.
///
/// Hand-rolled so the target takes no dependency beyond `hearth` itself: a
/// base64 crate version skew between the fuzz crate and the main tree would
/// silently change which byte sequences this target can produce.
fn b64url(bytes: &[u8], out: &mut String) {
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        let take = chunk.len() + 1; // 1 byte → 2 chars, 2 → 3, 3 → 4
        for i in 0..take {
            let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            out.push(B64URL[idx] as char);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);

    // 1. Raw bytes straight into the hot-path decoder.
    let _ = decode_claims_unverified(&input);

    // 2. Signature paths with a zero key: header parse + base64 decode + the
    //    ring `verify` rejection. Cheap, and the header deserializer is real.
    let zero_key = [0u8; 32];
    let _ = verify_token_signature(&input, &zero_key);
    let _ = verify_assertion_signature(&input, &zero_key);

    // 3. Re-shape the input into a well-formed JWT so the claims deserializer
    //    is actually reached. Split the bytes three ways; each third becomes a
    //    base64url segment. A one-byte input still yields a valid `a.b.c`.
    if data.is_empty() {
        return;
    }
    let third = data.len().div_ceil(3).max(1);
    let mut token = String::with_capacity(data.len() * 2 + 2);
    for (i, part) in data.chunks(third).take(3).enumerate() {
        if i > 0 {
            token.push('.');
        }
        b64url(part, &mut token);
    }
    // `chunks` yields fewer than three parts for short inputs; pad to exactly
    // three segments so the `parts.len() != 3` guard is not what rejects it.
    while token.matches('.').count() < 2 {
        token.push('.');
        token.push('A');
    }
    let _ = decode_claims_unverified(&token);
    let _ = verify_token_signature(&token, &zero_key);
});

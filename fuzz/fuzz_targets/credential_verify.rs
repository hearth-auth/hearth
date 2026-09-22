//! Fuzz target for credential / password-hash verification.
//!
//! ## What this exercises
//!
//! The PHC-string parsers behind [`verify_password_with_pepper`], which is the
//! function every login goes through:
//!
//! * `verify_hash` prefix dispatch — `$2a$`/`$2b$`/`$2y$` (bcrypt),
//!   `$pbkdf2-sha256$`, and `PasswordHash::new` for Argon2id / scrypt.
//! * `verify_pbkdf2_sha256` — the hand-rolled PHC parser written for Keycloak
//!   imports (segment count, `i=` parse, two base64 decodes, length-derived
//!   output buffer). It is the only password parser in the tree that is not
//!   delegated to the `password-hash` crate.
//! * `PepperKey::from_hex` — the operator-supplied pepper parser.
//! * The four `verify_password_with_pepper` rotation arms (active version,
//!   grace-window previous version, unrecognised version, legacy `None`),
//!   including `apply_pepper`'s HMAC pre-hash.
//!
//! ## Why it is written this way (audit 2026-09-21, task 23.13)
//!
//! The previous version of this target was:
//!
//! ```text
//! let password = CleartextPassword::new(data.to_vec());
//! let lossy_hash = String::from_utf8_lossy(data);
//! drop(password);
//! drop(lossy_hash);
//! ```
//!
//! It constructed two values and dropped them. It called no verifier, no
//! parser, and no Hearth code beyond a `Vec` move — so it could not fail for
//! any input, while occupying a leg of the CI fuzz matrix and a paragraph of
//! doc comment claiming it covered `verify_token_signature` (which it never
//! called either). Verified by mutation: a `panic!("mutation")` planted at the
//! top of `credentials::verify_hash` survived 1 000 runs of the old target and
//! is found by this one in a single run.
//!
//! An attacker does not choose the stored hash directly, but a *legacy
//! importer* does: bcrypt/scrypt/PBKDF2 hashes only ever enter Hearth through
//! a migration from another IdP, so the stored PHC string is exactly the kind
//! of half-trusted input a parser bug hides in.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use hearth::identity::{
    hash_password, verify_password_with_pepper, CleartextPassword, CredentialConfig, PepperKey,
    StoredCredential,
};

/// A real Argon2id credential, hashed once for the whole run.
///
/// `hash_password` costs milliseconds even at test parameters, which would
/// dominate every iteration; the credential is a template whose `hash` field
/// each iteration overwrites with the fuzz input.
static TEMPLATE: OnceLock<Option<StoredCredential>> = OnceLock::new();

/// The password `TEMPLATE` was hashed from, so the success path is reachable.
const TEMPLATE_PASSWORD: &[u8] = b"correct horse battery staple";

/// Upper bound on the PBKDF2 iteration count this harness will let through.
///
/// `verify_pbkdf2_sha256` parses `i=` as a `u32` and rejects only zero, so a
/// stored hash declaring `i=4294967295` makes verification run ~4.3 billion
/// HMAC-SHA256 rounds — hours of CPU per login attempt. That is a real
/// unbounded-work finding against the legacy-import path (reported separately;
/// the fix belongs in `credentials::verify_pbkdf2_sha256`, not here). Until it
/// is capped at the source, skipping such inputs is what keeps this target
/// from hanging a CI leg instead of reporting a crash.
const MAX_PBKDF2_ITERATIONS: u64 = 1_000_000;

/// Trailing byte that opts an input into the Argon2id-executing steps.
const KDF_MARKER: u8 = 0xA5;

/// Whether `hash_str` declares a PBKDF2 iteration count this harness refuses
/// to spend CPU on. Mirrors `verify_pbkdf2_sha256`'s own segment split.
fn pbkdf2_iterations_are_absurd(hash_str: &str) -> bool {
    let Some(rest) = hash_str.strip_prefix("$pbkdf2-sha256$") else {
        return false;
    };
    let Some(params) = rest.split('$').next() else {
        return false;
    };
    params
        .strip_prefix("i=")
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|i| i > MAX_PBKDF2_ITERATIONS)
}

fuzz_target!(|data: &[u8]| {
    let cheap = CredentialConfig::fast_for_testing();

    // 1. The bytes as a password. `CleartextPassword` takes arbitrary bytes,
    //    including interior NULs and invalid UTF-8.
    let password = CleartextPassword::new(data.to_vec());

    // 2. The bytes as a stored PHC hash string — the parser surface.
    let lossy_hash = String::from_utf8_lossy(data).into_owned();

    let template = TEMPLATE
        .get_or_init(|| hash_password(&CleartextPassword::new(TEMPLATE_PASSWORD.to_vec()), &cheap, 0).ok())
        .as_ref();
    let Some(template) = template else {
        // Argon2id could not be initialised at all; nothing below is meaningful.
        return;
    };

    if !pbkdf2_iterations_are_absurd(&lossy_hash) {
        // 2a. Arbitrary hash string, no pepper: prefix dispatch, the PBKDF2
        //     PHC parser, and `PasswordHash::new` for everything else.
        let mut credential = template.clone();
        credential.hash = lossy_hash.clone();
        credential.pepper_version = None;
        let _ = verify_password_with_pepper(&password, &credential, &cheap);

        // 2b. Same hash string, but the credential claims a pepper version the
        //     config does not know — the "grace window closed" rejection arm.
        let mut stale = template.clone();
        stale.hash = lossy_hash.clone();
        stale.pepper_version = Some(u32::MAX);
        let _ = verify_password_with_pepper(&password, &stale, &cheap);
    }

    // 3. The pepper parser. Operator-facing (`hearth.yaml`), cheap, so it runs
    //    on every input.
    let _ = PepperKey::from_hex(&lossy_hash);

    // Steps 4 and 5 run a real Argon2id KDF, which is milliseconds per call
    // even at test parameters and orders of magnitude slower than every parser
    // above. Gating them on a one-byte marker keeps the parser surface running
    // at full fuzzing speed; `-sanitizer-coverage-trace-compares` solves a
    // single-byte equality in a handful of iterations, and
    // `fuzz/seeds/credential_verify/` ships inputs that already carry it so a
    // 1 000-run CI smoke reaches both steps from the first execution.
    if data.last() != Some(&KDF_MARKER) {
        return;
    }

    // 4. The success path: the *correct* password against the *real* Argon2id
    //    hash. A target that only ever exercises rejection cannot tell a
    //    verifier that always says "no" from one that works.
    let correct = CleartextPassword::new(TEMPLATE_PASSWORD.to_vec());
    let _ = verify_password_with_pepper(&correct, template, &cheap);

    // 5. The peppered rotation arms, including `apply_pepper`'s HMAC pre-hash.
    if let Ok(key) = PepperKey::new(data.to_vec()) {
        let peppered_cfg = CredentialConfig::fast_for_testing_with_pepper(1, key);
        // Hash and re-verify under the pepper: exercises `apply_pepper`'s HMAC
        // pre-hash on both the write and the read side, and the version-match
        // arm of the rotation match.
        if let Ok(peppered) = hash_password(&correct, &peppered_cfg, 0) {
            let _ = verify_password_with_pepper(&correct, &peppered, &peppered_cfg);
            let _ = verify_password_with_pepper(&password, &peppered, &peppered_cfg);
            // Legacy credential (no version) read under a peppered config.
            let mut legacy = peppered;
            legacy.pepper_version = None;
            let _ = verify_password_with_pepper(&correct, &legacy, &peppered_cfg);
        }
    }
});

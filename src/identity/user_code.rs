//! RFC 8628 device-authorization **user codes**.
//!
//! # The modulo-bias defect (task 22.26, audit 2026-08-28 §4.25#4)
//!
//! The alphabet has 28 symbols and the generator drew one uniform byte per
//! character, mapping it with `byte % 28`. 256 is not a multiple of 28:
//! `256 = 9 × 28 + 4`. Bytes `0..=3` therefore have a tenth pre-image while
//! every other symbol has nine, so the first four symbols of the alphabet
//! (`B`, `C`, `D`, `F`) each appear with probability `10/256` instead of
//! `9/256` — 11 % more often than the rest.
//!
//! The practical effect is small (an eight-character code loses roughly
//! 0.02 bits of the ~38.5 bits it nominally carries) but it is free to fix and
//! it is exactly the class of defect that compounds when someone later reuses
//! the helper with a shorter code.
//!
//! # The fix: rejection sampling
//!
//! [`ACCEPT_LIMIT`] is the largest multiple of the alphabet length that fits
//! in a byte (`9 × 28 = 252`). Bytes `252..=255` are discarded and redrawn, so
//! every accepted byte comes from a range that *is* an exact multiple of 28
//! and each symbol has exactly nine pre-images. The expected number of
//! redraws is `4/256` per character — statistically free.

use ring::rand::SecureRandom;

use crate::identity::IdentityError;

/// Unambiguous alphabet for device user codes (RFC 8628 §6.1).
///
/// Excludes `I`/`1`, `O`/`0`, `L`, `U`, `A`, `E` to avoid visual confusion and
/// accidental words. 28 characters.
pub const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTVWXYZ23456789";

/// User code length, in characters.
pub const USER_CODE_LENGTH: usize = 8;

/// Largest multiple of [`USER_CODE_ALPHABET`]'s length that fits in a `u8`.
///
/// Bytes at or above this value are rejected and redrawn; below it, `% 28` is
/// exactly uniform.
pub const ACCEPT_LIMIT: u16 = 256 - (256 % USER_CODE_ALPHABET.len() as u16);

/// Maps one random byte to a user-code character, or `None` when the byte
/// falls in the rejection region and must be redrawn.
///
/// Exposed so the uniformity property can be asserted directly rather than
/// only inferred from a statistical sample.
#[must_use]
pub fn user_code_char_for_byte(byte: u8) -> Option<char> {
    if u16::from(byte) >= ACCEPT_LIMIT {
        return None;
    }
    let idx = usize::from(byte) % USER_CODE_ALPHABET.len();
    Some(USER_CODE_ALPHABET[idx] as char)
}

/// Generates a [`USER_CODE_LENGTH`]-character user code with an exactly
/// uniform character distribution.
///
/// # Errors
///
/// Returns [`IdentityError::SigningError`] if the OS entropy source fails.
pub fn generate_user_code() -> Result<String, IdentityError> {
    let rng = ring::rand::SystemRandom::new();
    generate_user_code_with(&rng)
}

/// [`generate_user_code`] against a caller-supplied RNG, so a caller that
/// already holds a [`ring::rand::SystemRandom`] does not construct a second.
///
/// # Errors
///
/// Returns [`IdentityError::SigningError`] if the OS entropy source fails.
pub fn generate_user_code_with(rng: &dyn SecureRandom) -> Result<String, IdentityError> {
    let mut code = String::with_capacity(USER_CODE_LENGTH);
    // Draw a whole batch at a time and only refill when the batch is spent.
    // At a 4/256 rejection rate a single batch of 16 covers 8 characters with
    // probability > 0.99; the loop handles the remainder.
    let mut buf = [0u8; 16];
    let mut next = buf.len();
    while code.len() < USER_CODE_LENGTH {
        if next == buf.len() {
            rng.fill(&mut buf)
                .map_err(|_| IdentityError::SigningError {
                    reason: "random generation failed".to_string(),
                })?;
            next = 0;
        }
        let byte = buf[next];
        next += 1;
        if let Some(ch) = user_code_char_for_byte(byte) {
            code.push(ch);
        }
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_limit_is_an_exact_multiple_of_the_alphabet() {
        let n = USER_CODE_ALPHABET.len() as u16;
        assert_eq!(ACCEPT_LIMIT, 252, "9 * 28");
        assert_eq!(
            ACCEPT_LIMIT % n,
            0,
            "accepted range must be a whole number of alphabet cycles"
        );
        assert!(
            ACCEPT_LIMIT + n > 256,
            "must be the *largest* such multiple"
        );
    }

    /// The deterministic form of the uniformity property: every symbol must
    /// have exactly the same number of accepted byte pre-images.
    #[test]
    fn every_symbol_has_the_same_number_of_preimages() {
        let mut counts = [0u32; 28];
        let mut rejected = 0u32;
        for b in 0..=u8::MAX {
            match user_code_char_for_byte(b) {
                Some(ch) => {
                    let idx = USER_CODE_ALPHABET
                        .iter()
                        .position(|&a| a as char == ch)
                        .expect("char must be in the alphabet");
                    counts[idx] += 1;
                }
                None => rejected += 1,
            }
        }
        assert_eq!(rejected, 4, "256 % 28 == 4 bytes must be rejected");
        for (i, c) in counts.iter().enumerate() {
            assert_eq!(
                *c, 9,
                "symbol {} has {c} pre-images, expected 9 — modulo bias",
                USER_CODE_ALPHABET[i] as char
            );
        }
    }

    #[test]
    fn generated_codes_have_the_right_shape() {
        for _ in 0..64 {
            let code = generate_user_code().expect("generate");
            assert_eq!(code.len(), USER_CODE_LENGTH);
            assert!(
                code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)),
                "code {code:?} contains a character outside the alphabet"
            );
        }
    }
}

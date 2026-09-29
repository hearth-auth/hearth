//! High-entropy opaque secrets and length-blind constant-time comparison.
//!
//! # Why this module exists
//!
//! Two cryptographic-hygiene defects motivated it (audit 2026-08-28 §4.25#5
//! and §4.25#6):
//!
//! 1. **122-bit secrets.** Several bearer-shaped values (PAR `request_uri`
//!    identifiers, consent tickets, federation confirm tickets, the SAML
//!    `RelayState` token, session identifiers) were minted as UUID v4 strings.
//!    A v4 UUID spends 4 bits on the version nibble and 2 bits on the variant,
//!    leaving 122 bits of randomness. RFC 9126 §7.1 makes 128 bits the
//!    normative floor for a PAR `request_uri`, and the same floor is the right
//!    default for every other unguessable handle Hearth issues.
//!    [`random_secret_hex`] and [`random_secret_uuid`] draw a full 16 bytes
//!    (128 bits) from the OS CSPRNG with no structural bits reserved.
//!
//! 2. **Variable-time secret comparison.** Secret-shaped values were compared
//!    with `==` / `!=`, which short-circuits on the first differing byte.
//!    [`ct_eq_secret`] hashes both sides with SHA-256 first and then compares
//!    the two fixed-width digests in constant time, so neither the position of
//!    the first difference **nor the length** of either input is observable.
//!
//! # Why hash-then-compare rather than a bare `subtle::ct_eq`
//!
//! `subtle::ConstantTimeEq` for slices returns early when the two slices have
//! different lengths, so a bare `a.ct_eq(b)` still leaks whether the candidate
//! is the right length. Hashing both operands to a 32-byte digest removes that
//! channel: the comparison always runs over exactly 32 bytes regardless of the
//! inputs. The extra SHA-256 is a few hundred nanoseconds and none of these
//! call sites are on the hot path.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of random bytes behind every Hearth-issued opaque secret.
///
/// 16 bytes == 128 bits, the floor RFC 9126 §7.1 makes normative for a PAR
/// `request_uri` and the value Hearth applies uniformly to every unguessable
/// handle it mints.
pub const SECRET_BYTES: usize = 16;

/// Draws [`SECRET_BYTES`] bytes from the operating-system CSPRNG.
///
/// Panics only if the OS entropy source itself fails, which
/// [`rand_core::OsRng`] treats as unrecoverable. Failing closed on a broken
/// CSPRNG is the correct behaviour: returning a low-entropy secret would be
/// worse than aborting.
#[must_use]
pub fn random_secret_bytes() -> [u8; SECRET_BYTES] {
    let mut buf = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Returns a 32-character lowercase-hex string carrying 128 bits of entropy.
///
/// The shape is deliberately identical to `Uuid::simple()` output (32 hex
/// characters) so it is a drop-in replacement at call sites that previously
/// formatted a UUID, and it is safe in URLs, cookies, and storage-key
/// suffixes without escaping.
#[must_use]
pub fn random_secret_hex() -> String {
    hex::encode(random_secret_bytes())
}

/// Returns a `Uuid` whose 128 bits are **all** random.
///
/// Unlike [`Uuid::new_v4`] this does not reserve the version or variant bits,
/// so the value carries 128 bits of entropy instead of 122. It still parses,
/// formats, sorts, and serializes exactly like any other UUID — `Uuid` does
/// not validate the version nibble on parse — so storage keys and wire shapes
/// that already carry a UUID keep working unchanged.
///
/// Do **not** use this for identifiers whose UUID *version* carries meaning.
/// `ClientId`, for example, uses `get_version_num() == 5` to distinguish
/// YAML-reconciled clients from hand-registered ones; a full-entropy UUID
/// would land on version 5 one time in sixteen and corrupt that heuristic.
/// This constructor is for unguessable handles only.
#[must_use]
pub fn random_secret_uuid() -> Uuid {
    Uuid::from_bytes(random_secret_bytes())
}

/// Compares two secret-shaped byte strings without leaking their contents or
/// their lengths through timing.
///
/// Both operands are hashed with SHA-256 and the resulting 32-byte digests are
/// compared with `subtle`'s constant-time equality, so the work performed is
/// independent of where (or whether) the inputs diverge.
#[must_use]
pub fn ct_eq_secret(a: &[u8], b: &[u8]) -> bool {
    let ha = Sha256::digest(a);
    let hb = Sha256::digest(b);
    ha.ct_eq(&hb).into()
}

/// [`ct_eq_secret`] for `str` operands.
#[must_use]
pub fn ct_eq_secret_str(a: &str, b: &str) -> bool {
    ct_eq_secret(a.as_bytes(), b.as_bytes())
}

/// [`ct_eq_secret`] for optional operands.
///
/// Returns `false` when either side is absent. Both `Some` arms still run the
/// full hash-and-compare, so presence is the only thing a caller can observe.
#[must_use]
pub fn ct_eq_secret_opt(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => ct_eq_secret_str(a, b),
        _ => false,
    }
}

/// A secret received in a request: a password, a one-time token, a client
/// secret or an assertion (GA audit L20).
///
/// Form and JSON bodies used to hold these as plain `String`s, which are
/// freed without being overwritten, so a password outlived the request in
/// whatever heap page it landed on. `FormSecret` is zeroized on drop, and its
/// `Debug` prints a placeholder so a derived `Debug` on the containing struct
/// is safe. It deliberately implements neither `Display` nor `Serialize`.
///
/// It deserializes from a plain string, so it drops into an axum `Form`,
/// `Json` or `Query` extractor unchanged. The string serde hands over is moved
/// in, not copied.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct FormSecret(String);

impl FormSecret {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The secret's value. Callers must not log it or copy it into a
    /// non-zeroizing buffer that outlives the request.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is the empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The secret's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Reads as a `&str`, so `Option<FormSecret>::as_deref()` and `&str`
/// parameters work unchanged. Copying the value out (`to_string()`) produces
/// a buffer that is *not* wiped; do that only where an API demands a `String`.
impl std::ops::Deref for FormSecret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for FormSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FormSecret(<redacted>)")
    }
}

impl<'de> serde::Deserialize<'de> for FormSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Compile-time check that `T` is wiped on drop. Tests call it on each
/// secret-bearing request field; the call only type-checks when the field's
/// type is [`ZeroizeOnDrop`].
#[cfg(test)]
pub(crate) fn assert_zeroize_on_drop<T: ZeroizeOnDrop>(_: &T) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every one of the 128 bits must vary across a sample. A UUID v4 pins six
    /// of them (the version nibble and the two variant bits), so this is the
    /// direct regression guard for the 122-bit defect.
    fn assert_all_128_bits_vary(samples: &[[u8; 16]]) {
        let mut seen_zero = [false; 128];
        let mut seen_one = [false; 128];
        for s in samples {
            for bit in 0..128 {
                let set = s[bit / 8] & (0x80 >> (bit % 8)) != 0;
                if set {
                    seen_one[bit] = true;
                } else {
                    seen_zero[bit] = true;
                }
            }
        }
        for bit in 0..128 {
            assert!(
                seen_zero[bit] && seen_one[bit],
                "bit {bit} never took both values across {} samples — \
                 it is structurally fixed, so the value carries < 128 bits",
                samples.len()
            );
        }
    }

    #[test]
    fn random_secret_bytes_uses_all_128_bits() {
        let samples: Vec<[u8; 16]> = (0..256).map(|_| random_secret_bytes()).collect();
        assert_all_128_bits_vary(&samples);
    }

    #[test]
    fn random_secret_uuid_uses_all_128_bits() {
        let samples: Vec<[u8; 16]> = (0..256).map(|_| *random_secret_uuid().as_bytes()).collect();
        assert_all_128_bits_vary(&samples);
    }

    #[test]
    fn random_secret_hex_decodes_to_16_bytes() {
        let s = random_secret_hex();
        assert_eq!(s.len(), 32, "expected 32 hex characters");
        let decoded = hex::decode(&s).expect("valid hex");
        assert_eq!(decoded.len(), SECRET_BYTES);
    }

    #[test]
    fn random_secret_hex_uses_all_128_bits() {
        let samples: Vec<[u8; 16]> = (0..256)
            .map(|_| {
                let mut out = [0u8; 16];
                let raw = hex::decode(random_secret_hex()).expect("valid hex");
                out.copy_from_slice(&raw);
                out
            })
            .collect();
        assert_all_128_bits_vary(&samples);
    }

    #[test]
    fn random_secret_uuid_round_trips_through_string() {
        let u = random_secret_uuid();
        let parsed: Uuid = u.to_string().parse().expect("full-entropy UUID must parse");
        assert_eq!(u, parsed);
    }

    #[test]
    fn ct_eq_secret_matches_equality_semantics() {
        assert!(ct_eq_secret_str("abc", "abc"));
        assert!(!ct_eq_secret_str("abc", "abd"));
        assert!(!ct_eq_secret_str("abc", "abcd"));
        assert!(!ct_eq_secret_str("", "a"));
        assert!(ct_eq_secret_str("", ""));
    }

    #[test]
    fn ct_eq_secret_opt_requires_both_sides() {
        assert!(ct_eq_secret_opt(Some("x"), Some("x")));
        assert!(!ct_eq_secret_opt(Some("x"), Some("y")));
        assert!(!ct_eq_secret_opt(None, Some("x")));
        assert!(!ct_eq_secret_opt(Some("x"), None));
        assert!(!ct_eq_secret_opt(None, None));
    }

    // ── FormSecret (GA audit L20) ────────────────────────────────────────────

    #[derive(serde::Deserialize, Debug)]
    struct Body {
        name: String,
        secret: FormSecret,
        #[serde(default)]
        maybe: Option<FormSecret>,
    }

    #[test]
    fn form_secret_deserializes_from_a_urlencoded_form() {
        let body: Body = serde_urlencoded::from_str("name=a&secret=CANARY-f0rm&maybe=CANARY-opt")
            .expect("form parses");
        assert_eq!(body.name, "a");
        assert_eq!(body.secret.expose(), "CANARY-f0rm");
        assert_eq!(
            body.maybe.as_ref().map(FormSecret::expose),
            Some("CANARY-opt")
        );
        assert_zeroize_on_drop(&body.secret);
        assert_zeroize_on_drop(&body.maybe);
    }

    #[test]
    fn form_secret_deserializes_from_json_and_defaults_when_absent() {
        let body: Body =
            serde_json::from_str(r#"{"name":"a","secret":"CANARY-js0n"}"#).expect("json parses");
        assert_eq!(body.secret.expose(), "CANARY-js0n");
        assert!(body.maybe.is_none(), "an absent optional secret is None");
    }

    #[test]
    fn form_secret_debug_never_prints_the_value() {
        let body: Body = serde_urlencoded::from_str("name=a&secret=CANARY-f0rm&maybe=CANARY-opt")
            .expect("form parses");
        let dbg = format!("{body:?}");
        assert!(!dbg.contains("CANARY"), "Debug leaked a secret: {dbg}");
        assert!(
            dbg.contains("name: \"a\""),
            "non-secret fields still print: {dbg}"
        );
    }

    #[test]
    fn form_secret_zeroize_wipes_the_buffer() {
        let mut s = FormSecret::new("CANARY-wipe".to_string());
        assert_eq!(s.len(), 11);
        zeroize::Zeroize::zeroize(&mut s);
        assert!(s.is_empty(), "zeroize must leave no content behind");
    }
}

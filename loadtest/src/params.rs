//! Deterministic, parameterized seed dataset shape (HEA-1789).
//!
//! Every knob that controls the seeded corpus lives here, together with the
//! deterministic derivations that turn `(seed, realm_index, user_index)` into
//! concrete emails and passwords. Determinism is the point: the same
//! parameters always produce the same dataset, so a load run is reproducible
//! and its report header fully describes the corpus it ran against.
//!
//! Nothing in this module performs I/O — it is pure and unit-tested. The HTTP
//! seeding orchestration lives in [`crate::seed`].

use clap::Args;

/// Parameters controlling the seeded dataset shape.
///
/// Defaults mirror the plan (HEA-1787 §6). Every field has a CLI flag and an
/// environment-variable fallback so `make seed` / `make seed-large` can drive
/// it without long argument lists.
#[derive(Debug, Clone, Args)]
pub struct SeedParams {
    /// Base URL of a running Hearth instance to seed against.
    ///
    /// The seed step attaches over HTTP; it does not boot Hearth itself. Point
    /// this at a dev instance (`make dev`) or a large-corpus instance
    /// (`make seed-large`). MUST be a loopback / dev address — see the README
    /// security warning.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_TARGET_HOST",
        default_value = "http://127.0.0.1:8420"
    )]
    pub target_host: String,

    /// Number of realms to seed into.
    ///
    /// NOTE: the current server disables `POST /admin/realms` (realms are
    /// declared in `hearth.yaml`). Values > the number of realms the admin
    /// token can authenticate against are clamped at seed time with a logged
    /// warning; see the README.
    #[arg(long, env = "HEARTH_LOADTEST_REALMS", default_value_t = 5)]
    pub realms: u32,

    /// Users to create per realm.
    #[arg(long, env = "HEARTH_LOADTEST_USERS_PER_REALM", default_value_t = 200)]
    pub users_per_realm: u32,

    /// Fraction of users (0.0..=1.0) that get a live session + access token.
    #[arg(long, env = "HEARTH_LOADTEST_SESSIONS_FRAC", default_value_t = 0.5)]
    pub sessions_frac: f64,

    /// Fraction of the live tokens (0.0..=1.0) that are pre-revoked, so the
    /// revoke-cache / `active:false` path has real data on the first hit.
    #[arg(long, env = "HEARTH_LOADTEST_REVOKED_FRAC", default_value_t = 0.1)]
    pub revoked_frac: f64,

    /// Deterministic seed. The same value reproduces the same emails and
    /// (ephemeral, never-persisted) passwords across runs.
    #[arg(long, env = "HEARTH_LOADTEST_SEED", default_value_t = 1)]
    pub seed: u64,

    /// Output path for the JSON seed-handle. The parent directory MUST be
    /// gitignored — the handle holds live bearer tokens.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_SEED_OUT",
        default_value = "loadtest/reports/seed-handle.json"
    )]
    pub seed_out: String,
}

/// Errors from validating [`SeedParams`].
#[derive(Debug, PartialEq, Eq)]
pub enum ParamError {
    /// A fraction field was outside the inclusive `0.0..=1.0` range.
    FractionOutOfRange(&'static str),
    /// `users_per_realm` was zero — nothing to seed.
    NoUsers,
    /// `realms` was zero — nothing to seed.
    NoRealms,
}

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FractionOutOfRange(field) => {
                write!(f, "{field} must be between 0.0 and 1.0 inclusive")
            }
            Self::NoUsers => write!(f, "users-per-realm must be at least 1"),
            Self::NoRealms => write!(f, "realms must be at least 1"),
        }
    }
}

impl std::error::Error for ParamError {}

impl SeedParams {
    /// Validates the parameter combination. Call before any seeding I/O.
    ///
    /// # Errors
    /// Returns a [`ParamError`] describing the first invalid field.
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.realms == 0 {
            return Err(ParamError::NoRealms);
        }
        if self.users_per_realm == 0 {
            return Err(ParamError::NoUsers);
        }
        if !(0.0..=1.0).contains(&self.sessions_frac) {
            return Err(ParamError::FractionOutOfRange("sessions-frac"));
        }
        if !(0.0..=1.0).contains(&self.revoked_frac) {
            return Err(ParamError::FractionOutOfRange("revoked-frac"));
        }
        Ok(())
    }

    /// Number of live sessions to mint per realm, rounded to nearest.
    #[must_use]
    pub fn sessions_per_realm(&self) -> u32 {
        frac_of(self.users_per_realm, self.sessions_frac)
    }

    /// Number of the minted sessions (per realm) to pre-revoke, rounded to
    /// nearest.
    #[must_use]
    pub fn revoked_per_realm(&self) -> u32 {
        frac_of(self.sessions_per_realm(), self.revoked_frac)
    }

    /// Deterministic email for the user at `(realm_index, user_index)`.
    ///
    /// The `.test` TLD is reserved (RFC 6761) and never resolvable, which keeps
    /// seeded addresses from colliding with anything real.
    #[must_use]
    pub fn user_email(&self, realm_index: u32, user_index: u32) -> String {
        format!(
            "loaduser-{}-r{realm_index}-u{user_index}@loadtest.test",
            self.seed
        )
    }

    /// Deterministic, high-entropy password for a seeded user.
    ///
    /// Derived from `(seed, realm_index, user_index)` so it is reproducible but
    /// unguessable without the seed. It is the credential a seeded user *would*
    /// authenticate with; it is **never** written to the seed handle or any log.
    ///
    /// NOTE: the boot-local REST flow cannot yet consume this — `POST
    /// /admin/users` has no way to set a password (see [`crate::seed`]). It is
    /// exercised by the unit tests and reserved for the `hearth.yaml`
    /// seed-user attach path, where users are pre-provisioned with these
    /// deterministic credentials. Kept public + `dead_code`-allowed until that
    /// path is wired.
    #[must_use]
    #[allow(dead_code)]
    pub fn user_password(&self, realm_index: u32, user_index: u32) -> String {
        // splitmix64 over a mixed key: no external RNG dependency, and a fixed
        // seed yields a fixed password. 128 bits of derived entropy, rendered
        // as 32 hex chars, comfortably clears any realm password policy floor.
        let key = self
            .seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(u64::from(realm_index) << 32)
            .wrapping_add(u64::from(user_index));
        let hi = splitmix64(key);
        let lo = splitmix64(key ^ 0xD1B5_4A32_D192_ED03);
        // Prefix guarantees an upper-case letter and a symbol so policies that
        // require character classes are satisfied regardless of the hex tail.
        format!("Ld!{hi:016x}{lo:016x}")
    }

    /// One-line human-readable description of the corpus, for the report header
    /// and log output. Contains no secret material.
    #[must_use]
    pub fn dataset_shape_summary(&self) -> String {
        format!(
            "realms={} users/realm={} sessions/realm={} revoked/realm={} \
             (sessions_frac={} revoked_frac={} seed={})",
            self.realms,
            self.users_per_realm,
            self.sessions_per_realm(),
            self.revoked_per_realm(),
            self.sessions_frac,
            self.revoked_frac,
            self.seed,
        )
    }
}

/// `round(count * frac)`, saturating and clamped to `count`.
fn frac_of(count: u32, frac: f64) -> u32 {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let n = (f64::from(count) * frac).round() as i64;
    n.clamp(0, i64::from(count)) as u32
}

/// Fast, dependency-free deterministic bit mixer (Vigna's splitmix64).
/// Only reachable via [`SeedParams::user_password`]; see that method's note.
#[allow(dead_code)]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Minimal CLI wrapper so we can exercise clap parsing of `SeedParams`
    /// exactly as `main` does.
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        params: SeedParams,
    }

    fn parse(args: &[&str]) -> SeedParams {
        // clap requires argv[0]; prepend a dummy binary name.
        let mut argv = vec!["hearth-loadtest"];
        argv.extend_from_slice(args);
        TestCli::parse_from(argv).params
    }

    #[test]
    fn defaults_match_the_plan() {
        let p = parse(&[]);
        assert_eq!(p.realms, 5);
        assert_eq!(p.users_per_realm, 200);
        assert!((p.sessions_frac - 0.5).abs() < f64::EPSILON);
        assert!((p.revoked_frac - 0.1).abs() < f64::EPSILON);
        assert_eq!(p.target_host, "http://127.0.0.1:8420");
        p.validate().expect("defaults are valid");
    }

    #[test]
    fn flags_parse_and_override_defaults() {
        let p = parse(&[
            "--realms",
            "3",
            "--users-per-realm",
            "10",
            "--sessions-frac",
            "0.25",
            "--revoked-frac",
            "0.5",
            "--target-host",
            "http://127.0.0.1:9999",
            "--seed",
            "42",
        ]);
        assert_eq!(p.realms, 3);
        assert_eq!(p.users_per_realm, 10);
        assert!((p.sessions_frac - 0.25).abs() < f64::EPSILON);
        assert_eq!(p.seed, 42);
        assert_eq!(p.target_host, "http://127.0.0.1:9999");
    }

    #[test]
    fn validate_rejects_out_of_range_fractions() {
        let mut p = parse(&[]);
        p.sessions_frac = 1.5;
        assert_eq!(
            p.validate(),
            Err(ParamError::FractionOutOfRange("sessions-frac"))
        );
        p.sessions_frac = 0.5;
        p.revoked_frac = -0.1;
        assert_eq!(
            p.validate(),
            Err(ParamError::FractionOutOfRange("revoked-frac"))
        );
    }

    #[test]
    fn validate_rejects_empty_corpus() {
        let mut p = parse(&[]);
        p.realms = 0;
        assert_eq!(p.validate(), Err(ParamError::NoRealms));
        p.realms = 1;
        p.users_per_realm = 0;
        assert_eq!(p.validate(), Err(ParamError::NoUsers));
    }

    #[test]
    fn session_and_revoke_counts_round_and_clamp() {
        let p = parse(&[
            "--users-per-realm",
            "200",
            "--sessions-frac",
            "0.5",
            "--revoked-frac",
            "0.1",
        ]);
        assert_eq!(p.sessions_per_realm(), 100);
        assert_eq!(p.revoked_per_realm(), 10);

        // 0 fractions → 0; full fractions → full count.
        let none = parse(&["--users-per-realm", "10", "--sessions-frac", "0.0"]);
        assert_eq!(none.sessions_per_realm(), 0);
        assert_eq!(none.revoked_per_realm(), 0);
        let all = parse(&[
            "--users-per-realm",
            "10",
            "--sessions-frac",
            "1.0",
            "--revoked-frac",
            "1.0",
        ]);
        assert_eq!(all.sessions_per_realm(), 10);
        assert_eq!(all.revoked_per_realm(), 10);
    }

    #[test]
    fn derivations_are_deterministic_for_a_fixed_seed() {
        let a = parse(&["--seed", "7"]);
        let b = parse(&["--seed", "7"]);
        assert_eq!(a.user_email(1, 2), b.user_email(1, 2));
        assert_eq!(a.user_password(1, 2), b.user_password(1, 2));
    }

    #[test]
    fn derivations_differ_by_seed_and_by_index() {
        let s7 = parse(&["--seed", "7"]);
        let s8 = parse(&["--seed", "8"]);
        assert_ne!(s7.user_password(0, 0), s8.user_password(0, 0));
        assert_ne!(s7.user_password(0, 0), s7.user_password(0, 1));
        assert_ne!(s7.user_password(0, 0), s7.user_password(1, 0));
        assert_ne!(s7.user_email(0, 0), s7.user_email(0, 1));
    }

    #[test]
    fn derived_password_shape_satisfies_policy_classes() {
        let p = parse(&["--seed", "123"]);
        let pw = p.user_password(4, 9);
        assert!(pw.len() >= 12, "password too short: {}", pw.len());
        assert!(pw.chars().any(char::is_uppercase), "needs upper-case");
        assert!(pw.chars().any(char::is_numeric), "needs a digit");
        assert!(pw.contains('!'), "needs a symbol");
    }

    #[test]
    fn dataset_summary_mentions_shape_and_no_secrets() {
        let p = parse(&["--seed", "77"]);
        let s = p.dataset_shape_summary();
        assert!(s.contains("realms=5"));
        assert!(s.contains("users/realm=200"));
        // The summary must never leak a derived password.
        assert!(!s.contains(&p.user_password(0, 0)));
    }
}

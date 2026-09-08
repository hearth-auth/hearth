#![allow(clippy::unwrap_used)]
//! Claim release gates declared in `hearth.yaml` (audit 2026-08-28 §4.13#3).
//!
//! Two defects, one blast radius — a claim that reaches a third-party client
//! when the operator believed it was gated:
//!
//! 1. A **misspelled** release gate (`first_party_onlyy`, `required_scope`)
//!    was silently discarded. The mapping then carried the struct default —
//!    `first_party_only: false`, no scope requirement — and the claim was
//!    emitted to every client.
//! 2. The documented **Tier-3 default** (`first_party_only: true` for custom
//!    claim names) was not implemented. A custom mapper declared with no
//!    gates at all released to third-party clients.

use hearth::config::Config;
use hearth::identity::claims_config::ClaimMapping;

/// Production validation prerequisites, so these tests fail on the claim
/// profile and nothing else.
const PREAMBLE: &str = r#"
oidc:
  issuer: "https://auth.example.com"
server:
  trust_forwarded_proto: true
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
"#;

fn config_with_claims(mappings_yaml: &str) -> Result<Config, String> {
    let yaml = format!("{PREAMBLE}realms:\n  acme:\n    claims:\n      mappings:\n{mappings_yaml}");
    Config::from_yaml_str(&yaml).map_err(|e| e.to_string())
}

/// Resolves the realm's effective claim profile the way startup does.
fn effective_mappings(config: &Config) -> Vec<ClaimMapping> {
    let realms = config.realms.as_ref().expect("realms block");
    let realm = realms.get("acme").expect("acme realm");
    realm
        .to_realm_config(&config.auth, None)
        .expect("realm config")
        .claim_profile
        .expect("claim profile")
        .mappings
}

/// Runs the config and returns the refusal message, panicking if it parsed.
/// Avoids `expect_err`, which would dump the whole `Config` on failure.
fn claims_error(mappings_yaml: &str, why: &str) -> String {
    match config_with_claims(mappings_yaml) {
        Ok(_) => panic!("{why}"),
        Err(e) => e,
    }
}

fn mapping<'a>(mappings: &'a [ClaimMapping], claim: &str) -> &'a ClaimMapping {
    mappings
        .iter()
        .find(|m| m.claim == claim)
        .unwrap_or_else(|| panic!("no mapping for claim `{claim}`"))
}

// ── Misspelled release gates ──────────────────────────────────────────────

/// A typo in `first_party_only` must not silently downgrade the gate to the
/// permissive default.
#[test]
fn misspelled_first_party_only_is_refused() {
    let err = claims_error(
        "        - claim: dept_code\n\
         \x20         source:\n\
         \x20           source: user_attribute\n\
         \x20           attribute: dept\n\
         \x20         first_party_onlyy: true\n",
        "a misspelled release gate must be refused, not discarded",
    );
    assert!(
        err.contains("first_party_onlyy"),
        "the error must name the unknown key so the operator can find the \
         typo; got: {err}"
    );
}

/// Same for the other two gates.
#[test]
fn misspelled_required_scopes_is_refused() {
    let err = claims_error(
        "        - claim: dept_code\n\
         \x20         source:\n\
         \x20           source: user_attribute\n\
         \x20           attribute: dept\n\
         \x20         required_scope:\n\
         \x20           - profile\n",
        "a misspelled required_scopes gate must be refused",
    );
    assert!(
        err.contains("required_scope"),
        "the error must name the unknown key; got: {err}"
    );
}

#[test]
fn misspelled_allowed_clients_is_refused() {
    let err = claims_error(
        "        - claim: dept_code\n\
         \x20         source:\n\
         \x20           source: user_attribute\n\
         \x20           attribute: dept\n\
         \x20         allowed_client:\n\
         \x20           - portal\n",
        "a misspelled allowed_clients gate must be refused",
    );
    assert!(
        err.contains("allowed_client"),
        "the error must name the unknown key; got: {err}"
    );
}

// ── Tier-3 default ────────────────────────────────────────────────────────

/// A custom (Tier 3) claim declared with no release gates defaults to
/// `first_party_only: true` — over-disclosure is opt-in.
#[test]
fn tier3_custom_claim_defaults_to_first_party_only() {
    let config = config_with_claims(
        "        - claim: dept_code\n\
         \x20         source:\n\
         \x20           source: user_attribute\n\
         \x20           attribute: dept\n",
    )
    .expect("a custom claim with no gates is a valid configuration");
    let mappings = effective_mappings(&config);
    assert!(
        mapping(&mappings, "dept_code").first_party_only,
        "a Tier-3 custom claim with no declared gates must default to \
         first_party_only: true (AUTHZ_EXPANSION.md § Safe defaults)"
    );
}

/// The default is a default, not a lock: an operator who writes
/// `first_party_only: false` gets what they asked for.
#[test]
fn explicit_first_party_only_false_is_honored() {
    let config = config_with_claims(
        "        - claim: dept_code\n\
         \x20         source:\n\
         \x20           source: user_attribute\n\
         \x20           attribute: dept\n\
         \x20         first_party_only: false\n",
    )
    .expect("an explicit opt-out is a valid configuration");
    let mappings = effective_mappings(&config);
    assert!(
        !mapping(&mappings, "dept_code").first_party_only,
        "an explicit first_party_only: false must be honored"
    );
}

/// Overriding a claim that the built-in profile already ships inherits that
/// mapping's gate rather than the Tier-3 default. `email` is released to
/// third-party clients by default; overriding its source must not silently
/// withdraw it.
#[test]
fn overriding_a_default_claim_inherits_its_gate() {
    let config = config_with_claims(
        "        - claim: email\n\
         \x20         source:\n\
         \x20           source: user_attribute\n\
         \x20           attribute: work_email\n",
    )
    .expect("overriding a default claim is a valid configuration");
    let mappings = effective_mappings(&config);
    assert!(
        !mapping(&mappings, "email").first_party_only,
        "overriding `email` must inherit the default mapping's \
         first_party_only: false, not pick up the Tier-3 default"
    );
}

/// The inheritance runs in the other direction too: `roles` is
/// `first_party_only: true` in the built-in profile, so an override that
/// declares no gate stays gated.
#[test]
fn overriding_roles_inherits_its_first_party_gate() {
    let config = config_with_claims(
        "        - claim: roles\n\
         \x20         source:\n\
         \x20           source: role_subset\n\
         \x20           prefix: \"app.\"\n",
    )
    .expect("overriding roles is a valid configuration");
    let mappings = effective_mappings(&config);
    assert!(
        mapping(&mappings, "roles").first_party_only,
        "overriding `roles` must inherit the default mapping's \
         first_party_only: true"
    );
}

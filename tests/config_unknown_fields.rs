//! Characterization tests for config drift — unknown / no-op YAML keys
//! (HEA-1836, Phase 2 gap #7).
//!
//! The top-level [`Config`] struct and its sections do **not** carry
//! `#[serde(deny_unknown_fields)]`, so any key an operator misspells, or any
//! documented-but-unimplemented key (`security.bearer_token`,
//! `security.password.pepper.*`, `auth.audit_log_retention`), is **silently
//! discarded** during deserialization. An operator who sets such a key
//! believes they have protected pepper material / the metrics scrape endpoint /
//! audit retention, when in fact the value is a no-op.
//!
//! These tests PIN the current (silent-ignore) behavior so the gap is explicit
//! and greppable. Whether these keys should instead be *rejected* (add
//! `deny_unknown_fields`) or *implemented* is a CTO / SecurityAuditor decision
//! (HEA-1766 report §Escalations). When that decision lands, whoever implements
//! it MUST update these assertions to match the chosen behavior — the test
//! failing is the signal that config-drift protection changed.

use hearth::config::Config;

/// A syntactically valid config with a completely bogus top-level key still
/// parses successfully; the unknown key is dropped rather than rejected.
#[test]
fn unknown_top_level_key_is_silently_ignored() {
    let yaml = r#"
dev_mode: true
server:
  bind_address: "127.0.0.1"
  port: 8420
this_key_does_not_exist: "operator typo"
"#;
    let cfg = Config::from_yaml_str(yaml)
        .expect("CHARACTERIZATION: unknown top-level keys are currently accepted, not rejected");
    // The real key next to the bogus one still applied.
    assert_eq!(cfg.server.port, 8420);
}

/// A misspelled key *inside* a real section is likewise dropped: the section
/// deserializes from its known fields and ignores the rest.
#[test]
fn unknown_nested_key_is_silently_ignored() {
    let yaml = r#"
dev_mode: true
server:
  bind_address: "127.0.0.1"
  port: 8420
  porrt: 9999          # typo for `port` — silently ignored
metrics:
  enabled: true
  bearer_tokn: "secret"  # typo for `bearer_token` — silently ignored
"#;
    let cfg = Config::from_yaml_str(yaml).expect(
        "CHARACTERIZATION: unknown nested keys are currently accepted; the typo'd `porrt` \
         and `bearer_tokn` are dropped, so `port` keeps its explicit value and \
         `metrics.bearer_token` stays unset",
    );
    assert_eq!(cfg.server.port, 8420, "the typo did not override the real port");
    assert!(
        cfg.metrics.bearer_token.is_none(),
        "the typo'd bearer_tokn was dropped — metrics scrape endpoint is UNPROTECTED despite \
         the operator believing they set a token",
    );
}

/// Documented-but-unimplemented keys called out in the audit are accepted with
/// no effect. This is the operator-dangerous case: the config *looks* like it
/// protects something but does nothing.
#[test]
fn documented_but_unimplemented_keys_are_no_ops() {
    let yaml = r#"
dev_mode: true
security:
  bearer_token: "believed-to-protect-metrics"
auth:
  audit_log_retention: "90d"
"#;
    // Currently accepted — no validation error, no observable effect.
    let cfg = Config::from_yaml_str(yaml).expect(
        "CHARACTERIZATION: documented-but-unimplemented keys are silently accepted as no-ops",
    );
    // `metrics.bearer_token` (the key that actually gates /metrics) remains
    // unset — proving `security.bearer_token` did NOT wire anything up.
    assert!(
        cfg.metrics.bearer_token.is_none(),
        "security.bearer_token is a no-op: the real metrics gate (metrics.bearer_token) is unset",
    );
}

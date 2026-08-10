//! Unknown config-key rejection tests (HEA-2113, decision D5).
//!
//! Every struct in `src/config/types.rs` carries `#[serde(deny_unknown_fields)]`.
//! Unknown or misspelled keys produce a hard parse error at startup rather than
//! being silently discarded. Operators get a clear message instead of believing
//! a mistyped or removed key did something.
//!
//! Phantom keys fixed in this PR:
//! - `auth.audit_log_retention` (documented in old guides, no backing field)
//! - `security.bearer_token` (wrong path; real gate is `metrics.bearer_token`)
//! - `security.password.pepper.active_version` (real field: `version`)
//! - `security.password.pepper.active_hex` (real field: `key_hex`)

use hearth::config::Config;

/// A completely bogus top-level key must be rejected with a parse error that
/// names the unknown field.
#[test]
fn unknown_top_level_key_is_rejected() {
    let yaml = r#"
dev_mode: true
server:
  bind_address: "127.0.0.1"
  port: 8420
this_key_does_not_exist: "operator typo"
"#;
    let err = Config::from_yaml_str(yaml).expect_err("unknown top-level key must be rejected");
    let display = format!("{err}");
    assert!(
        display.contains("this_key_does_not_exist"),
        "error must name the unknown field; got: {display}"
    );
}

/// A misspelled key inside a section must be rejected, not silently discarded.
#[test]
fn unknown_nested_key_is_rejected() {
    let yaml = r#"
dev_mode: true
server:
  bind_address: "127.0.0.1"
  port: 8420
  porrt: 9999
"#;
    let err =
        Config::from_yaml_str(yaml).expect_err("typo'd nested key must produce a parse error");
    let display = format!("{err}");
    assert!(
        display.contains("porrt"),
        "error must name the typo'd field; got: {display}"
    );
}

/// `auth.audit_log_retention` appears in older runbooks but has no backing
/// field in `AuthConfig`. It must be rejected on upgrade, not silently ignored.
#[test]
fn auth_audit_log_retention_is_rejected() {
    let yaml = r#"
dev_mode: true
auth:
  audit_log_retention: "90d"
"#;
    let err = Config::from_yaml_str(yaml)
        .expect_err("auth.audit_log_retention must be rejected — it is not implemented");
    let display = format!("{err}");
    assert!(
        display.contains("audit_log_retention"),
        "error must name the phantom field; got: {display}"
    );
}

/// `security.bearer_token` was documented as the metrics scrape token but is
/// NOT a field of `SecurityYaml`. The real path is `metrics.bearer_token`.
/// An operator following the old docs left `/metrics` unauthenticated while
/// believing it was protected.
#[test]
fn security_bearer_token_is_rejected() {
    let yaml = r#"
dev_mode: true
security:
  bearer_token: "believed-to-protect-metrics"
"#;
    let err = Config::from_yaml_str(yaml).expect_err(
        "security.bearer_token must be rejected — the real path is metrics.bearer_token",
    );
    let display = format!("{err}");
    assert!(
        display.contains("bearer_token"),
        "error must name the phantom field; got: {display}"
    );
}

/// `security.password.pepper.active_version` appears in old example YAML but
/// does NOT match any field of `PepperYaml`. The real field is `version`.
#[test]
fn pepper_active_version_is_rejected() {
    let yaml = r#"
dev_mode: true
security:
  password:
    pepper:
      active_version: 1
      key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    let err = Config::from_yaml_str(yaml)
        .expect_err("pepper.active_version must be rejected — the real field is `version`");
    let display = format!("{err}");
    assert!(
        display.contains("active_version"),
        "error must name the phantom field; got: {display}"
    );
}

/// `security.password.pepper.active_hex` appears in old example YAML but
/// does NOT match any field of `PepperYaml`. The real field is `key_hex`.
#[test]
fn pepper_active_hex_is_rejected() {
    let yaml = r#"
dev_mode: true
security:
  password:
    pepper:
      version: 1
      active_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    let err = Config::from_yaml_str(yaml)
        .expect_err("pepper.active_hex must be rejected — the real field is `key_hex`");
    let display = format!("{err}");
    assert!(
        display.contains("active_hex"),
        "error must name the phantom field; got: {display}"
    );
}

/// Verify that the correct pepper key names still parse cleanly (regression guard).
#[test]
fn correct_pepper_keys_are_accepted() {
    let yaml = r#"
dev_mode: true
security:
  password:
    pepper:
      version: 1
      key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    Config::from_yaml_str(yaml).expect("correct pepper key names must parse successfully");
}

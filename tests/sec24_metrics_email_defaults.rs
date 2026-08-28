//! Tests for HEA-SEC-24: metrics endpoint default and production email
//! transport enforcement.
//!
//! Covers:
//! - HSEC-005: `MetricsConfig::default()` has `enabled = false` (secure default).
//! - HSEC-010: `email.transport = log` in production with realms that require
//!   email delivery (magic_link auth or self-registration enabled) is a hard
//!   startup error.
//!
//! Each test validates via `Config::from_yaml_str` which runs `Config::validate()`
//! under the hood — the same code path that gates server startup.

// ── MetricsConfig defaults ────────────────────────────────────────────────────

/// HSEC-005 unit: `MetricsConfig::default()` must have `enabled = false`.
///
/// This enforces the "secure by default" invariant: the metrics scrape
/// endpoint is not exposed unless the operator explicitly opts in.
#[test]
fn metrics_default_is_disabled() {
    let cfg = hearth::config::MetricsConfig::default();
    assert!(
        !cfg.enabled,
        "MetricsConfig default must have enabled = false; got enabled = true"
    );
    assert!(
        cfg.bearer_token.is_none(),
        "MetricsConfig default must have bearer_token = None"
    );
}

// ── HSEC-010: email.transport = log in production with email-requiring realms ─

/// A minimal prod-mode YAML with a given realm auth block.
///
/// The base config satisfies all other production requirements so the only
/// validation failure, if any, comes from the email.transport check.
fn prod_config_yaml(realm_auth_snippet: &str) -> String {
    format!(
        r#"
server:
  port: 8420
  bind_address: "127.0.0.1"
  trust_forwarded_proto: true
storage:
  data_dir: "/tmp/hearth-sec24-test"
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
oidc:
  issuer: "https://auth.example.com"
email:
  transport: log
realms:
  testrealm:
    auth:
{realm_auth_snippet}
"#
    )
}

/// HSEC-010: `magic_link` in `allowed_auth_methods` + `log` transport in
/// production must produce a validation error that identifies `email.transport`.
#[test]
fn prod_log_transport_with_magic_link_is_error() {
    let yaml = prod_config_yaml("      allowed_auth_methods: [magic_link, password]");
    let result = hearth::config::Config::from_yaml_str(&yaml);
    let err = result.expect_err(
        "email.transport = log with magic_link in production must be a validation error",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("email.transport"),
        "error must identify the offending field 'email.transport'; got: {msg}"
    );
    assert!(
        msg.contains("magic_link") || msg.contains("email delivery"),
        "error must mention magic_link or email delivery; got: {msg}"
    );
}

/// HSEC-010: Self-registration `mode: open` + `log` transport in production
/// must produce a validation error that identifies `email.transport`.
#[test]
fn prod_log_transport_with_self_registration_open_is_error() {
    let yaml = prod_config_yaml("      registration:\n        mode: open");
    let result = hearth::config::Config::from_yaml_str(&yaml);
    let err = result.expect_err(
        "email.transport = log with open self-registration in production must be a validation error",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("email.transport"),
        "error must identify the offending field 'email.transport'; got: {msg}"
    );
}

/// HSEC-010: Self-registration `mode: domain_restricted` also requires email
/// delivery; must be a validation error with `log` transport in production.
#[test]
fn prod_log_transport_with_domain_restricted_reg_is_error() {
    let yaml = prod_config_yaml(
        "      registration:\n        mode: domain_restricted\n        allowed_domains: [example.com]",
    );
    let result = hearth::config::Config::from_yaml_str(&yaml);
    let err = result.expect_err(
        "email.transport = log with domain_restricted registration in production must be an error",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("email.transport"),
        "error must identify the offending field 'email.transport'; got: {msg}"
    );
}

/// HSEC-010: `log` transport in production with no email-requiring realm
/// features must NOT produce a validation error (warning only at runtime).
#[test]
fn prod_log_transport_without_email_features_is_ok() {
    let yaml = r#"
server:
  port: 8420
  bind_address: "127.0.0.1"
  trust_forwarded_proto: true
storage:
  data_dir: "/tmp/hearth-sec24-test"
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
oidc:
  issuer: "https://auth.example.com"
email:
  transport: log
realms:
  testrealm:
    auth:
      allowed_auth_methods: [password, passkey]
"#;
    let result = hearth::config::Config::from_yaml_str(yaml);
    assert!(
        result.is_ok(),
        "log transport without email-requiring features must be allowed; got: {:?}",
        result.err()
    );
}

/// HSEC-010: `log` transport in dev mode (even with magic_link configured)
/// must NOT be a validation error — dev-mode friction is a non-goal.
#[test]
fn dev_mode_log_transport_with_magic_link_is_ok() {
    let cfg = hearth::config::Config::dev();
    assert!(cfg.dev_mode, "Config::dev() must have dev_mode = true");
    assert!(
        cfg.validate().is_ok(),
        "dev mode config must pass validate() even with log transport"
    );
}

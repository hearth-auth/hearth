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

// ── branding / email.branding key round-trip guards (HEA-2155) ──────────────
//
// `BrandingConfig` carries `#[serde(deny_unknown_fields)]`. Any key added to
// the `branding:` docs without a matching struct field causes these tests to
// fail at parse time — the regression guard the acceptance criteria require.

/// All documented top-level `branding:` keys (product_name, logo_url, theme)
/// must parse successfully and round-trip their values (HEA-2155).
///
/// If a documented key is removed from `BrandingConfig`, the assertion on its
/// value fails. If an undocumented key is in the YAML, `deny_unknown_fields`
/// fails the parse before any assertion runs.
#[test]
fn branding_documented_keys_round_trip() {
    let yaml = r#"
dev_mode: true
branding:
  product_name: "Acme Auth"
  logo_url: "https://cdn.example.com/logo.svg"
  theme: ocean
"#;
    let cfg = Config::from_yaml_str(yaml)
        .expect("all documented branding keys must parse and validate without error");
    assert_eq!(
        cfg.branding.product_name.as_deref(),
        Some("Acme Auth"),
        "branding.product_name must be parsed"
    );
    assert_eq!(
        cfg.branding.logo_url.as_deref(),
        Some("https://cdn.example.com/logo.svg"),
        "branding.logo_url must be parsed"
    );
    assert_eq!(
        cfg.branding.theme.as_deref(),
        Some("ocean"),
        "branding.theme must be parsed"
    );
}

/// `branding.custom_css` is documented but requires a real file path for
/// validation to pass. This test proves the key is wired (not an unknown field)
/// by asserting the config rejects a non-existent path with a validation error,
/// not an unknown-field parse error (HEA-2155).
#[test]
fn branding_custom_css_key_is_wired() {
    let yaml = r#"
dev_mode: true
branding:
  custom_css: "/does/not/exist/brand.css"
"#;
    let err =
        Config::from_yaml_str(yaml).expect_err("non-existent custom_css path must fail validation");
    let display = format!("{err}");
    assert!(
        !display.contains("unknown field"),
        "error must be a file-not-found validation error, not an unknown-field parse error; got: {display}"
    );
    assert!(
        display.contains("custom_css"),
        "error must mention custom_css; got: {display}"
    );
}

/// A key that belongs under `email.branding:` must be rejected when placed
/// under the top-level `branding:` block. `BrandingConfig` carries
/// `deny_unknown_fields`, so the parse fails rather than silently discarding
/// the key (HEA-2155, HEA-2113).
#[test]
fn branding_phantom_key_is_rejected() {
    // `accent_color` is a valid `email.branding` field but does not exist in
    // `BrandingConfig`. An operator who copies it to the wrong section gets a
    // named hard error rather than a silent no-op.
    // NOTE: `r##"..."##` — a hex colour contains `"#`, which closes an `r#"..."#`
    // literal early and does not compile.
    let yaml = r##"
dev_mode: true
branding:
  accent_color: "#E85D04"
"##;
    let err = Config::from_yaml_str(yaml)
        .expect_err("branding.accent_color must be rejected — it belongs under email.branding");
    let display = format!("{err}");
    assert!(
        display.contains("accent_color"),
        "error must name the phantom field; got: {display}"
    );
}

/// All documented `email.branding:` keys (accent_color, support_email,
/// custom_footer_text) must parse and round-trip their values (HEA-2155).
///
/// Note: `EmailBranding` intentionally omits `deny_unknown_fields` to
/// support DB forward-compatibility. These assertions guard against key
/// removal: a field removed from the struct returns `None` and fails here.
#[test]
fn email_branding_documented_keys_round_trip() {
    // NOTE: `r##"..."##` — see `branding_phantom_key_is_rejected`.
    let yaml = r##"
dev_mode: true
email:
  branding:
    accent_color: "#4F46E5"
    support_email: "support@example.com"
    custom_footer_text: "2026 Acme Corp. All rights reserved."
"##;
    let cfg = Config::from_yaml_str(yaml)
        .expect("all documented email.branding keys must parse without error");
    let branding = cfg
        .email
        .branding
        .as_ref()
        .expect("email.branding must be present after parsing");
    assert_eq!(
        branding.accent_color.as_deref(),
        Some("#4F46E5"),
        "email.branding.accent_color must be parsed"
    );
    assert_eq!(
        branding.support_email.as_deref(),
        Some("support@example.com"),
        "email.branding.support_email must be parsed"
    );
    assert_eq!(
        branding.custom_footer_text.as_deref(),
        Some("2026 Acme Corp. All rights reserved."),
        "email.branding.custom_footer_text must be parsed"
    );
}

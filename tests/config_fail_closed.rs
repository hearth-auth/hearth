//! Fail-closed configuration semantics (audit 2026-08-28 §4.11, §4.13, §1A).
//!
//! Covers, in order:
//!
//! * **20.5** — a `${VAR}` reference to an unset environment variable must not
//!   silently become the empty string and then be accepted as a credential.
//! * **20.6** — an absent `security:` block must not zero the per-field
//!   `#[serde(default = "fn")]` values (class guard for the whole config tree).
//! * **20.8** — the `0` sentinel means "unlimited" for every request limiter.
//! * **20.4** — `storage.fsync` is a working knob, not an ignored one.
//! * **20.9** — `hearth config validate` and the server share one validator.
//! * **20.17** — every parsed `security.*` key reaches a live consumer.

use hearth::config::Config;

/// Builds a *production* config YAML whose only defect is the one under test.
///
/// `storage_extra` / `security_extra` / `tail` are appended inside the matching
/// block so the result never repeats a top-level key (YAML rejects duplicates).
fn prod_yaml(storage_extra: &str, security_extra: &str, tail: &str) -> String {
    format!(
        "server:\n  trust_forwarded_proto: true\n\
         storage:\n  data_dir: \"/tmp/hearth-config-fail-closed\"\n{storage_extra}\
         security:\n  key_encryption_key: \"\
         1111111111111111111111111111111111111111111111111111111111111111\"\n{security_extra}\
         oidc:\n  issuer: \"https://auth.example.test\"\n\
         {tail}"
    )
}

/// Runs `f` with `key` guaranteed absent from the environment.
///
/// The env is process-global; nextest runs one process per test binary, and
/// these tests use distinct variable names so they cannot collide.
fn with_unset_var<T>(key: &str, f: impl FnOnce() -> T) -> T {
    std::env::remove_var(key);
    f()
}

// ─────────────────────────────────────────────────────────────────────────────
// 20.5 — an unset ${VAR} must not become an accepted empty credential
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unset_env_var_in_metrics_bearer_token_is_refused() {
    // `${HEARTH_TEST_UNSET_METRICS_TOKEN}` is not set, so substitution yields
    // `metrics.bearer_token: ""`. The /metrics guard compares the supplied
    // Bearer value against that empty expectation with a constant-time equal,
    // and a request with NO Authorization header at all supplies `""` — so the
    // scrape endpoint is wide open while the operator believes it is bearer
    // protected (audit §4.13#4).
    let yaml = prod_yaml(
        "",
        "",
        "metrics:\n  enabled: true\n  bearer_token: \"${HEARTH_TEST_UNSET_METRICS_TOKEN}\"\n",
    );
    let err = with_unset_var("HEARTH_TEST_UNSET_METRICS_TOKEN", || {
        Config::from_yaml_str(&yaml)
    })
    .expect_err("an unset ${VAR} that becomes an empty credential must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("HEARTH_TEST_UNSET_METRICS_TOKEN"),
        "the error must name the variable that was not set; got: {msg}"
    );
}

#[test]
fn unset_env_var_in_client_secret_is_refused() {
    // Same mechanism on a confidential OAuth client: `client_secret` becomes
    // `Some("")`, the `is_none()` validator is satisfied, and the client then
    // authenticates with `Authorization: Basic base64("<client_id>:")`.
    let yaml = prod_yaml(
        "",
        "",
        r#"email:
  transport: smtp
  from: "noreply@example.test"
  smtp:
    host: "smtp.example.test"
    port: 587
realms:
  acme:
    applications:
      portal:
        name: "portal"
        redirect_uris:
          - "https://portal.example.test/callback"
        confidential: true
        client_secret: "${HEARTH_TEST_UNSET_CLIENT_SECRET}"
"#,
    );
    let err = with_unset_var("HEARTH_TEST_UNSET_CLIENT_SECRET", || {
        Config::from_yaml_str(&yaml)
    })
    .expect_err("an unset ${VAR} used as a client secret must be refused");
    assert!(
        err.to_string().contains("HEARTH_TEST_UNSET_CLIENT_SECRET"),
        "the error must name the unset variable; got: {err}"
    );
}

#[test]
fn explicit_empty_default_opts_out_of_the_fail_closed_rule() {
    // `${VAR:-}` is the documented way to say "empty is intentional". It emits
    // no warning and must keep parsing, otherwise the escape hatch is gone.
    let yaml = prod_yaml(
        "",
        "  allowed_hosts:\n    - \"${HEARTH_TEST_UNSET_HOST:-example.test}\"\n",
        "",
    );
    let cfg = with_unset_var("HEARTH_TEST_UNSET_HOST", || {
        Config::from_yaml_str_unchecked(&yaml)
    })
    .expect("a ${VAR:-default} reference must still parse");
    assert_eq!(cfg.security.allowed_hosts, vec!["example.test".to_string()]);
}

#[test]
fn a_literal_empty_client_secret_is_refused_too() {
    // The env path is only one way to reach an empty credential; a literal
    // `client_secret: ""` must fail for the same reason.
    let yaml = prod_yaml(
        "",
        "",
        r#"email:
  transport: smtp
  from: "noreply@example.test"
  smtp:
    host: "smtp.example.test"
    port: 587
realms:
  acme:
    applications:
      portal:
        name: "portal"
        redirect_uris:
          - "https://portal.example.test/callback"
        confidential: true
        client_secret: ""
"#,
    );
    let err = Config::from_yaml_str(&yaml)
        .expect_err("an empty client_secret on a confidential client must be refused");
    assert!(
        err.to_string().contains("client_secret"),
        "the error must name the field; got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 20.6 — an absent `security:` block keeps the documented defaults
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn absent_security_block_keeps_the_abuse_controls_armed() {
    let cfg = Config::from_yaml_str_unchecked("storage:\n  data_dir: \"/tmp/hea-20-6\"\n")
        .expect("a config with no security: block parses");
    assert!(
        cfg.security.reserved_slugs.iter().any(|s| s == "admin"),
        "an absent security: block must not empty reserved_slugs"
    );
    assert_eq!(
        cfg.security.slug_cooldown_days, 30,
        "an absent security: block must not zero slug_cooldown_days"
    );
    assert_eq!(
        cfg.security.jwks_rps_limit, 60,
        "an absent security: block must not zero jwks_rps_limit"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 20.4 — storage.fsync is a working knob
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fsync_false_is_refused_in_production() {
    // Previously `storage.fsync: false` produced a warn line and was then
    // ignored: production always built `SyncMode::EveryWrite`. A knob that
    // silently does nothing is worse than no knob — refuse it.
    let yaml = prod_yaml("  fsync: false\n", "", "");
    let err = Config::from_yaml_str(&yaml)
        .expect_err("storage.fsync: false must be refused outside dev mode");
    assert!(
        err.to_string().contains("storage.fsync"),
        "the error must name storage.fsync; got: {err}"
    );
}

#[test]
fn fsync_resolves_per_mode_and_honours_an_explicit_dev_override() {
    // Absent  → mode default (prod: on, dev: off).
    // Present → honoured, so a dev run can exercise the real fsync path.
    let cfg = Config::from_yaml_str_unchecked("storage:\n  data_dir: \"/tmp/hea-20-4\"\n")
        .expect("parses");
    assert!(
        cfg.storage.fsync_enabled(false),
        "production defaults to fsync on"
    );
    assert!(
        !cfg.storage.fsync_enabled(true),
        "dev defaults to fsync off"
    );

    let cfg = Config::from_yaml_str_unchecked(
        "dev_mode: true\nstorage:\n  data_dir: \"/tmp/hea-20-4\"\n  fsync: true\n",
    )
    .expect("parses");
    assert!(
        cfg.storage.fsync_enabled(true),
        "an explicit storage.fsync: true must be honoured in dev mode, not overwritten"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 20.9 — one validator behind both `hearth config validate` and the server
// ─────────────────────────────────────────────────────────────────────────────

/// The all-collecting validator behind `hearth config validate` and the admin
/// config editor must report the same defects the server refuses to start with.
///
/// `validate()` now delegates to `validate_all()`, so this asserts the *rules*
/// reached `validate_all` rather than comparing the two functions to each other
/// — comparing them would pass vacuously.
#[test]
fn the_cli_validator_reports_the_rules_only_the_server_used_to_enforce() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "kdf bound of zero",
            "  password:\n    kdf:\n      max_in_flight: 0\n",
            "security.password.kdf.max_in_flight",
        ),
        (
            "malformed pepper key",
            "  password:\n    pepper:\n      version: 1\n      key_hex: \"nothex\"\n",
            "security.password.pepper.key_hex",
        ),
        (
            "zero admin kdf bound",
            "  password:\n    kdf:\n      admin_max_in_flight: 0\n",
            "security.password.kdf.admin_max_in_flight",
        ),
    ];

    for (label, fragment, expected_field) in cases {
        let yaml = prod_yaml("", fragment, "");
        let cfg = Config::from_yaml_str_unchecked(&yaml)
            .unwrap_or_else(|e| panic!("{label}: unchecked parse must succeed: {e}"));
        let issues = cfg.validate_all();
        assert!(
            issues.iter().any(|i| i.field == *expected_field),
            "{label}: `hearth config validate` (and the admin config editor, which writes \
             hearth.yaml through the same validator) reported nothing for {expected_field}, \
             a config the server refuses to start with; got {issues:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 20.17 — every parsed security key reaches a live consumer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_security_key_with_no_consumer_is_refused_at_startup() {
    // `security.http2.*` was the audit's example: it parsed, validated, landed
    // in the config struct, and nothing read it. Task 22.12 has since wired it,
    // so the registry now holds no dead keys and the unwired arm is exercised
    // by a unit test against a synthetic registry instead.
    //
    // What remains reachable from outside the crate is the other half of the
    // same fail-closed rule: a key written under `security:` that the registry
    // does not know at all. That is the shape a newly added field takes before
    // anybody registers a consumer for it, so it guards the same defect.
    let yaml = prod_yaml("", "  totally_made_up_control: true\n", "");
    let issues = hearth::config::security_key_liveness_issues(&yaml);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "security.totally_made_up_control"),
        "a security key with no registered consumer must be reported; got {issues:?}"
    );

    // …and the whole config is refused, not merely annotated.
    let err = Config::from_yaml_str(&yaml)
        .expect_err("a config setting an unconsumed security key must not boot");
    assert!(
        err.to_string().contains("totally_made_up_control"),
        "the start-up error must name the offending key; got: {err}"
    );
}

#[test]
fn every_registered_security_key_is_reachable_from_yaml() {
    // The registry is only useful if it matches the struct. Every leaf key an
    // operator can actually write under `security:` must be registered, and
    // every registered path must still parse — a renamed field must break this
    // test rather than quietly stop being checked.
    for path in hearth::config::registered_security_key_paths() {
        assert!(
            path.starts_with("security."),
            "registry paths are absolute from the config root; got {path}"
        );
        assert!(
            !path.ends_with('.') && !path.contains(".."),
            "malformed registry path: {path}"
        );
    }
    assert!(
        hearth::config::registered_security_key_paths().count() >= 40,
        "the registry lost entries — every security leaf key must stay registered"
    );
}

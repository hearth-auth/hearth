//! HEA-2166: production misconfigurations must fail CLOSED at startup.
//!
//! Three paths previously degraded silently to insecure outside dev mode:
//!
//! 1. Missing key-encryption key → realm signing keys stored in plaintext,
//!    with no operator signal.
//! 2. No TLS and no trusted proxy → session cookies issued without the
//!    `Secure` attribute, with only a log line as the "control".
//! 3. `demo.enabled: true` → mass-seeded accounts sharing the publicly
//!    documented default password, permitted in production.
//!
//! Each must now be a hard validation error outside dev mode, while `--dev`
//! retains the permissive developer loop.

use hearth::config::Config;

/// Production-mode base config that satisfies every OTHER validation rule,
/// including the three HEA-2166 gates (KEK present, TLS terminated at a
/// trusted proxy, demo off). Each test strips or flips exactly one of the
/// three so the only possible failure is the gate under test.
fn prod_yaml(kek: bool, trust_forwarded_proto: bool, demo_enabled: bool) -> String {
    let mut yaml = format!(
        r#"
server:
  port: 8420
  bind_address: "127.0.0.1"
  trust_forwarded_proto: {trust_forwarded_proto}
storage:
  data_dir: "/tmp/hearth-hea2166-test"
oidc:
  issuer: "https://auth.example.com"
email:
  transport: log
"#,
    );
    if kek {
        yaml.push_str(
            "security:\n  key_encryption_key: \
             \"1111111111111111111111111111111111111111111111111111111111111111\"\n",
        );
    }
    if demo_enabled {
        yaml.push_str("demo:\n  enabled: true\n");
    }
    yaml
}

/// Case 1 — missing KEK. Without `security.key_encryption_key` (and with
/// `HEARTH_KEK` unset) a production config previously validated cleanly and
/// the server silently stored private keys in plaintext.
#[test]
fn prod_missing_kek_is_a_hard_validation_error() {
    // nextest runs one process per test, so mutating the environment is safe.
    std::env::remove_var("HEARTH_KEK");
    let yaml = prod_yaml(false, true, false);
    let err = Config::from_yaml_str(&yaml)
        .expect_err("production config without a key-encryption key must refuse to start");
    let msg = err.to_string();
    assert!(
        msg.contains("security.key_encryption_key"),
        "error must identify the offending field; got: {msg}"
    );
    assert!(
        msg.contains("HEARTH_KEK"),
        "error must name the env-var fix; got: {msg}"
    );
    assert!(
        msg.contains("plaintext"),
        "error must state the consequence (plaintext key storage); got: {msg}"
    );
}

/// Case 1 counter — a KEK supplied via the `HEARTH_KEK` env var (the
/// recommended deployment shape, keeping secrets out of YAML) must satisfy
/// the gate even when the YAML key is absent.
#[test]
fn prod_kek_via_env_var_passes_validation() {
    std::env::set_var(
        "HEARTH_KEK",
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    let yaml = prod_yaml(false, true, false);
    let result = Config::from_yaml_str(&yaml);
    std::env::remove_var("HEARTH_KEK");
    result.expect("HEARTH_KEK env var alone must satisfy the production KEK requirement");
}

/// Case 2 — no TLS, no trusted proxy. Previously an `error!` log line and the
/// server carried on issuing session cookies without the `Secure` attribute.
#[test]
fn prod_no_tls_and_no_trusted_proxy_is_a_hard_validation_error() {
    std::env::remove_var("HEARTH_KEK");
    let yaml = prod_yaml(true, false, false);
    let err = Config::from_yaml_str(&yaml).expect_err(
        "production config with neither TLS nor trust_forwarded_proto must refuse to start",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("server.tls_cert_path"),
        "error must name the direct-TLS fix; got: {msg}"
    );
    assert!(
        msg.contains("trust_forwarded_proto"),
        "error must name the reverse-proxy fix; got: {msg}"
    );
    assert!(
        msg.contains("Secure"),
        "error must state the consequence (cookies without Secure); got: {msg}"
    );
}

/// Case 3 — `demo.enabled` in production. Previously ungated: the mass seeder
/// ran with the hardcoded, publicly documented default password.
#[test]
fn prod_demo_enabled_is_a_hard_validation_error() {
    std::env::remove_var("HEARTH_KEK");
    let yaml = prod_yaml(true, true, true);
    let err = Config::from_yaml_str(&yaml)
        .expect_err("demo.enabled = true outside dev mode must refuse to start");
    let msg = err.to_string();
    assert!(
        msg.contains("demo.enabled"),
        "error must identify the offending field; got: {msg}"
    );
    assert!(
        msg.contains("dev"),
        "error must point the operator at dev mode; got: {msg}"
    );
}

/// Case 4 — `hearth serve` with no config file previously booted a production
/// server from compiled-in defaults without ever calling `validate()`,
/// bypassing every gate above. The defaults must route through the same
/// fail-closed checks as a config file.
#[test]
fn bare_serve_without_config_refuses_to_start_in_prod() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = std::process::Command::new(hearth_bin())
        .arg("serve")
        .current_dir(dir.path())
        .env_remove("HEARTH_KEK")
        .output()
        .expect("spawn hearth serve");
    assert!(
        !output.status.success(),
        "bare `hearth serve` (no config, no --dev) must refuse to start"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("security.key_encryption_key"),
        "startup error must name the first failed gate; got: {combined}"
    );
}

/// Returns the path to the compiled `hearth` binary (nextest layout).
fn hearth_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe()
        .expect("current exe")
        .parent()
        .expect("parent dir")
        .parent()
        .expect("grandparent dir")
        .to_path_buf();
    path.push("hearth");
    path
}

/// Dev mode keeps today's permissive behaviour for all three: no KEK, no TLS,
/// demo seeding on — the developer loop is unaffected.
#[test]
fn dev_mode_retains_permissive_behaviour_for_all_three() {
    std::env::remove_var("HEARTH_KEK");
    let yaml = "dev_mode: true\ndemo:\n  enabled: true\n";
    Config::from_yaml_str(yaml)
        .expect("dev mode must allow missing KEK, missing TLS, and demo.enabled");
}

/// The admin config-check panel (`validate_all`) must surface all three gates
/// as issues in one pass, mirroring the fail-fast `validate` errors.
#[test]
fn validate_all_surfaces_all_three_gates() {
    std::env::remove_var("HEARTH_KEK");
    let yaml = prod_yaml(false, false, true);
    let config =
        Config::from_yaml_str_unchecked(&yaml).expect("config must parse without validation");
    let issues = config.validate_all();
    let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
    assert!(
        fields.contains(&"security.key_encryption_key"),
        "validate_all must flag the missing KEK; got fields: {fields:?}"
    );
    assert!(
        fields.contains(&"server.tls_cert_path"),
        "validate_all must flag missing TLS; got fields: {fields:?}"
    );
    assert!(
        fields.contains(&"demo.enabled"),
        "validate_all must flag demo mode; got fields: {fields:?}"
    );
}

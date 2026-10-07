//! CLI integration tests for `hearth config validate` and `hearth config example`.
//!
//! Spawns the compiled binary as a child process and verifies exit codes,
//! stdout/stderr content, and output validity.
//!
//! Covers TEST_SCENARIOS: hearth config validate / hearth config example

use std::process::Command;

/// Returns the path to the compiled `hearth` binary.
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

// === hearth config validate ===

/// A minimal valid production config (data_dir prevents the empty-dir error;
/// the KEK and trust_forwarded_proto satisfy the HEA-2166 fail-closed gates;
/// a real email transport satisfies the GA-audit M15 gate).
const VALID_CONFIG: &str = r#"
server:
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1"]
storage:
  data_dir: "/tmp/hearth-test"
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
oidc:
  issuer: "https://auth.example.com"
email:
  transport: smtp
  from: "auth@example.com"
  smtp:
    host: "mail.example.com"
    port: 587
"#;

/// Config with an invalid field (empty data_dir triggers a validation error).
const INVALID_CONFIG_EMPTY_DATA_DIR: &str = r#"
storage:
  data_dir: ""
"#;

/// Config with a bad SMTP block — missing smtp section when transport = smtp.
const INVALID_CONFIG_SMTP_MISSING_BLOCK: &str = r#"
storage:
  data_dir: "/tmp/hearth-test"
oidc:
  issuer: "https://auth.example.com"
email:
  transport: smtp
  from: "auth@example.com"
"#;

#[test]
fn validate_returns_0_for_valid_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, VALID_CONFIG).expect("write config");

    let status = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth");

    assert!(
        status.success(),
        "hearth config validate should exit 0 for a valid config"
    );
}

#[test]
fn validate_prints_summary_on_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, VALID_CONFIG).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Configuration valid"),
        "stdout should contain 'Configuration valid', got: {stdout}"
    );
    assert!(
        stdout.contains("storage:") || stdout.contains("/tmp/hearth-test"),
        "stdout should include storage path summary, got: {stdout}"
    );
    assert!(
        stdout.contains("email transport:"),
        "stdout should include email transport, got: {stdout}"
    );
    assert!(
        stdout.contains("TLS:"),
        "stdout should include TLS mode, got: {stdout}"
    );
}

#[test]
fn validate_returns_1_for_empty_data_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, INVALID_CONFIG_EMPTY_DATA_DIR).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    assert!(
        !output.status.success(),
        "hearth config validate should exit 1 for invalid config"
    );
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("storage.data_dir"),
        "stderr should mention the invalid field, got: {stderr}"
    );
}

#[test]
fn validate_returns_1_for_missing_smtp_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, INVALID_CONFIG_SMTP_MISSING_BLOCK).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    assert!(
        !output.status.success(),
        "hearth config validate should exit 1 for smtp without smtp block"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("email.smtp"),
        "stderr should mention email.smtp, got: {stderr}"
    );
}

#[test]
fn validate_returns_1_for_bad_yaml_syntax() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, "server:\n  port: [unclosed").expect("write config");

    let status = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth");

    assert_eq!(status.code(), Some(1), "bad YAML should exit 1");
}

#[test]
fn validate_returns_1_for_nonexistent_file() {
    let status = Command::new(hearth_bin())
        .args(["config", "validate", "/nonexistent/hearth.yaml"])
        .status()
        .expect("spawn hearth");

    assert_eq!(status.code(), Some(1));
}

#[test]
fn validate_prints_parse_error_for_bad_yaml_syntax() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, "server:\n  port: [unclosed").expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    // HEA-2011: the parse-error branch reported via `tracing::error!`, but no
    // subscriber is installed for the `config` subcommand — the operator saw an
    // exit code and nothing else.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("parse error"),
        "bad YAML should print a parse error to stderr, got: {stderr}"
    );
}

// === hearth serve — startup diagnostics (HEA-2011) ===

/// Production config that is missing `oidc.issuer`, which `serve` (without
/// `--dev`) rejects during config validation — i.e. before tracing is up.
const SERVE_CONFIG_MISSING_ISSUER: &str = r#"
storage:
  data_dir: "/tmp/hearth-test-hea2011"
"#;

/// HEA-2011: `hearth serve` must not exit 1 in total silence when config
/// validation fails.
///
/// The config load happens before `telemetry::init`, so the `tracing::error!`
/// on that path wrote the diagnostic nowhere. An operator following the
/// HEA-1997 saturation runbook §3B saw a server that died with no output at
/// all, while `hearth config validate` on the same file printed a perfect
/// field-level report.
#[test]
fn serve_prints_field_level_diagnostic_when_config_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, SERVE_CONFIG_MISSING_ISSUER).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "serve",
            "-c",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth serve");

    assert_eq!(
        output.status.code(),
        Some(1),
        "serve should exit 1 on invalid config"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("oidc.issuer"),
        "serve must name the offending config field on stderr, got: {stderr:?}"
    );
    assert!(
        stderr.contains("Configuration invalid"),
        "serve should print the same field-level report as `config validate`, got: {stderr:?}"
    );
}

// === GA audit 3 round 3: federation PEMs are checked by `config validate` ===

/// `VALID_CONFIG` plus a realm `acme` with a SAML connector `corp` whose
/// `idp_certificate_pem` is `pem`.
fn config_with_saml_idp_certificate(pem: &str) -> String {
    format!(
        concat!(
            "{base}realms:\n",
            "  acme:\n",
            "    federation:\n",
            "      providers:\n",
            "        corp:\n",
            "          type: saml\n",
            "          entity_id: \"https://idp.corp.example\"\n",
            "          sso_url: \"https://idp.corp.example/sso\"\n",
            "          idp_certificate_pem: {pem:?}\n",
        ),
        base = VALID_CONFIG,
        pem = pem,
    )
}

fn certificate_pem(name: &str) -> String {
    use base64::Engine as _;
    let key = hearth::identity::tokens::RsaSigningKey::generate(name, 365).expect("key");
    let b64 = base64::engine::general_purpose::STANDARD.encode(key.cert_der());
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn run_validate(config: &str) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, config).expect("write config");
    Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth")
}

/// An unusable SAML IdP certificate fails `config validate`, naming the
/// field, the realm and the connector — not the first federated login.
#[test]
fn validate_returns_1_for_an_unusable_saml_idp_certificate() {
    let output = run_validate(&config_with_saml_idp_certificate(
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
    ));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("realms.acme.federation.providers.corp.idp_certificate_pem"),
        "the report must name the field: {stderr}"
    );
    assert!(
        stderr.contains("'corp'") && stderr.contains("'acme'"),
        "the report must name the IdP and the realm: {stderr}"
    );
}

/// Control and rollover shape: two concatenated certificates validate.
#[test]
fn validate_accepts_a_saml_idp_certificate_bundle() {
    let bundle = format!("{}{}", certificate_pem("old"), certificate_pem("new"));
    let output = run_validate(&config_with_saml_idp_certificate(&bundle));
    assert!(
        output.status.success(),
        "a two-certificate bundle must validate; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `VALID_CONFIG` with a cluster section whose `peer_address` is `addr`.
fn config_with_peer_address(addr: &str) -> String {
    format!(
        "{VALID_CONFIG}cluster:\n  node_id: 1\n  peer_address: \"{addr}\"\n  peers:\n    \
         - id: 2\n      address: \"hearth-2.internal:8421\"\n  \
         tls_cert_path: \"/etc/hearth/peer.crt\"\n  \
         tls_key_path: \"/etc/hearth/peer.key\"\n  \
         tls_ca_cert_path: \"/etc/hearth/ca.crt\"\n"
    )
}

/// The peer server binds `cluster.peer_address`. A host name used to pass
/// `config validate`, and then the node served without its peer server.
#[test]
fn validate_returns_1_for_a_host_name_peer_address() {
    let output = run_validate(&config_with_peer_address("hearth-1.internal:8421"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("cluster.peer_address") && stderr.contains("'hearth-1.internal:8421'"),
        "the report must name the field and the value: {stderr}"
    );
}

/// Control: an IP address and port validate, and a peer's `address` may
/// still be a host name (it is dialled, not bound).
#[test]
fn validate_accepts_an_ip_peer_address() {
    let output = run_validate(&config_with_peer_address("10.0.0.1:8421"));
    assert!(
        output.status.success(),
        "an IP peer_address must validate; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// === hearth config example ===

#[test]
fn example_output_is_valid_yaml() {
    let output = Command::new(hearth_bin())
        .args(["config", "example"])
        .output()
        .expect("spawn hearth");

    assert!(
        output.status.success(),
        "hearth config example should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "hearth config example should produce output"
    );

    // The example YAML must parse successfully.
    let parsed: serde_norway::Value =
        serde_norway::from_str(&stdout).expect("example output must be valid YAML");
    assert!(
        parsed.is_mapping(),
        "example YAML root must be a mapping, got: {parsed:?}"
    );
}

#[test]
fn example_output_contains_key_sections() {
    let output = Command::new(hearth_bin())
        .args(["config", "example"])
        .output()
        .expect("spawn hearth");

    let stdout = String::from_utf8_lossy(&output.stdout);

    for section in &["server:", "storage:", "observability:", "email:"] {
        assert!(
            stdout.contains(section),
            "example YAML should contain section '{section}'"
        );
    }
}

#[test]
fn example_output_file_option_writes_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("hearth.yaml");

    let status = Command::new(hearth_bin())
        .args([
            "config",
            "example",
            "--output",
            out_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth");

    assert!(
        status.success(),
        "hearth config example --output should exit 0"
    );

    let content = std::fs::read_to_string(&out_path).expect("output file should exist");
    assert!(!content.is_empty(), "output file should not be empty");

    // The written file must also parse as valid YAML.
    serde_norway::from_str::<serde_norway::Value>(&content)
        .expect("written example must be valid YAML");
}

/// HEA-2166: the generated example is a *starting point*, not a production
/// config. `config validate` applies production rules, so the example must
/// FAIL until the operator supplies a key-encryption key and TLS — and the
/// report must name each gap with its remediation. A silently-valid example
/// is how plaintext-key deployments happened in the first place.
#[test]
fn example_written_config_fails_validate_naming_production_gaps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");

    // Generate the example
    Command::new(hearth_bin())
        .args([
            "config",
            "example",
            "--output",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth for example");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .env_remove("HEARTH_KEK")
        .output()
        .expect("spawn hearth for validate");

    assert!(
        !output.status.success(),
        "the out-of-the-box example must not validate as a production config"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("security.key_encryption_key") && stderr.contains("HEARTH_KEK"),
        "report must name the missing KEK and the env-var fix; got: {stderr}"
    );
    assert!(
        stderr.contains("server.tls_cert_path") && stderr.contains("trust_forwarded_proto"),
        "report must name both TLS remediations; got: {stderr}"
    );
}

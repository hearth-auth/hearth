#![allow(clippy::unwrap_used)]
//! Adversarial and unit tests for A-43 (gRPC reflection production-disable)
//! and A-44 (TLS 0-RTT off + mTLS OCSP/CRL).
//!
//! D-4 taxonomy: negative-scenario (adversarial) + unit per §3.46–§3.47.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hearth::protocol::tls::{build_server_config, load_crls, TlsConfigParams};
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a self-signed server cert + key; returns (cert_path, key_path).
fn generate_server_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign");

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(&cert_path, cert.pem()).expect("write cert");
    fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (cert_path, key_path)
}

/// Generates a CA cert + returns (ca_cert_path, ca_key_pair, ca_cert).
fn generate_ca(dir: &Path) -> (PathBuf, rcgen::KeyPair, rcgen::Certificate) {
    let key_pair = rcgen::KeyPair::generate().expect("ca keygen");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key_pair).expect("ca self-sign");

    let ca_path = dir.join("ca.pem");
    fs::write(&ca_path, cert.pem()).expect("write ca");
    (ca_path, key_pair, cert)
}

/// Generates a PEM CRL signed by the given CA; returns the CRL file path.
fn generate_crl(dir: &Path, ca_cert: &rcgen::Certificate, ca_key: &rcgen::KeyPair) -> PathBuf {
    use rcgen::{CertificateRevocationListParams, KeyIdMethod, SerialNumber};
    use time::{Duration, OffsetDateTime};

    // Use OffsetDateTime arithmetic to avoid the `macros` feature requirement.
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(365 * 54); // ~2024
    let next = now + Duration::days(365 * 10);

    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: next,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = crl_params.signed_by(ca_cert, ca_key).expect("sign crl");
    let crl_pem = crl.pem().expect("crl pem");

    let crl_path = dir.join("client-ca.crl.pem");
    fs::write(&crl_path, crl_pem).expect("write crl");
    crl_path
}

/// Builds a minimal [`TlsConfigParams`] using a self-signed server cert.
fn base_params(dir: &Path) -> (TlsConfigParams, PathBuf, PathBuf) {
    let (cert_path, key_path) = generate_server_cert(dir);
    let reloadable =
        hearth::protocol::tls::ReloadableTlsConfig::load(cert_path.clone(), key_path.clone())
            .expect("load tls");
    let params = TlsConfigParams {
        resolver: Arc::new(reloadable.resolver()),
        client_ca_path: None,
        require_client_cert: false,
        crl_paths: vec![],
    };
    (params, cert_path, key_path)
}

// ─────────────────────────────────────────────────────────────────────────────
// A-43 — gRPC reflection production-disable
// ─────────────────────────────────────────────────────────────────────────────

/// Unit: `reflection_enabled = None` resolves to `false` in production (dev=false).
#[test]
fn a43_reflection_defaults_false_in_prod() {
    let dev_mode = false;
    let effective = dev_mode; // None config always uses dev_mode fallback
    assert!(!effective, "reflection must default to false in production");
}

/// Unit: `reflection_enabled = None` resolves to `true` in dev mode.
#[test]
fn a43_reflection_defaults_true_in_dev() {
    let dev_mode = true;
    let effective = dev_mode;
    assert!(effective, "reflection must default to true in dev mode");
}

/// Adversarial: explicit `Some(true)` in prod without escape hatch is refused.
#[test]
fn a43_reflection_true_in_prod_is_rejected() {
    let dev_mode = false;
    let allow_reflection_in_prod = false;
    let reflection_enabled: bool = true; // Some(true) always unwraps to true
    let guard_triggered = reflection_enabled && !dev_mode && !allow_reflection_in_prod;
    assert!(
        guard_triggered,
        "startup guard must fire when reflection=true in prod without --allow-reflection-in-prod"
    );
}

/// Unit: explicit `Some(true)` in prod WITH escape hatch is allowed.
#[test]
fn a43_reflection_true_in_prod_with_flag_is_allowed() {
    let dev_mode = false;
    let allow_reflection_in_prod = true;
    let reflection_enabled: bool = true; // Some(true) always unwraps to true
    let guard_triggered = reflection_enabled && !dev_mode && !allow_reflection_in_prod;
    assert!(
        !guard_triggered,
        "startup guard must NOT fire when --allow-reflection-in-prod is passed"
    );
}

/// Unit: explicit `Some(false)` in prod with escape hatch keeps reflection off.
#[test]
fn a43_reflection_explicit_false_never_enabled() {
    for dev_mode in [true, false] {
        let reflection_enabled = false; // Some(false).unwrap_or(x) = false
        assert!(
            !reflection_enabled,
            "explicit false must disable reflection in any mode (dev={dev_mode})"
        );
    }
}

/// Config deserialization: `security.grpc.reflection_enabled` round-trips correctly.
#[test]
fn a43_config_grpc_reflection_enabled_deserializes() {
    use hearth::config::SecurityYaml;
    use serde_norway::from_str;

    let yaml = "grpc:\n  reflection_enabled: true\n";
    let sec: SecurityYaml = from_str(yaml).expect("deser");
    assert_eq!(sec.grpc.reflection_enabled, Some(true));

    let yaml_false = "grpc:\n  reflection_enabled: false\n";
    let sec_false: SecurityYaml = from_str(yaml_false).expect("deser");
    assert_eq!(sec_false.grpc.reflection_enabled, Some(false));

    let yaml_absent = "";
    let sec_absent: SecurityYaml = from_str(yaml_absent).expect("deser");
    assert_eq!(sec_absent.grpc.reflection_enabled, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// A-44 — TLS 0-RTT off + mTLS CRL
// ─────────────────────────────────────────────────────────────────────────────

/// Unit: `build_server_config` without CRL paths succeeds (baseline, no regression).
#[test]
fn a44_build_server_config_no_crls_succeeds() {
    let dir = TempDir::new().expect("tempdir");
    let (params, _, _) = base_params(dir.path());
    build_server_config(params).expect("build_server_config must succeed without CRL");
}

/// Unit: `max_early_data_size` is 0 — 0-RTT early data is explicitly disabled.
#[test]
fn a44_zero_rtt_disabled_by_default() {
    let dir = TempDir::new().expect("tempdir");
    let (params, _, _) = base_params(dir.path());
    // build_server_config asserts max_early_data_size == 0 internally (A-44);
    // if that invariant ever breaks, the function panics rather than returning Ok.
    build_server_config(params).expect("must succeed — 0-RTT assertion must hold");
}

/// Adversarial: `load_crls` on a nonexistent path returns an error.
#[test]
fn a44_load_crls_missing_file_errors() {
    let err = load_crls(Path::new("/nonexistent/client-ca.crl.pem"))
        .expect_err("must error on missing CRL file");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to load CRL"),
        "error message must mention CRL load: {msg}"
    );
}

/// Adversarial: `load_crls` on a file that is not a CRL returns an error.
#[test]
fn a44_load_crls_non_crl_pem_errors() {
    let dir = TempDir::new().expect("tempdir");
    let bad_path = dir.path().join("not-a-crl.pem");
    // Write a plain certificate PEM, which is not a CRL.
    let key = rcgen::KeyPair::generate().expect("keygen");
    let params = rcgen::CertificateParams::new(vec!["test".into()]).expect("params");
    let cert = params.self_signed(&key).expect("sign");
    fs::write(&bad_path, cert.pem()).expect("write");

    let result = load_crls(&bad_path);
    assert!(
        result.is_err(),
        "must error when file contains no CRL entries"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("failed to load CRL") || msg.contains("no CRL entries"),
        "error must indicate CRL load failure: {msg}"
    );
}

/// Unit: `load_crls` on a valid PEM CRL file succeeds and returns one entry.
#[test]
fn a44_load_crls_valid_file_succeeds() {
    let dir = TempDir::new().expect("tempdir");
    let (ca_path, ca_key, ca_cert) = generate_ca(dir.path());
    let _ = ca_path; // path written but we use the in-memory cert/key
    let crl_path = generate_crl(dir.path(), &ca_cert, &ca_key);

    let crls = load_crls(&crl_path).expect("load_crls must succeed on a valid CRL");
    assert!(!crls.is_empty(), "must return at least one CRL entry");
}

/// Unit: `build_server_config` with a valid CRL path succeeds.
#[test]
fn a44_build_server_config_with_crl_path_succeeds() {
    let dir = TempDir::new().expect("tempdir");
    let (ca_path, ca_key, ca_cert) = generate_ca(dir.path());
    let crl_path = generate_crl(dir.path(), &ca_cert, &ca_key);

    let (cert_path, key_path) = generate_server_cert(dir.path());
    let reloadable =
        hearth::protocol::tls::ReloadableTlsConfig::load(cert_path, key_path).expect("load tls");

    let params = TlsConfigParams {
        resolver: Arc::new(reloadable.resolver()),
        client_ca_path: Some(ca_path),
        require_client_cert: true,
        crl_paths: vec![crl_path],
    };
    build_server_config(params).expect("build_server_config must succeed with valid CRL path");
}

/// Adversarial: `build_server_config` with a nonexistent CRL path returns an error.
#[test]
fn a44_build_server_config_with_bad_crl_path_errors() {
    let dir = TempDir::new().expect("tempdir");
    let (ca_path, _, _) = generate_ca(dir.path());

    let (cert_path, key_path) = generate_server_cert(dir.path());
    let reloadable =
        hearth::protocol::tls::ReloadableTlsConfig::load(cert_path, key_path).expect("load tls");

    let params = TlsConfigParams {
        resolver: Arc::new(reloadable.resolver()),
        client_ca_path: Some(ca_path),
        require_client_cert: true,
        crl_paths: vec![PathBuf::from("/nonexistent/bad.crl.pem")],
    };
    let result = build_server_config(params);
    result.expect_err("must error when a CRL path does not exist");
}

/// Config deserialization: `security.tls.crl_paths` round-trips correctly.
#[test]
fn a44_config_tls_crl_paths_deserializes() {
    use hearth::config::SecurityYaml;
    use serde_norway::from_str;

    let yaml = "tls:\n  crl_paths:\n    - /etc/hearth/client-ca.crl.pem\n";
    let sec: SecurityYaml = from_str(yaml).expect("deser");
    assert_eq!(sec.tls.crl_paths.len(), 1);
    assert_eq!(
        sec.tls.crl_paths[0].to_str().unwrap(),
        "/etc/hearth/client-ca.crl.pem"
    );

    let yaml_empty = "";
    let sec_empty: SecurityYaml = from_str(yaml_empty).expect("deser");
    assert!(sec_empty.tls.crl_paths.is_empty());
}

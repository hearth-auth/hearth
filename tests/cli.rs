//! CLI integration tests.
//!
//! Tests the `hearth` binary end-to-end by spawning it as a child process
//! and verifying behavior via HTTP requests and exit codes.
//!
//! Covers TEST\_SCENARIOS: CLI Tool (Integration)

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// Finds an available TCP port by binding to port 0 and reading the assigned port.
fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    listener.local_addr().expect("local addr").port()
}

/// Guard that kills the server process on drop for test cleanup.
struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Returns the path to the compiled `hearth` binary.
fn hearth_bin() -> std::path::PathBuf {
    // cargo nextest / cargo test puts the binary in target/debug
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

/// Starts the hearth server in dev mode on the given port.
fn start_server_dev(port: u16) -> ServerGuard {
    let child = Command::new(hearth_bin())
        .args(["serve", "--dev", "--port", &port.to_string()])
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hearth server");
    ServerGuard { child }
}

/// Waits for the server to accept TCP connections, polling up to `timeout`.
fn wait_for_server(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return true;
        }
        // Short backoff between TCP probe attempts. The only way to detect
        // server readiness here is to probe the socket; tokio::time::advance
        // would not help because server startup is real OS-process I/O, not
        // timer-gated. This sleep is conditional on the poll loop continuing.
        // AUDIT: justified-sleep: bounded by outer TCP-probe poll loop (HEA-571).
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// === TEST_SCENARIOS: hearth serve --dev starts server and accepts connections ===

#[tokio::test]
async fn serve_dev_starts_and_accepts_connections() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    // Verify a health endpoint responds
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("health request");

    assert_eq!(resp.status(), 200, "health endpoint should return 200 OK");
}

#[tokio::test]
async fn serve_dev_exposes_oidc_discovery() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://127.0.0.1:{port}/.well-known/openid-configuration"
        ))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("discovery request");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert!(body.get("issuer").is_some(), "discovery should have issuer");
    assert!(
        body.get("jwks_uri").is_some(),
        "discovery should have jwks_uri"
    );
}

#[tokio::test]
async fn serve_dev_exposes_jwks() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    let client = reqwest::Client::new();
    // /jwks blocks until the dev-mode signing keys (RSA/EC) are minted, which
    // observably takes >5s on cold CI runners — the sibling /.well-known/openid-configuration
    // test only returns precomputed metadata, so 5s is fine there. Use a longer per-request
    // budget here to absorb cold-runner key-generation variance.
    let resp = client
        .get(format!("http://127.0.0.1:{port}/jwks"))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("jwks request");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert!(body.get("keys").is_some(), "JWKS should have keys array");
}

// === TEST_SCENARIOS: CLI exits with appropriate non-zero error codes ===

#[test]
fn cli_no_subcommand_exits_with_error() {
    let output = Command::new(hearth_bin())
        .output()
        .expect("run hearth without args");

    assert!(
        !output.status.success(),
        "hearth with no subcommand should exit non-zero"
    );
}

#[test]
fn cli_invalid_subcommand_exits_with_error() {
    let output = Command::new(hearth_bin())
        .arg("nonexistent-command")
        .output()
        .expect("run hearth with invalid subcommand");

    assert!(
        !output.status.success(),
        "hearth with invalid subcommand should exit non-zero"
    );
}

#[test]
fn cli_serve_invalid_port_exits_with_error() {
    let output = Command::new(hearth_bin())
        .args(["serve", "--port", "not-a-number"])
        .output()
        .expect("run hearth serve with invalid port");

    assert!(
        !output.status.success(),
        "hearth serve with invalid port should exit non-zero"
    );
}

#[test]
fn cli_serve_missing_config_file_exits_with_error() {
    let output = Command::new(hearth_bin())
        .args(["serve", "--config", "/nonexistent/hearth.yaml"])
        .output()
        .expect("run hearth serve with missing config");

    assert!(
        !output.status.success(),
        "hearth serve with missing config file should exit non-zero"
    );
}

// === TEST_SCENARIOS: cluster init failure is fatal ===

/// A config with a `cluster:` section pointing at unreachable peers must cause
/// `hearth serve` to exit non-zero rather than silently degrading to single-node
/// mode (HEA-2108).
#[test]
fn serve_cluster_init_failure_is_fatal() {
    use std::io::Write;

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("hearth.yaml");

    // Minimal cluster config: node_id + peer_address + unreachable peer + dummy
    // TLS paths (files do not exist — ClusterEngine::init will fail reading them).
    let cfg_yaml = r#"
cluster:
  node_id: 1
  peer_address: "127.0.0.1:19001"
  peers:
    - id: 2
      address: "127.0.0.1:19002"
  tls_cert_path: "/nonexistent/cert.pem"
  tls_key_path: "/nonexistent/key.pem"
  tls_ca_cert_path: "/nonexistent/ca.pem"
"#;
    std::fs::File::create(&cfg_path)
        .expect("create config")
        .write_all(cfg_yaml.as_bytes())
        .expect("write config");

    // Use --dev so no real storage/email/key setup is needed.
    let output = Command::new(hearth_bin())
        .args([
            "serve",
            "--dev",
            "--config",
            cfg_path.to_str().expect("path"),
        ])
        .output()
        .expect("spawn hearth serve");

    assert!(
        !output.status.success(),
        "hearth serve with failing cluster config must exit non-zero (got 0); \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The report is a log line on stdout. This used to read stderr only, and
    // the config said `node_id:` for a peer's `id:`, so the test passed on
    // the YAML parse error and never reached cluster init.
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        all.contains("Raft ClusterEngine init failed"),
        "the output must report the cluster init failure; got: {all}"
    );
}

/// Writes a CA and one `127.0.0.1` leaf into `dir` as `ca.crt`, `node.crt`
/// and `node.key`, for the peer mTLS paths of a cluster config.
fn write_peer_tls(dir: &std::path::Path) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf cert");
    std::fs::write(dir.join("ca.crt"), ca.pem()).expect("write ca");
    std::fs::write(dir.join("node.crt"), leaf.pem()).expect("write leaf");
    std::fs::write(dir.join("node.key"), leaf_key.serialize_pem()).expect("write key");
}

/// The peer server binds `cluster.peer_address` at start-up. When it could
/// not (here: the port is taken), it used to fail inside a spawned task:
/// one ERROR line, and the node went on running without a peer server, so
/// it could never join a cluster. `serve` must exit instead.
#[test]
fn serve_exits_when_the_peer_server_cannot_bind() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_peer_tls(dir.path());
    let taken = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let peer_address = taken.local_addr().expect("addr");
    let cfg_path = dir.path().join("hearth.yaml");
    let tls = dir.path().display();
    std::fs::write(
        &cfg_path,
        format!(
            "server:\n  port: {http_port}\nstorage:\n  data_dir: \"{tls}/data\"\n\
             cluster:\n  node_id: 1\n  peer_address: \"{peer_address}\"\n  peers:\n    \
             - id: 2\n      address: \"127.0.0.1:{peer_port}\"\n  \
             tls_cert_path: \"{tls}/node.crt\"\n  tls_key_path: \"{tls}/node.key\"\n  \
             tls_ca_cert_path: \"{tls}/ca.crt\"\n",
            http_port = find_available_port(),
            peer_port = find_available_port(),
        ),
    )
    .expect("write config");

    let mut child = Command::new(hearth_bin())
        .args([
            "serve",
            "--dev",
            "--config",
            cfg_path.to_str().expect("path"),
        ])
        .stdout(std::fs::File::create(dir.path().join("out.log")).expect("stdout file"))
        .stderr(std::fs::File::create(dir.path().join("err.log")).expect("stderr file"))
        .spawn()
        .expect("spawn hearth serve");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    drop(taken);
    // Logs go to stdout, the start-up fatal report to stderr: read both.
    let output = ["out.log", "err.log"]
        .map(|f| std::fs::read_to_string(dir.path().join(f)).unwrap_or_default())
        .concat();
    // A debug-level log of 30 s is long: keep its end for the failure message.
    let skip = output.chars().count().saturating_sub(4000);
    let tail: String = output.chars().skip(skip).collect();

    let status = status.unwrap_or_else(|| {
        panic!("serve kept running for 30 s without its peer server; output ends: {tail}")
    });
    assert!(
        !status.success(),
        "serve must exit non-zero; output ends: {tail}"
    );
    assert!(
        output.contains(&peer_address.to_string()),
        "the error must name the peer address {peer_address}; output ends: {tail}"
    );
}

// === TEST_SCENARIOS: CLI management commands ===

#[test]
fn cli_realm_create_generates_uuid() {
    let output = Command::new(hearth_bin())
        .args(["realm", "create"])
        .output()
        .expect("run hearth realm create");

    assert!(
        output.status.success(),
        "realm create should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should output valid JSON with a realm_id UUID
    let body: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("realm create output should be JSON");
    let realm_id = body["realm_id"].as_str().expect("should have realm_id");
    assert!(
        uuid::Uuid::parse_str(realm_id).is_ok(),
        "realm_id should be a valid UUID, got: {realm_id}"
    );
}

// === `serve --dev` on a binary built without the `dev-endpoints` feature ===

/// `dev-endpoints` is not a default feature, so `cargo build` yields a binary
/// whose `--dev` mode has no `/admin/bootstrap`. The server must say so at
/// startup and name the fix, rather than leaving the operator to discover a
/// bare `404` from the first step of every dev recipe.
#[cfg(not(feature = "dev-endpoints"))]
#[test]
fn serve_dev_without_dev_endpoints_feature_says_bootstrap_is_unavailable() {
    let port = find_available_port();
    let mut child = Command::new(hearth_bin())
        .args(["serve", "--dev", "--port", &port.to_string()])
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hearth server");
    let up = wait_for_server(port, Duration::from_secs(20));
    // Kill before asserting so a failed assertion never leaks the server.
    let _ = child.kill();
    let output = child.wait_with_output().expect("collect server output");
    assert!(up, "server should accept TCP connections within 20s");
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        logs.contains("WITHOUT the `dev-endpoints` cargo feature")
            && logs.contains("--features dev-endpoints"),
        "startup logs must say /admin/bootstrap is unavailable and how to get it; got:\n{logs}"
    );
}

#[cfg(feature = "dev-endpoints")]
#[tokio::test]
async fn cli_app_create_against_running_server() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    // Client registration is a privileged operation (HEA-1750): mint an admin
    // token + realm via the dev-only bootstrap endpoint. The target realm is
    // derived from the token, so we register under the bootstrap realm.
    let client = reqwest::Client::new();
    let boot: serde_json::Value = client
        .post(format!("http://127.0.0.1:{port}/admin/bootstrap"))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("bootstrap request")
        .json()
        .await
        .expect("parse bootstrap JSON");
    let realm_id = boot["realm_id"].as_str().expect("realm_id").to_string();
    let admin_token = boot["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Register an app (OAuth client) via CLI
    let output = Command::new(hearth_bin())
        .args([
            "app",
            "create",
            "--server",
            &format!("http://127.0.0.1:{port}"),
            "--realm-id",
            &realm_id,
            "--name",
            "CLI Test App",
            "--redirect-uri",
            "https://cli-test.example.com/callback",
            "--token",
            &admin_token,
        ])
        .output()
        .expect("run hearth app create");

    assert!(
        output.status.success(),
        "app create should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let body: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("app create output should be JSON");
    assert!(
        body["client_id"].as_str().is_some(),
        "should have client_id in output"
    );
    assert_eq!(
        body["client_name"].as_str().unwrap_or(""),
        "CLI Test App",
        "client_name should match"
    );
}

// === TEST_SCENARIOS: CLI config + completions subcommands (HEA-1836) ===
//
// These cover the deterministic, no-storage subcommands that previously had no
// integration coverage: `completions <shell>`, `config example`, and
// `config validate` (both the accept and reject paths). The storage/server
// backed subcommands (`migrate`, `backup`, `rbac orphans`, `config reload`)
// remain follow-up work — they need a seeded data dir or a running process.

/// Writes `content` to a uniquely-named temp file and returns its path.
/// The caller is responsible for the file living long enough for the child
/// process to read it; callers keep it around and let the OS reclaim temp.
fn write_temp_config(tag: &str, content: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    path.push(format!("hearth-cli-{tag}-{pid}-{nanos}.yaml"));
    std::fs::write(&path, content).expect("write temp config");
    path
}

#[test]
fn cli_completions_zsh_generates_script() {
    let output = Command::new(hearth_bin())
        .args(["completions", "zsh"])
        .output()
        .expect("run hearth completions zsh");
    assert!(
        output.status.success(),
        "completions zsh should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("#compdef hearth") || stdout.contains("_hearth"),
        "zsh completion must reference the hearth command; got:\n{stdout}"
    );
}

#[test]
fn cli_completions_bash_generates_script() {
    let output = Command::new(hearth_bin())
        .args(["completions", "bash"])
        .output()
        .expect("run hearth completions bash");
    assert!(
        output.status.success(),
        "completions bash should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hearth"),
        "bash completion must reference the hearth command"
    );
}

#[test]
fn cli_config_example_prints_yaml() {
    let output = Command::new(hearth_bin())
        .args(["config", "example"])
        .output()
        .expect("run hearth config example");
    assert!(
        output.status.success(),
        "config example should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("server:") && stdout.contains("storage:"),
        "example config must contain the documented top-level sections"
    );
}

#[test]
fn cli_config_validate_accepts_valid_file() {
    // `dev_mode` may no longer be set in a config file — `hearth serve --dev`
    // is the only way to reach dev mode (audit 2026-08-28 §4.7#3), and the
    // validator refuses the key outright. So this fixture is a minimal but
    // genuinely valid PRODUCTION config instead.
    let path = write_temp_config(
        "valid",
        concat!(
            "server:\n  bind_address: \"127.0.0.1\"\n  port: 8420\n",
            "  trust_forwarded_proto: true\n  trusted_proxies: [\"127.0.0.1\"]\n",
            "storage:\n  data_dir: \"/tmp/hearth-cli-validate\"\n",
            "oidc:\n  issuer: \"https://auth.example.com\"\n",
            "security:\n  key_encryption_key: \"",
            "1111111111111111111111111111111111111111111111111111111111111111\"\n",
            "email:\n  transport: smtp\n  from: \"auth@example.com\"\n",
            "  smtp:\n    host: \"mail.example.com\"\n    port: 587\n",
        ),
    );
    let output = Command::new(hearth_bin())
        .args(["config", "validate"])
        .arg(&path)
        .output()
        .expect("run hearth config validate");
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "config validate should exit 0 for a valid file; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("valid"),
        "success output must confirm the config is valid; got:\n{stdout}"
    );
}

#[test]
fn cli_config_validate_rejects_invalid_file() {
    // port 0 is out of range (and, in non-dev mode, data_dir is required) — the
    // validator must collect at least one issue and exit non-zero.
    let path = write_temp_config("invalid", "server:\n  port: 0\n");
    let output = Command::new(hearth_bin())
        .args(["config", "validate"])
        .arg(&path)
        .output()
        .expect("run hearth config validate");
    let _ = std::fs::remove_file(&path);
    assert!(
        !output.status.success(),
        "config validate must exit non-zero for an invalid file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "failure output must explain the validation error; got:\n{stderr}"
    );
}

// ===== §4.9#8, §4.14#6: the backup CLI family must say what happened =====

/// `hearth backup <verb>` installs no tracing subscriber, so every
/// `tracing::error!` on those paths was written to a dispatcher that does not
/// exist. A failed `verify` exited 3 with an empty stderr — the operator saw a
/// number and no reason. Same for `create` failing on the data-directory lock.
#[test]
fn backup_verify_failure_reports_the_reason() {
    let missing = std::env::temp_dir().join("hearth-no-such-archive-4f2a.tar.gz");
    let _ = std::fs::remove_file(&missing);

    let out = Command::new(hearth_bin())
        .args(["backup", "verify", "--input"])
        .arg(&missing)
        .output()
        .expect("run hearth backup verify");

    assert_eq!(
        out.status.code(),
        Some(3),
        "a failed verify exits 3; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // CLI diagnostics follow the same convention as `serve`: the tracing fmt
    // layer writes to stdout. `examples/auth0-migration/run.sh` parses the
    // migration summary off stdout, so the stream must not move.
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        output.contains("integrity failure"),
        "the failure reason must be emitted, got: {output:?}"
    );
}

/// `hearth backup create` against a data directory another process holds fails
/// on the flock. That failure was also silent.
#[test]
fn backup_create_lock_failure_reports_the_reason() {
    use fs2::FileExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    // Hold the same exclusive flock `EmbeddedStorageEngine::open` takes, so the
    // child fails on the lock rather than on a missing directory.
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data_dir.join("LOCK"))
        .expect("open LOCK");
    lock_file.try_lock_exclusive().expect("hold the lock");

    let out = Command::new(hearth_bin())
        .args(["backup", "create", "--data-dir"])
        .arg(&data_dir)
        .arg("--output")
        .arg(dir.path().join("archive.tar.gz"))
        .output()
        .expect("run hearth backup create");

    assert_ne!(out.status.code(), Some(0), "create must fail on the lock");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        output.contains("locked"),
        "a lock failure must name the lock, got: {output:?}"
    );
}

// ===== §4.13#5: security.backup.verify_key must reach the server =====

/// `security.backup.verify_key` was parsed and then dropped: nothing ever put
/// it on `AppState`, so the restore handler's signature check could not fire on
/// any deployment. This guards the config → server link that was missing; the
/// check itself is covered in `tests/backup_http.rs`.
#[test]
fn configured_backup_verify_key_reaches_the_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = find_available_port();
    let config_path = dir.path().join("hearth.yaml");
    let data_dir = dir.path().join("data");
    std::fs::write(
        &config_path,
        format!(
            r#"
server:
  port: {port}
  bind_address: "127.0.0.1"
dev_mode: true
storage:
  data_dir: "{}"
oidc:
  issuer: "http://127.0.0.1:{port}"
email:
  transport: log
security:
  backup:
    verify_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#,
            data_dir.display()
        ),
    )
    .expect("write config");

    let mut child = Command::new(hearth_bin())
        .args(["serve", "--dev", "-c"])
        .arg(&config_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hearth server");

    let up = wait_for_server(port, Duration::from_secs(30));
    let _ = child.kill();
    let out = child.wait_with_output().expect("collect server output");

    assert!(
        up,
        "the server must start with a backup verify key configured"
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        logs.contains("backup restore signature verification ENABLED"),
        "the configured verify key must reach the server; logs: {logs}"
    );
}

// ===== A-30: `backup restore` refuses archives it cannot authenticate =====
//
// The CLI restore never looked at the manifest signature at all — not even
// with `security.backup.verify_key` configured — so an archive anyone could
// write restored silently. It now requires a verify key (flag or config) and
// a valid signature, unless the operator passes `--allow-unsigned`.

/// Writes an unsigned archive with no realms: small, and it restores to exit 0
/// once past the signature gate, so the gate is the only thing under test.
fn write_empty_archive(path: &std::path::Path) {
    let writer = hearth::backup::BackupArchive::create(path).expect("create archive");
    writer
        .finish(hearth::backup::BackupManifest::new(vec![]))
        .expect("finish archive");
}

fn run_hearth(args: &[&std::ffi::OsStr]) -> (Option<i32>, String) {
    let out = Command::new(hearth_bin())
        .args(args)
        .env_remove("HEARTH_KEK")
        // Opening a store outside dev mode requires a master key.
        .env(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        .output()
        .expect("run hearth");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

#[test]
fn backup_restore_refuses_without_a_verify_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("a.hearth-backup");
    let data_dir = dir.path().join("data");
    write_empty_archive(&archive);

    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir.as_os_str(),
    ]);
    assert_eq!(code, Some(2), "restore must refuse; output: {out}");
    assert!(
        out.contains("security.backup.verify_key") && out.contains("--allow-unsigned"),
        "the refusal must say how to configure the key and how to opt out: {out}"
    );
    assert!(
        !data_dir.exists(),
        "the refusal must come before anything is written"
    );

    // Control: the explicit opt-in restores the same archive.
    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir.as_os_str(),
        os("--allow-unsigned"),
    ]);
    assert_eq!(
        code,
        Some(0),
        "--allow-unsigned must restore; output: {out}"
    );
    assert!(
        out.contains("WITHOUT signature verification"),
        "an unverified restore must say so: {out}"
    );
}

#[test]
fn backup_keygen_sign_and_verified_restore_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_file = dir.path().join("backup-signing.pem");
    let archive = dir.path().join("a.hearth-backup");
    write_empty_archive(&archive);

    let (code, out) = run_hearth(&[
        os("backup"),
        os("keygen"),
        os("--output"),
        key_file.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "keygen: {out}");
    let key = hearth::backup::BackupSigningKey::from_pem(
        &std::fs::read_to_string(&key_file).expect("key file written"),
    )
    .expect("keygen writes a key the library reads");
    let verify_key = key.verify_key_b64();
    assert!(
        out.contains(&verify_key),
        "keygen must print the verify key to configure: {out}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key_file)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "private key must not be group/world readable"
        );
    }
    // keygen never overwrites an existing key.
    let (code, _) = run_hearth(&[
        os("backup"),
        os("keygen"),
        os("--output"),
        key_file.as_os_str(),
    ]);
    assert_ne!(code, Some(0), "keygen must refuse to overwrite a key");

    let (code, out) = run_hearth(&[
        os("backup"),
        os("sign"),
        os("--input"),
        archive.as_os_str(),
        os("--key-file"),
        key_file.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "sign: {out}");

    let data_dir = dir.path().join("data");
    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir.as_os_str(),
        os(&format!("--verify-key={verify_key}")),
    ]);
    assert_eq!(code, Some(0), "signed archive must restore; output: {out}");
    assert!(out.contains("signature verified"), "{out}");

    // A different key must not verify it — and `--allow-unsigned` does not
    // override a key that was given.
    let (other, _) = hearth::backup::BackupSigningKey::generate().expect("generate");
    let other_key = other.verify_key_b64();
    let data_dir2 = dir.path().join("data2");
    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir2.as_os_str(),
        os(&format!("--verify-key={other_key}")),
        os("--allow-unsigned"),
    ]);
    assert_eq!(code, Some(2), "wrong key must refuse; output: {out}");
    assert!(out.contains("signature is invalid"), "{out}");
}

#[test]
fn backup_restore_reads_the_verify_key_from_config_and_it_is_authoritative() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("a.hearth-backup");
    write_empty_archive(&archive);
    let (key, _) = hearth::backup::BackupSigningKey::generate().expect("generate");
    let config = dir.path().join("hearth.yaml");
    std::fs::write(
        &config,
        format!(
            "server:\n  port: 8420\n  bind_address: \"127.0.0.1\"\nstorage:\n  data_dir: \"{}\"\n\
             oidc:\n  issuer: \"http://127.0.0.1:8420\"\nemail:\n  transport: log\n\
             security:\n  backup:\n    verify_key: \"{}\"\n",
            dir.path().join("unused").display(),
            key.verify_key_b64()
        ),
    )
    .expect("write config");

    // The archive is unsigned. A configured key is authoritative, so the
    // opt-in for key-less deployments does not wave it through.
    let data_dir = dir.path().join("data");
    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir.as_os_str(),
        os("--config"),
        config.as_os_str(),
        os("--allow-unsigned"),
    ]);
    assert_eq!(
        code,
        Some(2),
        "unsigned archive must be refused; output: {out}"
    );
    assert!(out.contains("archive is unsigned"), "{out}");
}

/// Rewrites the archive at `path` in place, replacing the bytes of member
/// `name` with `bytes` and leaving `manifest.json` — and so its signature —
/// exactly as it was.
fn swap_member(path: &std::path::Path, name: &str, bytes: &[u8]) {
    use std::io::Read as _;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let decoder = zstd::Decoder::new(std::fs::File::open(path).expect("open")).expect("dec");
    for entry in tar::Archive::new(decoder).entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let p = entry.path().expect("path").to_string_lossy().into_owned();
        let mut b = Vec::new();
        entry.read_to_end(&mut b).expect("read");
        entries.push((p, b));
    }
    let encoder = zstd::Encoder::new(std::fs::File::create(path).expect("create"), 0).expect("enc");
    let mut builder = tar::Builder::new(encoder);
    for (p, b) in entries {
        let data = if p == name { bytes.to_vec() } else { b };
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, &p, data.as_slice())
            .expect("append");
    }
    builder
        .into_inner()
        .expect("into_inner")
        .finish()
        .expect("finish");
}

/// The signature covers the manifest only; members are authenticated through
/// the manifest's checksums. `--skip-verify` skipped exactly those checksums,
/// so a signed archive whose members were swapped after signing restored with
/// "archive signature verified" in the log. A verified signature must imply
/// verified members.
#[test]
fn backup_restore_refuses_skip_verify_when_the_signature_is_checked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("a.hearth-backup");
    let mut writer = hearth::backup::BackupArchive::create(&archive).expect("create archive");
    writer
        .add_file("realms/ghost/users.ndjson", b"{\"id\":\"original\"}\n")
        .expect("add member");
    writer
        .finish(hearth::backup::BackupManifest::new(vec![]))
        .expect("finish archive");
    let (key, _) = hearth::backup::BackupSigningKey::generate().expect("generate");
    hearth::backup::sign_archive(&archive, &archive, &key).expect("sign");
    swap_member(
        &archive,
        "realms/ghost/users.ndjson",
        b"{\"id\":\"attacker\"}\n",
    );
    let verify_key = key.verify_key_b64();

    let data_dir = dir.path().join("data");
    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir.as_os_str(),
        os(&format!("--verify-key={verify_key}")),
        os("--skip-verify"),
    ]);
    assert_eq!(
        code,
        Some(2),
        "--skip-verify must not bypass member authentication; output: {out}"
    );
    assert!(
        out.contains("--skip-verify"),
        "the refusal must name the flag: {out}"
    );
    assert!(
        !out.contains("signature verified"),
        "nothing may claim the archive was verified: {out}"
    );
    assert!(
        !data_dir.exists(),
        "the refusal must come before anything is written"
    );

    // Without the flag the tampered member is caught by the checksum check.
    let (code, out) = run_hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        data_dir.as_os_str(),
        os(&format!("--verify-key={verify_key}")),
    ]);
    assert_eq!(code, Some(2), "tampered member must be refused: {out}");
    assert!(out.contains("realms/ghost/users.ndjson"), "{out}");
    assert!(!data_dir.exists(), "nothing may be written");
}

// ===== `hearth rbac orphans` must say why it failed =====

/// Runs `hearth rbac orphans <verb> --data-dir <dir>` with NO master key, on a
/// data directory holding only a `hearth.host_key` file (which production
/// ignores), and returns (exit code, stdout + stderr).
///
/// Both streams count as "reported": CLI diagnostics follow the `serve` /
/// `backup` convention above, where the tracing fmt layer writes to stdout.
fn run_orphans_without_master_key(verb: &str) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    std::fs::write(data_dir.join("hearth.host_key"), [0u8; 72]).expect("write host key");

    let out = Command::new(hearth_bin())
        .args(["rbac", "orphans", verb, "--data-dir"])
        .arg(&data_dir)
        .env_remove("HEARTH_MASTER_KEY")
        .env_remove("HEARTH_KEK")
        .output()
        .expect("run hearth rbac orphans");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

/// `hearth rbac orphans list` reported every failure with `tracing::error!`
/// before any subscriber was installed, so a refused store open exited 1 with
/// no output at all.
#[test]
fn rbac_orphans_list_failure_reports_the_reason() {
    let (code, out) = run_orphans_without_master_key("list");
    assert_eq!(code, Some(1), "a failed list exits 1; output: {out:?}");
    assert!(
        out.contains("HEARTH_MASTER_KEY is not set"),
        "the refusal must be reported and name HEARTH_MASTER_KEY, got: {out:?}"
    );
    assert!(
        out.contains("ignored"),
        "the refusal must say the host key file was ignored, got: {out:?}"
    );
}

/// Same silent failure on `purge`.
#[test]
fn rbac_orphans_purge_failure_reports_the_reason() {
    let (code, out) = run_orphans_without_master_key("purge");
    assert_eq!(code, Some(1), "a failed purge exits 1; output: {out:?}");
    assert!(
        out.contains("HEARTH_MASTER_KEY is not set"),
        "the refusal must be reported and name HEARTH_MASTER_KEY, got: {out:?}"
    );
}

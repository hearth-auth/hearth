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
    // `dev_mode: true` relaxes data_dir / oidc-issuer requirements, so this
    // minimal file validates cleanly.
    let path = write_temp_config(
        "valid",
        "dev_mode: true\nserver:\n  bind_address: \"127.0.0.1\"\n  port: 8420\n",
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

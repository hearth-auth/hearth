//! GA audit 2026-09-28 OPS-13 — `serve --dev -c prod.yaml` opened the
//! production data directory.
//!
//! `--dev` honours a non-default `storage.data_dir` from the config file
//! (HEA-1805), and it runs with fsync off and the `fast_for_testing` Argon2
//! costs. Pointed at a production config it wrote unsynced records and weakly
//! hashed passwords into the production store.
//!
//! A production start now marks its data directory, and `--dev` refuses a
//! marked directory.

#![cfg(unix)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The marker a production start leaves in its data directory.
const MARKER: &str = ".hearth-production";

fn hearth_bin() -> PathBuf {
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// A production config that passes every start-up gate, storing in `data_dir`.
fn production_config(dir: &Path, data_dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("prod.yaml");
    std::fs::write(
        &path,
        format!(
            "server:\n  bind_address: \"127.0.0.1\"\n  port: {port}\n  trust_forwarded_proto: true\n  \
             trusted_proxies: [\"127.0.0.1\"]\nstorage:\n  data_dir: \"{}\"\noidc:\n  \
             issuer: \"https://auth.example.com\"\nemail:\n  transport: smtp\n  from: \
             \"auth@example.com\"\n  smtp:\n    host: \"mail.example.com\"\n    port: 587\n\
             onboarding:\n  enabled: false\n",
            data_dir.display()
        ),
    )
    .expect("write config");
    path
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        // AUDIT: justified-sleep: bounded poll for a child process to bind (OPS-13).
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A production start marks its data directory.
#[test]
fn a_production_start_marks_its_data_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let port = free_port();
    let config = production_config(dir.path(), &data_dir, port);

    let mut child = Command::new(hearth_bin())
        .args(["serve", "-c"])
        .arg(&config)
        .env("HEARTH_MASTER_KEY", "22".repeat(32))
        .env("HEARTH_KEK", "33".repeat(32))
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn production server");
    let up = wait_for_port(port, Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();

    assert!(up, "the production server should start with this config");
    assert!(
        data_dir.join(MARKER).exists(),
        "a production start must leave {MARKER} in its data directory"
    );
}

/// `--dev` pointed at a marked directory refuses to start, before it writes.
#[test]
fn dev_mode_refuses_a_production_data_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    std::fs::write(data_dir.join(MARKER), "").expect("mark");
    let port = free_port();
    let config = production_config(dir.path(), &data_dir, port);

    let mut child = Command::new(hearth_bin())
        .args(["serve", "--dev", "--port", &port.to_string(), "-c"])
        .arg(&config)
        .env_remove("HEARTH_DEV_DATA_DIR")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run hearth");
    let started = Instant::now();
    let exited = loop {
        if child.try_wait().expect("try_wait").is_some() {
            break true;
        }
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            break false;
        }
        // AUDIT: justified-sleep: bounded poll for the child to exit (OPS-13).
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = child.wait_with_output().expect("collect output");

    assert!(
        exited && !output.status.success(),
        "--dev must refuse (exit non-zero) a data directory a production server has used; \
         it was still running after 20 s"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains(MARKER),
        "the refusal must name the marker file so the operator knows why; got:\n{text}"
    );
    let wal_written = std::fs::read_dir(&data_dir)
        .expect("read data dir")
        .filter_map(Result::ok)
        .any(|e| e.file_name() != MARKER);
    assert!(
        !wal_written,
        "--dev must refuse before writing anything into the production data directory"
    );
}

/// The control: an unmarked directory from a dev config still works (HEA-1805).
#[test]
fn dev_mode_still_uses_an_unmarked_config_data_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("dev-data");
    let port = free_port();
    let config = dir.path().join("dev.yaml");
    std::fs::write(
        &config,
        format!("storage:\n  data_dir: \"{}\"\n", data_dir.display()),
    )
    .expect("write config");

    let mut child = Command::new(hearth_bin())
        .args(["serve", "--dev", "--port", &port.to_string(), "-c"])
        .arg(&config)
        .env_remove("HEARTH_DEV_DATA_DIR")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dev server");
    let up = wait_for_port(port, Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        up,
        "--dev with an unmarked config data_dir must still start"
    );
    assert!(
        !data_dir.join(MARKER).exists(),
        "a dev start must not mark its data directory as production"
    );
}

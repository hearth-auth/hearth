//! Integration tests for graceful shutdown behaviour (SIGTERM / SIGINT drain).
//!
//! Verifies HEA-2161: SIGTERM must trigger the same graceful-drain sequence as
//! SIGINT so that `docker stop`, `kubectl delete pod`, and `systemctl stop` do
//! not drop in-flight requests or produce a non-zero exit code.
//!
//! **Red at af4edb59**: without the fix, SIGTERM had no handler, causing the OS
//! to kill the process immediately (exit-by-signal → `status.code() == None`,
//! not `Some(0)`), and any in-flight request was reset mid-response.
//!
//! Covers TEST_SCENARIOS: Graceful shutdown (SIGTERM) (HEA-2161)

#[cfg(unix)]
mod sigterm {
    use std::net::TcpListener;
    use std::process::{Child, Command};
    use std::time::Duration;

    fn find_available_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
        listener.local_addr().expect("local addr").port()
    }

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

    /// Starts the hearth server in dev mode and returns the raw `Child` handle
    /// (no auto-kill guard so tests can observe the natural exit).
    fn start_server_dev(port: u16) -> Child {
        Command::new(hearth_bin())
            .args(["serve", "--dev", "--port", &port.to_string()])
            .env("RUST_LOG", "warn")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn hearth server")
    }

    /// Polls until the server accepts a TCP connection or the timeout expires.
    fn wait_for_server(port: u16, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
                return true;
            }
            // AUDIT: justified-sleep: bounded by outer TCP-probe poll loop (HEA-2161).
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Sends SIGTERM to the given PID via `kill(1)` (no libc dependency).
    fn send_sigterm(pid: u32) {
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("send SIGTERM");
    }

    /// Waits for `child` to exit, polling up to `deadline`.
    /// Kills the child and panics if it does not exit in time.
    fn wait_for_exit(child: &mut Child, deadline: Duration) -> std::process::ExitStatus {
        let start = std::time::Instant::now();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return status,
                None if start.elapsed() < deadline => {
                    // AUDIT: justified-sleep: bounded 100 ms poll tick; cannot use tokio::time::advance in a cross-process test (HEA-2161).
                    std::thread::sleep(Duration::from_millis(100));
                }
                None => {
                    let _ = child.kill();
                    panic!(
                        "server did not exit within {}s after SIGTERM",
                        deadline.as_secs()
                    );
                }
            }
        }
    }

    // === TEST_SCENARIOS: SIGTERM triggers graceful shutdown (exit code 0) ===

    /// Primary correctness test.
    ///
    /// Before HEA-2161: SIGTERM had no handler — the OS terminated the process
    /// immediately, producing `status.code() == None` (signal-kill, no exit code).
    /// After HEA-2161: SIGTERM fires the graceful-drain path, the server exits
    /// cleanly, and `status.code() == Some(0)`.
    #[tokio::test]
    async fn sigterm_exits_zero() {
        let port = find_available_port();
        let mut child = start_server_dev(port);

        assert!(
            wait_for_server(port, Duration::from_secs(20)),
            "server should accept TCP connections within 20 s"
        );

        send_sigterm(child.id());

        // Drain deadline is 10 s by default; allow 15 s for scheduling jitter.
        let status = wait_for_exit(&mut child, Duration::from_secs(15));

        assert_eq!(
            status.code(),
            Some(0),
            "SIGTERM must trigger graceful drain and the process must exit 0 \
             (without the fix the process is killed by signal and status.code() is None)"
        );
    }

    // === TEST_SCENARIOS: In-flight HTTP request completes after SIGTERM ===

    /// In-flight drain test.
    ///
    /// Bootstraps the server (which does Argon2id hashing — ~50-200 ms), fires
    /// SIGTERM 5 ms into the bootstrap request, and asserts that the in-flight
    /// request completes rather than being reset.
    ///
    /// Before HEA-2161: SIGTERM killed the process immediately, causing the
    /// bootstrap request to get a TCP reset (`reqwest` returns an error).
    /// After HEA-2161: SIGTERM triggers axum's `with_graceful_shutdown`, which
    /// waits for in-flight requests to complete before returning.
    #[tokio::test]
    async fn sigterm_does_not_abort_inflight_http_request() {
        let port = find_available_port();
        let mut child = start_server_dev(port);

        assert!(
            wait_for_server(port, Duration::from_secs(20)),
            "server should accept TCP connections within 20 s"
        );

        let pid = child.id();

        // The /admin/bootstrap endpoint performs Argon2id hashing (~50-200 ms),
        // ensuring the request is still in-flight when SIGTERM fires 5 ms later.
        let url = format!("http://127.0.0.1:{port}/admin/bootstrap");
        let req_handle = tokio::spawn(async move {
            reqwest::Client::new()
                .post(&url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
        });

        // Lets the OS accept the TCP connection and dispatch the request into the
        // Argon2id handler before the drain begins (~50 ms hash floor means 5 ms
        // is a safe "still in-flight" window — see HEA-2161).
        // AUDIT: justified-sleep: race window necessary for cross-process in-flight drain test (HEA-2161).
        std::thread::sleep(Duration::from_millis(5));
        send_sigterm(pid);

        // The in-flight request must complete — not get a TCP reset.
        let resp = req_handle
            .await
            .expect("request task did not panic")
            .expect(
                "in-flight bootstrap request must complete cleanly during graceful drain; \
                 a connection error here means SIGTERM aborted the request before the fix",
            );
        assert_eq!(
            resp.status().as_u16(),
            200,
            "bootstrap should return 200 when the server drains cleanly"
        );

        // Process must exit 0 within the drain deadline + buffer.
        let status = wait_for_exit(&mut child, Duration::from_secs(15));
        assert_eq!(
            status.code(),
            Some(0),
            "SIGTERM must produce exit code 0 after the drain completes"
        );
    }
}

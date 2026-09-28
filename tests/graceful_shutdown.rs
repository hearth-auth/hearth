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
    #[cfg(feature = "dev-endpoints")]
    use std::io::{BufRead, Read, Write};
    use std::net::TcpListener;
    #[cfg(feature = "dev-endpoints")]
    use std::net::TcpStream;
    use std::process::{Child, Command};
    #[cfg(feature = "dev-endpoints")]
    use std::sync::mpsc::Receiver;
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

    /// Starts the server in dev mode with request-level tracing on stdout.
    ///
    /// `tower_http`'s `DefaultOnRequest` logs `started processing request` at
    /// DEBUG the moment a request reaches the trace layer, which gives a test a
    /// real synchronisation point instead of a wall-clock guess. `RUST_LOG`
    /// wins over the config log level — `telemetry` builds its `EnvFilter` with
    /// `try_from_default_env` first.
    #[cfg(feature = "dev-endpoints")]
    fn start_server_dev_traced(port: u16) -> Child {
        Command::new(hearth_bin())
            .args(["serve", "--dev", "--port", &port.to_string()])
            .env("RUST_LOG", "warn,tower_http::trace=debug")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn hearth server")
    }

    /// Drains `child`'s stdout on a background thread and sends one message per
    /// request the server begins processing.
    ///
    /// The thread must keep reading after the first match, otherwise the pipe
    /// fills and the server blocks on its own log writes.
    #[cfg(feature = "dev-endpoints")]
    fn watch_for_request_start(child: &mut Child) -> Receiver<()> {
        let stdout = child.stdout.take().expect("server stdout must be piped");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if line.contains("started processing request") {
                    let _ = tx.send(());
                }
            }
        });
        rx
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
    /// SIGTERM after the request bytes are on the wire, and asserts that the
    /// in-flight request completes rather than being reset.
    ///
    /// Before HEA-2161: SIGTERM killed the process immediately, causing the
    /// bootstrap request to get a TCP reset.
    /// After HEA-2161: SIGTERM triggers axum's `with_graceful_shutdown`, which
    /// waits for in-flight requests to complete before returning.
    ///
    /// The harness has no wall-clock race. Two earlier forms did:
    ///
    /// 1. The original spawned the request on a `#[tokio::test]` current-thread
    ///    runtime and then blocked that same thread with `std::thread::sleep`,
    ///    so the request task was never polled before SIGTERM fired. It lost
    ///    its own race in every observed run, and the failure looked exactly
    ///    like the drain defect it was meant to detect
    ///    (audit 2026-08-28 §4.11#10, §4.12#11).
    /// 2. Writing the request from the test thread and sleeping 20 ms fixed the
    ///    starvation but kept a race: on a box saturated by the full suite the
    ///    server was not scheduled to read the request within 20 ms, hyper saw
    ///    an idle connection at shutdown, and the read returned
    ///    `ConnectionReset`.
    ///
    /// This form waits for the server to log `started processing request`
    /// before signalling. The connection is then provably serving a request,
    /// not idle, so the drain must wait for it however loaded the box is.
    #[cfg(feature = "dev-endpoints")]
    #[test]
    fn sigterm_does_not_abort_inflight_http_request() {
        let port = find_available_port();
        let mut child = start_server_dev_traced(port);
        let request_started = watch_for_request_start(&mut child);

        assert!(
            wait_for_server(port, Duration::from_secs(20)),
            "server should accept TCP connections within 20 s"
        );

        let pid = child.id();

        // Connect and write the whole request from this thread. `connect`
        // returns only once the server has accepted the connection, and
        // `write_all` + `flush` put the request bytes on the socket.
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to server");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("set read timeout");
        let request = format!(
            "POST /admin/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .expect("write bootstrap request");
        stream.flush().expect("flush bootstrap request");

        // Block until the server reports that the request has entered its
        // pipeline. /admin/bootstrap then performs Argon2id hashing, so the
        // request is still in flight when the drain begins.
        request_started
            .recv_timeout(Duration::from_secs(30))
            .expect("server must log that it started processing the bootstrap request");

        send_sigterm(pid);

        // The in-flight request must complete — not get a TCP reset.
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect(
            "in-flight bootstrap request must complete cleanly during graceful drain; \
             a read error here means SIGTERM aborted the request",
        );
        let head = String::from_utf8_lossy(&response);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "bootstrap should return 200 when the server drains cleanly, got: {}",
            head.lines().next().unwrap_or("<empty response>")
        );

        // Process must exit 0 within the drain deadline + buffer.
        let status = wait_for_exit(&mut child, Duration::from_secs(15));
        assert_eq!(
            status.code(),
            Some(0),
            "SIGTERM must produce exit code 0 after the drain completes"
        );
    }

    // === GA audit 2026-09-28 L24: every listener drains at once ===

    /// The gRPC listener must stop accepting at the signal, not after HTTP has
    /// finished draining.
    ///
    /// `main.rs` used to signal gRPC only once the HTTP drain returned, so
    /// gRPC kept accepting new work for the whole HTTP drain, and the worst
    /// case shutdown was twice `operational.shutdown_timeout_secs`.
    ///
    /// An HTTP request whose body never finishes holds the HTTP drain open for
    /// the full deadline; during that window a new gRPC connection must be
    /// refused.
    #[cfg(feature = "dev-endpoints")]
    #[test]
    fn grpc_stops_accepting_at_the_signal_while_http_still_drains() {
        let port = find_available_port();
        let grpc_port = find_available_port();
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("hearth.yaml");
        std::fs::write(
            &config_path,
            format!(
                "server:\n  grpc_port: {grpc_port}\noperational:\n  shutdown_timeout_secs: 6\n"
            ),
        )
        .expect("write config");

        let mut child = Command::new(hearth_bin())
            .args(["serve", "--dev", "--port", &port.to_string(), "-c"])
            .arg(&config_path)
            .env("RUST_LOG", "warn,tower_http::trace=debug")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn hearth server");
        let request_started = watch_for_request_start(&mut child);
        assert!(
            wait_for_server(port, Duration::from_secs(20)),
            "HTTP listener should come up"
        );
        assert!(
            wait_for_server(grpc_port, Duration::from_secs(20)),
            "gRPC listener should come up"
        );

        // A request whose body never arrives keeps the HTTP drain busy.
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
        stream
            .write_all(
                format!(
                    "POST /token HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
                     Content-Type: application/x-www-form-urlencoded\r\n\
                     Content-Length: 100\r\n\r\ngrant_type="
                )
                .as_bytes(),
            )
            .expect("write partial request");
        stream.flush().expect("flush");
        request_started
            .recv_timeout(Duration::from_secs(30))
            .expect("server must start processing the partial request");

        send_sigterm(child.id());
        // The HTTP drain (6 s) keeps the process alive far longer than this wait.
        // AUDIT: justified-sleep: lets the SIGTERM handler run before probing gRPC (L24).
        std::thread::sleep(Duration::from_millis(1500));

        let grpc_accepts = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{grpc_port}").parse().expect("addr"),
            Duration::from_secs(1),
        )
        .is_ok();
        let http_still_draining = child.try_wait().expect("try_wait").is_none();
        let _ = child.kill();
        let _ = child.wait();
        drop(stream);

        assert!(
            http_still_draining,
            "the HTTP drain should still be waiting on the unfinished request"
        );
        assert!(
            !grpc_accepts,
            "the gRPC listener still accepted a new connection after SIGTERM while HTTP \
             was draining — gRPC must start draining at the signal, not after HTTP"
        );
    }
}

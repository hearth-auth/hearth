//! #445: a `heap-profile` build writes jemalloc heap profiles while it serves.
//!
//! A memory soak runs such a build with `_RJEM_MALLOC_CONF=prof:true,...` and
//! compares the profiles from before and after a step in its memory floor: the
//! call stacks whose live heap grew hold the memory. Only a build with
//! `--features heap-profile` compiles this file (loadtest/live/README.md,
//! "Heap accounting").
#![cfg(all(
    feature = "heap-profile",
    not(any(target_env = "msvc", hearth_system_allocator))
))]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Kills the server when the test ends, whatever the outcome.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The heap profiles in `dir`, in name order (jemalloc numbers them).
fn heap_profiles(dir: &Path) -> Vec<PathBuf> {
    let mut profiles: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read the profile directory")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "heap"))
        .collect();
    profiles.sort();
    profiles
}

/// With the profiler on and a 1-second interval, the server writes a profile
/// every second. Two profiles show that the dumps repeat.
#[test]
fn a_profiling_server_writes_a_heap_profile_each_interval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = TcpListener::bind("127.0.0.1:0")
        .expect("bind to port 0")
        .local_addr()
        .expect("local addr")
        .port();
    let config = dir.path().join("hearth.yaml");
    std::fs::write(
        &config,
        format!(
            "storage:\n  data_dir: \"{}\"\n",
            dir.path().join("data").display()
        ),
    )
    .expect("write config");
    let conf = format!(
        "prof:true,lg_prof_sample:16,prof_prefix:{}",
        dir.path().join("hearth").display()
    );
    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_hearth"))
            .args(["serve", "--dev", "--port", &port.to_string(), "--config"])
            .arg(&config)
            .env("_RJEM_MALLOC_CONF", conf)
            .env("HEARTH_HEAP_PROFILE_INTERVAL_SECS", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn hearth serve"),
    );

    // Below nextest's 60 s kill, so a failure reports its own message.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut profiles = heap_profiles(dir.path());
    while profiles.len() < 2 && Instant::now() < deadline {
        // AUDIT: justified-sleep: polls for files that the server process writes; bounded by the deadline (#445).
        std::thread::sleep(Duration::from_millis(200));
        profiles = heap_profiles(dir.path());
    }
    assert!(
        profiles.len() >= 2,
        "{} heap profiles in 20 s at a 1 s interval: {profiles:?}",
        profiles.len()
    );
    // jemalloc finished the first file before it started the second.
    let first = std::fs::read_to_string(&profiles[0]).expect("read the first profile");
    assert!(
        first.starts_with("heap_v2/"),
        "{} is not a jemalloc heap profile: {:?}",
        profiles[0].display(),
        first.lines().next()
    );
}

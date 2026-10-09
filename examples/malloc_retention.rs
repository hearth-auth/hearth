//! How much freed memory glibc keeps in its arenas under a login-like load,
//! with and without a fixed mmap threshold or a periodic `malloc_trim(0)`.
//!
//! ## Why this exists
//!
//! A 35-minute live soak (2026-10-09, AWS `c7i.large`, issue #445) found 880 MB
//! free inside glibc's two arenas for ~1.17 GB of live heap; one
//! `malloc_trim(0)` gave 465 MB back. The suspect is glibc's dynamic mmap
//! threshold: once a large mmapped block is freed, glibc raises the threshold
//! to that block's size, so every later 19 MiB Argon2 buffer comes from an
//! arena, where small allocations fragment the space it leaves behind.
//!
//! This binary runs that shape of load in one process, with glibc capped at two
//! arenas as Hearth does at startup:
//!
//! * hasher threads run Argon2id at Hearth's default cost (m=19456 KiB, t=2,
//!   p=1), which allocates and frees a 19 MiB buffer per hash;
//! * worker threads keep a bounded live set of small and medium objects and
//!   replace them at random, as request handling does, and add a few entries
//!   that stay, as a filling cache does.
//!
//! Every few seconds it prints resident memory and glibc's `mallinfo2`
//! figures; at the end it prints Argon2 wall and CPU time percentiles (CPU
//! time includes the kernel's page-fault work, and is less sensitive to other
//! load on the host than wall time).
//!
//! Measured 2026-10-09 (12-core Linux workstation shared with other builds,
//! glibc 2.42, THP `madvise`; 5 minutes, modes run side by side on their own
//! two cores; CPU per hash is per-thread CPU time):
//!
//! | mode                                    | RSS    | free in arenas | CPU/hash p50 |
//! |-----------------------------------------|--------|----------------|--------------|
//! | `default`                               | 432 MB | 199 MB         | 40.7 ms      |
//! | `trim=60` (pauses up to 118 ms)         | 416 MB | 187 MB         | 40.1 ms      |
//! | `threshold=1048576`                     | 437 MB | 184 MB         | 55.1 ms      |
//! | `threshold=131072`                      | 227 MB | 38 MB          | 55.5 ms      |
//! | `threshold=131072` + `hugetlb=1` tunable | 221 MB | 34 MB          | 38.9 ms      |
//!
//! Above the threshold the workers' 16–256 KiB objects still come from the
//! arenas, which is why 1 MiB does not help here. Hashing alone (`0` workers,
//! 5 alternating 20 s runs), CPU per hash p50 was 20.7–28.2 ms by default,
//! 29.7–35.4 ms at `threshold=131072`, and 21.1–25.5 ms with the `hugetlb=1`
//! tunable added (`GLIBC_TUNABLES=glibc.malloc.hugetlb=1`).
//!
//! Run: `cargo run --release --example malloc_retention -- <seconds> <mode> [workers]`
//! where `<mode>` is one of:
//!
//! * `default` — glibc's dynamic mmap threshold;
//! * `threshold=<bytes>` — `mallopt(M_MMAP_THRESHOLD, bytes)` at startup;
//! * `trim=<seconds>` — a thread calls `malloc_trim(0)` at this interval;
//! * both, comma-separated: `threshold=1048576,trim=60`.
//!
//! `[workers]` defaults to 6; `0` leaves only the hashers, to time Argon2 alone.
//!
//! Linux with glibc only; elsewhere it prints a notice and exits.
// Example/measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn main() {
    glibc::run();
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn main() {
    println!("malloc_retention measures glibc malloc; it runs on Linux with glibc only");
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod glibc {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use argon2::{Algorithm, Argon2, Params, Version};

    const HASHERS: usize = 2;
    const WORKERS: usize = 6;
    /// Live objects per worker thread. With the size mix below this holds
    /// ~150 MB of live heap across all workers.
    const LIVE_SLOTS: usize = 3_000;
    /// A worker caches one long-lived entry every this many batches.
    const CACHE_ONE_IN: u64 = 4;
    const SAMPLE_EVERY: Duration = Duration::from_secs(5);

    /// The allocator settings under test; both may be set.
    #[derive(Default)]
    struct Mode {
        threshold: Option<usize>,
        trim_every: Option<u64>,
    }

    fn parse_mode(arg: &str) -> Mode {
        let mut mode = Mode::default();
        for part in arg.split(',') {
            if let Some(bytes) = part.strip_prefix("threshold=") {
                mode.threshold = Some(bytes.parse().expect("threshold=<bytes>"));
            } else if let Some(secs) = part.strip_prefix("trim=") {
                mode.trim_every = Some(secs.parse().expect("trim=<seconds>"));
            } else {
                assert_eq!(
                    part, "default",
                    "mode: default | threshold=<bytes> | trim=<seconds>"
                );
            }
        }
        mode
    }

    /// xorshift64*: enough randomness for a size mix, no dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// A request-shaped allocation size: mostly small, some buffers, a few
    /// response bodies or SST blocks.
    fn object_size(rng: &mut Rng) -> usize {
        match rng.below(100) {
            0..=69 => 16 + rng.below(496) as usize,
            70..=96 => 512 + rng.below(16 * 1024) as usize,
            _ => 16 * 1024 + rng.below(240 * 1024) as usize,
        }
    }

    fn resident_bytes() -> u64 {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
        let pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        pages * 4096
    }

    const MIB: f64 = 1024.0 * 1024.0;

    fn sample(start: Instant) {
        // SAFETY: `mallinfo2` only reads allocator statistics.
        let info = unsafe { libc::mallinfo2() };
        println!(
            "{:>5}s  rss {:>7.1}  arena {:>7.1}  free-in-arena {:>7.1}  in-use {:>7.1}  mmapped {:>6.1}",
            start.elapsed().as_secs(),
            resident_bytes() as f64 / MIB,
            info.arena as f64 / MIB,
            info.fordblks as f64 / MIB,
            info.uordblks as f64 / MIB,
            info.hblkhd as f64 / MIB,
        );
    }

    /// CPU time this thread has used, kernel time (page faults) included.
    fn thread_cpu_time() -> Duration {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid out-pointer for the call's duration.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }

    /// Wall and CPU time of each hash.
    fn hasher(stop: &AtomicBool, seed: u64) -> Vec<(Duration, Duration)> {
        let params = Params::new(19_456, 2, 1, Some(32)).expect("argon2 params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = seed.to_le_bytes().repeat(2);
        let mut out = [0_u8; 32];
        let mut times = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            let (t, cpu) = (Instant::now(), thread_cpu_time());
            argon2
                .hash_password_into(b"correct horse battery staple", &salt, &mut out)
                .expect("argon2 hash");
            times.push((t.elapsed(), thread_cpu_time().saturating_sub(cpu)));
        }
        times
    }

    fn worker(stop: &AtomicBool, seed: u64) {
        let mut rng = Rng(seed | 1);
        let mut live: Vec<Vec<u8>> = (0..LIVE_SLOTS).map(|_| Vec::new()).collect();
        // Entries that stay for the whole run, as a filling cache's do.
        let mut cached: Vec<Vec<u8>> = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            if rng.below(CACHE_ONE_IN) == 0 {
                cached.push(vec![3_u8; 200 + rng.below(1_300) as usize]);
            }
            for _ in 0..200 {
                let slot = rng.below(LIVE_SLOTS as u64) as usize;
                live[slot] = vec![1_u8; object_size(&mut rng)];
                // A short-lived request buffer, freed at once.
                let scratch = vec![2_u8; object_size(&mut rng)];
                std::hint::black_box(&scratch);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    pub(super) fn run() {
        let mut args = std::env::args().skip(1);
        let seconds: u64 = args.next().map_or(120, |s| s.parse().expect("<seconds>"));
        let mode = parse_mode(&args.next().unwrap_or_else(|| "default".to_owned()));
        let workers: usize = args
            .next()
            .map_or(WORKERS, |s| s.parse().expect("[workers]"));

        // SAFETY: process-wide allocator parameters, set before any thread starts.
        assert_eq!(unsafe { libc::mallopt(libc::M_ARENA_MAX, 2) }, 1);
        if let Some(bytes) = mode.threshold {
            let bytes = libc::c_int::try_from(bytes).expect("threshold fits a C int");
            // SAFETY: as above.
            assert_eq!(unsafe { libc::mallopt(libc::M_MMAP_THRESHOLD, bytes) }, 1);
            println!("fixed mmap threshold: {bytes} bytes");
        } else {
            println!("mmap threshold: glibc's dynamic default");
        }
        if let Some(secs) = mode.trim_every {
            println!("malloc_trim(0) every {secs} s");
        }

        let stop = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let hashers: Vec<_> = (0..HASHERS)
            .map(|i| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || hasher(&stop, i as u64 + 1))
            })
            .collect();
        let workers: Vec<_> = (0..workers)
            .map(|i| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || worker(&stop, 0x9e37_79b9 * (i as u64 + 1)))
            })
            .collect();
        let trimmer = if let Some(secs) = mode.trim_every {
            let stop = Arc::clone(&stop);
            Some(std::thread::spawn(move || {
                let mut pauses = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_secs(secs));
                    let t = Instant::now();
                    // SAFETY: `malloc_trim` takes the arena locks itself.
                    unsafe { libc::malloc_trim(0) };
                    pauses.push(t.elapsed());
                }
                pauses
            }))
        } else {
            None
        };

        let deadline = start + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            std::thread::sleep(SAMPLE_EVERY.min(deadline - Instant::now()));
            sample(start);
        }
        stop.store(true, Ordering::Relaxed);
        for w in workers {
            w.join().expect("worker");
        }
        let times: Vec<(Duration, Duration)> = hashers
            .into_iter()
            .flat_map(|h| h.join().expect("hasher"))
            .collect();
        let pct = |mut v: Vec<Duration>, p: f64| {
            v.sort_unstable();
            v[((v.len() - 1) as f64 * p) as usize].as_secs_f64() * 1e3
        };
        let wall: Vec<Duration> = times.iter().map(|t| t.0).collect();
        let cpu: Vec<Duration> = times.iter().map(|t| t.1).collect();
        println!(
            "argon2: {} hashes; wall p50 {:.2} ms, p99 {:.2} ms; cpu p50 {:.2} ms, p99 {:.2} ms",
            times.len(),
            pct(wall.clone(), 0.5),
            pct(wall, 0.99),
            pct(cpu.clone(), 0.5),
            pct(cpu, 0.99),
        );
        if let Some(trimmer) = trimmer {
            let pauses = trimmer.join().expect("trimmer");
            let max = pauses.iter().max().copied().unwrap_or_default();
            println!(
                "malloc_trim: {} calls, longest {:.1} ms",
                pauses.len(),
                max.as_secs_f64() * 1e3
            );
        }
    }
}

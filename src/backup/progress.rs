//! Progress lines of a restore (#912).
//!
//! A restore of a large realm runs for many minutes in two passes over the
//! archive: the check pass reads every record before the first write, and
//! the import pass writes them. Without a line between the start and the
//! summary, an operator cannot tell a slow restore from a stuck one. A
//! [`RestoreProgress`] logs, at a fixed interval, the records each pass has
//! handled, the rate and the elapsed time. It logs counts, rates and archive
//! member names only: never a record's content.

use std::time::{Duration, Instant};

use tracing::info;

/// How often a restore logs its progress.
pub(crate) const RESTORE_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// One progress line of a pass: counts and rates only.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ProgressLine {
    /// Records the pass has handled so far.
    pub(crate) records: u64,
    /// Time since the pass started.
    pub(crate) elapsed: Duration,
    /// Records per second since the previous line (or the start).
    pub(crate) rate: f64,
}

/// Counts the records of one pass of a restore and logs its progress every
/// interval.
pub(crate) struct RestoreProgress {
    /// The pass: `check` or `import`.
    pass: &'static str,
    /// The archive member the pass is in.
    member: String,
    interval: Duration,
    started: Instant,
    /// When the previous line was logged (or the pass started).
    last_at: Instant,
    /// Records at the previous line.
    last_records: u64,
    records: u64,
}

impl RestoreProgress {
    /// The progress of `pass`, starting now, with a line every `interval`.
    pub(crate) fn new(pass: &'static str, interval: Duration) -> Self {
        Self::starting_at(pass, interval, Instant::now())
    }

    /// The progress of `pass`, started at `now`.
    fn starting_at(pass: &'static str, interval: Duration, now: Instant) -> Self {
        Self {
            pass,
            member: String::new(),
            interval,
            started: now,
            last_at: now,
            last_records: 0,
            records: 0,
        }
    }

    /// The pass moves on to the archive member `member`.
    pub(crate) fn member(&mut self, member: &str) {
        self.member.clear();
        self.member.push_str(member);
    }

    /// Counts `n` more records, and logs a progress line when an interval
    /// has passed since the previous one.
    pub(crate) fn add(&mut self, n: u64) {
        if let Some(line) = self.observe(n, Instant::now()) {
            info!(
                pass = self.pass,
                member = self.member.as_str(),
                records = line.records,
                rate_per_s = line.rate.round(),
                elapsed_s = line.elapsed.as_secs(),
                "restore progress"
            );
        }
    }

    /// Logs the totals of the pass.
    pub(crate) fn finish(&self) {
        let elapsed = self.started.elapsed();
        info!(
            pass = self.pass,
            records = self.records,
            rate_per_s = rate(self.records, elapsed).round(),
            elapsed_s = elapsed.as_secs(),
            "restore pass done"
        );
    }

    /// Counts `n` more records at `now`, and returns the line to log when an
    /// interval has passed since the previous line.
    fn observe(&mut self, n: u64, now: Instant) -> Option<ProgressLine> {
        self.records += n;
        let since_last = now.saturating_duration_since(self.last_at);
        if since_last < self.interval {
            return None;
        }
        let line = ProgressLine {
            records: self.records,
            elapsed: now.saturating_duration_since(self.started),
            rate: rate(self.records - self.last_records, since_last),
        };
        self.last_at = now;
        self.last_records = self.records;
        Some(line)
    }
}

/// `records` per second over `elapsed`; zero over no time.
fn rate(records: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 {
        #[allow(clippy::cast_precision_loss)] // a rate, not a count
        let records = records as f64;
        records / secs
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_comes_once_per_interval_with_the_count_and_the_rate() {
        let start = Instant::now();
        let mut progress = RestoreProgress::starting_at("import", Duration::from_secs(10), start);

        assert_eq!(progress.observe(500, start + Duration::from_secs(4)), None);
        assert_eq!(progress.observe(500, start + Duration::from_secs(9)), None);
        let first = progress
            .observe(1_000, start + Duration::from_secs(10))
            .expect("a line once 10 s have passed");
        assert_eq!(first.records, 2_000);
        assert_eq!(first.elapsed, Duration::from_secs(10));
        assert!((first.rate - 200.0).abs() < 1e-9, "rate {}", first.rate);

        // The next interval counts from the first line, not from the start.
        assert_eq!(
            progress.observe(3_000, start + Duration::from_secs(19)),
            None
        );
        let second = progress
            .observe(0, start + Duration::from_secs(20))
            .expect("a line at 20 s");
        assert_eq!(second.records, 5_000);
        assert_eq!(second.elapsed, Duration::from_secs(20));
        assert!((second.rate - 300.0).abs() < 1e-9, "rate {}", second.rate);
    }

    #[test]
    fn a_pass_shorter_than_the_interval_logs_no_progress_line() {
        let start = Instant::now();
        let mut progress = RestoreProgress::starting_at("check", Duration::from_secs(10), start);
        for s in 0..10 {
            assert_eq!(progress.observe(100, start + Duration::from_secs(s)), None);
        }
        assert_eq!(progress.records, 1_000);
    }

    #[test]
    fn the_rate_over_no_time_is_zero() {
        assert!(rate(10, Duration::ZERO).abs() < f64::EPSILON);
        assert!((rate(10, Duration::from_secs(2)) - 5.0).abs() < 1e-9);
    }
}

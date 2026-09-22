//! Spamhaus DROP / EDROP reference adapter for [`IpReputationProvider`].
//!
//! # What it blocks
//!
//! - **DROP** (`drop.txt`) — the Spamhaus "Don't Route Or Peer" list.  IPv4
//!   CIDR ranges allocated to spam operations, hijacked netblocks, and other
//!   definitely-hostile infrastructure.
//! - **EDROP** (`dropv6.txt`) — the Spamhaus "Extended DROP" IPv6 equivalent.
//!
//! Both lists are parsed into a single [`CidrFilter`] held behind a
//! [`SwapCell`].  A lookup clones one `Arc` and then does a linear scan over
//! the in-memory CIDR list.  This is a reputation check on the abuse path,
//! not the auth hot path (`validate_token` / `lookup_session` /
//! `lookup_user`), so the read lock a [`SwapCell`] load takes is permitted.
//! It replaced `arc_swap::ArcSwap` in task 26.5; see [`SwapCell`] for why.
//!
//! # Background refresh
//!
//! Call [`SpamhausDropProvider::spawn_refresh`] from async startup code to
//! start a background Tokio task that downloads fresh lists from the configured
//! URLs every [`SpamhausDropConfig::refresh_interval_secs`] seconds.  On each
//! successful download the provider atomically replaces the live filter via
//! [`SpamhausDropProvider::reload`].
//!
//! If a download fails, the previous list is retained and a `tracing::warn`
//! event is emitted.  The task never panics.
//!
//! # Failure mode: fail-open
//!
//! An empty filter (both DROP and EDROP lists absent or all-comment) always
//! returns a clean verdict.  Providers start with an empty filter and become
//! populated only after the first successful refresh.
//!
//! # DROP list text format
//!
//! ```text
//! ; comment lines start with ';' and are ignored
//! 1.10.16.0/20 ; SBL000001
//! 192.0.2.0/24 ; SBL000002
//! ```
//!
//! Each non-comment, non-blank line has the form `CIDR ; SBLnnnnn [; note]`.
//! Only the CIDR part (before the first `;` or end-of-line) is used; the SBL
//! reference is ignored.  Lines that cannot be parsed as a CIDR are silently
//! skipped (fail-open).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::abuse::cidr::{Cidr, CidrFilter};
use crate::abuse::ip_reputation::{IpReputationProvider, IpReputationVerdict};
use crate::core::SwapCell;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`SpamhausDropProvider`].
///
/// Serialised under `security.ip_reputation.spamhaus` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct SpamhausDropConfig {
    /// URL for the Spamhaus DROP (IPv4) list.
    ///
    /// Default: `https://www.spamhaus.org/drop/drop.txt`
    pub drop_url: String,
    /// URL for the Spamhaus EDROP (IPv6) list.
    ///
    /// Default: `https://www.spamhaus.org/drop/dropv6.txt`
    pub dropv6_url: String,
    /// How often to refresh the lists (seconds).  Default: 86 400 (24 hours).
    pub refresh_interval_secs: u64,
}

impl Default for SpamhausDropConfig {
    fn default() -> Self {
        Self {
            drop_url: "https://www.spamhaus.org/drop/drop.txt".into(),
            dropv6_url: "https://www.spamhaus.org/drop/dropv6.txt".into(),
            refresh_interval_secs: 86_400,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────────────────────────────────────

/// Spamhaus DROP / EDROP reference adapter.
///
/// Implements [`IpReputationProvider`] using an Arc-swapped [`CidrFilter`] for
/// zero-allocation, lock-free lookups on the hot path.
///
/// # Usage
///
/// ```rust,ignore
/// // From static text (e.g. in tests or when lists are bundled in config):
/// let provider = SpamhausDropProvider::from_text(drop_txt, dropv6_txt);
///
/// // In production, start empty and spawn the daily refresh task:
/// let provider = Arc::new(SpamhausDropProvider::empty());
/// provider.spawn_refresh(SpamhausDropConfig::default());
/// ```
pub struct SpamhausDropProvider {
    /// Swappable CIDR filter.  Readers never block readers; replaced
    /// atomically on each successful refresh.
    filter: Arc<SwapCell<CidrFilter>>,
}

impl SpamhausDropProvider {
    /// Creates a provider pre-populated from the given DROP and EDROP list text.
    ///
    /// This constructor does not spawn any background tasks and does not make
    /// network requests.  It is the recommended constructor for tests.
    ///
    /// Malformed or unparseable CIDR lines in the list text are silently
    /// skipped (fail-open).
    ///
    /// # Parameters
    ///
    /// - `drop_text`  — content of `drop.txt` (IPv4 CIDRs).
    /// - `dropv6_text` — content of `dropv6.txt` (IPv6 CIDRs).
    #[must_use]
    pub fn from_text(drop_text: &str, dropv6_text: &str) -> Self {
        let filter = build_filter(drop_text, dropv6_text);
        Self {
            filter: Arc::new(SwapCell::from_pointee(filter)),
        }
    }

    /// Creates a provider with an empty (fail-open) filter.
    ///
    /// Call [`spawn_refresh`][Self::spawn_refresh] to start the background
    /// task that populates the filter from the configured URLs.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            filter: Arc::new(SwapCell::from_pointee(CidrFilter::empty())),
        }
    }

    /// Atomically replaces the current filter with one built from the given
    /// DROP and EDROP list text.
    ///
    /// This is called by the background refresh task but is also useful for
    /// manual refresh in integration tests.  Concurrent `check()` calls are
    /// not blocked — they complete against the old filter until the swap
    /// completes.
    pub fn reload(&self, drop_text: &str, dropv6_text: &str) {
        let new_filter = build_filter(drop_text, dropv6_text);
        self.filter.store(Arc::new(new_filter));
    }

    /// Spawns a background Tokio task that periodically downloads fresh DROP
    /// and EDROP lists from the configured URLs and atomically reloads the
    /// provider.
    ///
    /// Must be called from within a Tokio runtime context.
    ///
    /// The task:
    /// 1. Fires immediately on spawn (first refresh before the first interval).
    /// 2. Then fires every `config.refresh_interval_secs` seconds.
    /// 3. On any network or parse failure, logs a warning and keeps the
    ///    previous filter — the provider never becomes less restrictive due to
    ///    a transient error.
    pub fn spawn_refresh(self: &Arc<Self>, config: SpamhausDropConfig) {
        let provider = Arc::clone(self);
        tokio::spawn(async move {
            // Fire immediately, then on the configured interval.
            refresh_once(&provider, &config).await;
            let mut ticker =
                tokio::time::interval(Duration::from_secs(config.refresh_interval_secs));
            ticker.tick().await; // consume the immediate tick
            loop {
                ticker.tick().await;
                refresh_once(&provider, &config).await;
            }
        });
    }
}

impl IpReputationProvider for SpamhausDropProvider {
    /// Checks whether `ip` falls within any Spamhaus DROP or EDROP CIDR.
    ///
    /// Loads the current filter snapshot via [`SwapCell::load`] and performs a
    /// linear scan.  Returns a clean verdict if the filter is empty
    /// (fail-open) or if the IP does not match any CIDR.
    fn check(&self, ip: IpAddr) -> IpReputationVerdict {
        use crate::abuse::cidr::CidrOutcome;
        let guard = self.filter.load();
        let is_blocklisted = guard.check(ip) == CidrOutcome::Deny;
        IpReputationVerdict {
            is_blocklisted,
            ..Default::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses both DROP (IPv4) and EDROP (IPv6) list text into a single
/// [`CidrFilter`] deny list.
///
/// Lines starting with `;` are comments and are skipped.  Blank lines are
/// skipped.  For data lines, only the text before the first `;` is used as the
/// CIDR.  Lines that cannot be parsed as a valid CIDR are silently skipped.
fn build_filter(drop_text: &str, dropv6_text: &str) -> CidrFilter {
    let mut deny: Vec<Cidr> = Vec::new();
    for line in drop_text.lines().chain(dropv6_text.lines()) {
        parse_drop_line(line, &mut deny);
    }
    debug!(cidr_count = deny.len(), "Spamhaus DROP filter built");
    CidrFilter::new(Vec::new(), deny)
}

/// Parses a single DROP list line into `out`, ignoring comments and blanks.
fn parse_drop_line(line: &str, out: &mut Vec<Cidr>) {
    // Trim whitespace; skip blank lines.
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }
    // Skip comment lines.
    if trimmed.starts_with(';') {
        return;
    }
    // Take the portion before the first `;` (the CIDR column).
    let cidr_part = trimmed.split(';').next().unwrap_or(trimmed).trim();
    if cidr_part.is_empty() {
        return;
    }
    match Cidr::parse(cidr_part) {
        Ok(cidr) => out.push(cidr),
        Err(_) => {
            // Silently skip unparseable lines (fail-open for malformed input).
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background refresh helper
// ─────────────────────────────────────────────────────────────────────────────

/// Downloads and reloads one iteration of both DROP and EDROP lists.
async fn refresh_once(provider: &SpamhausDropProvider, config: &SpamhausDropConfig) {
    let drop_url = config.drop_url.clone();
    let dropv6_url = config.dropv6_url.clone();

    let result = tokio::task::spawn_blocking(move || {
        let drop_text = fetch_url(&drop_url)?;
        let dropv6_text = fetch_url(&dropv6_url)?;
        Ok::<(String, String), String>((drop_text, dropv6_text))
    })
    .await;

    match result {
        Ok(Ok((drop_text, dropv6_text))) => {
            provider.reload(&drop_text, &dropv6_text);
            debug!("Spamhaus DROP lists refreshed successfully");
        }
        Ok(Err(e)) => {
            warn!(error = %e, "Spamhaus DROP refresh failed; retaining previous list");
        }
        Err(e) => {
            warn!(error = %e, "Spamhaus DROP refresh task panicked; retaining previous list");
        }
    }
}

/// Connect timeout for a DROP-list refresh.
const SPAMHAUS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Total request timeout for a DROP-list refresh.
///
/// Longer than the provider-egress default because the DROP lists are a few
/// hundred kilobytes and this runs on a background refresh, not a request.
const SPAMHAUS_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds the `ureq` config for a DROP-list refresh.
///
/// # Task 26.37
///
/// This used bare `ureq::get`, and ureq 3.3.0's `Timeouts::default()` leaves
/// every field `None` except `await_100`.
///
/// Milder than its siblings, and worth saying why rather than implying
/// equivalence: this runs inside `spawn_blocking`, so a hung endpoint occupies
/// a blocking-pool thread rather than a Tokio *worker*. It still leaks one
/// thread per refresh interval, permanently, and the refresh loop's
/// "retaining previous list" recovery never fires because the call never
/// returns to report a failure.
fn spamhaus_agent_config() -> ureq::config::Config {
    ureq::config::Config::builder()
        .timeout_connect(Some(SPAMHAUS_CONNECT_TIMEOUT))
        .timeout_global(Some(SPAMHAUS_REQUEST_TIMEOUT))
        .max_redirects(crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS)
        .build()
}

/// Blocking HTTP GET using `ureq`.  Must be called inside `spawn_blocking`.
fn fetch_url(url: &str) -> Result<String, String> {
    let agent = ureq::Agent::new_with_config(spamhaus_agent_config());
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("HTTP GET {url} failed: {e}"))?;

    let status: u16 = resp.status().into();
    if status != 200 {
        return Err(format!("HTTP GET {url} returned status {status}"));
    }

    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("reading response body from {url}: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (inline)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod egress_bound_tests {
    use super::*;

    /// Task 26.37 — a hung DROP-list endpoint must not leak a thread forever.
    ///
    /// The fetch used bare `ureq::get`, and ureq 3.3.0's `Timeouts::default()`
    /// leaves every field `None` except `await_100`. This runs inside
    /// `spawn_blocking`, so it costs a blocking-pool thread rather than a Tokio
    /// worker — milder than its siblings, but still one thread per refresh
    /// interval, permanently. The refresh loop's "retaining previous list"
    /// recovery cannot fire either, because the call never returns to report a
    /// failure.
    #[test]
    fn spamhaus_agent_config_bounds_both_timeouts() {
        let timeouts = spamhaus_agent_config().timeouts();
        assert_eq!(
            timeouts.connect,
            Some(SPAMHAUS_CONNECT_TIMEOUT),
            "DROP-list refresh must bound connect time"
        );
        assert_eq!(
            timeouts.global,
            Some(SPAMHAUS_REQUEST_TIMEOUT),
            "DROP-list refresh must bound total request time"
        );
        assert!(
            SPAMHAUS_REQUEST_TIMEOUT > SPAMHAUS_CONNECT_TIMEOUT,
            "the DROP lists are hundreds of kilobytes; the overall budget must \
             leave room to read them after connecting"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    const SAMPLE_DROP: &str = "\
; Spamhaus DROP List
1.10.16.0/20 ; SBL000001
192.0.2.0/24 ; SBL000002
";

    #[test]
    fn parse_valid_drop_line() {
        let mut out = Vec::new();
        parse_drop_line("1.10.16.0/20 ; SBL000001", &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn parse_comment_line_skipped() {
        let mut out = Vec::new();
        parse_drop_line("; this is a comment", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_blank_line_skipped() {
        let mut out = Vec::new();
        parse_drop_line("   ", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_malformed_cidr_skipped() {
        let mut out = Vec::new();
        parse_drop_line("not-a-cidr ; SBL000001", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn from_text_ip_in_drop_is_blocklisted() {
        let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
        assert!(p.check(v4(1, 10, 16, 1)).is_blocklisted);
    }

    #[test]
    fn from_text_ip_outside_drop_is_clean() {
        let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
        assert!(p.check(v4(8, 8, 8, 8)).is_clean());
    }

    #[test]
    fn empty_provider_fails_open() {
        let p = SpamhausDropProvider::empty();
        assert!(p.check(v4(1, 10, 16, 1)).is_clean());
    }

    /// Shares `192.0.2.0/24` with [`SAMPLE_DROP`] and differs everywhere else,
    /// so one IP is blocklisted under *both* lists (a per-snapshot invariant a
    /// single `check` can assert) and two more distinguish which list is live.
    const OTHER_DROP: &str = "\
; Spamhaus DROP List
192.0.2.0/24 ; SBL000002
203.0.113.0/24 ; SBL000003
";

    /// `reload` must publish every list it is handed while `check` calls race
    /// it, with the last reload winning (task 26.5 — the `SwapCell` migration).
    ///
    /// A lost update leaves the provider answering from a superseded list,
    /// which is a silent policy regression: an operator who reloads a widened
    /// blocklist would keep admitting the addresses it added.
    #[test]
    fn concurrent_checks_never_miss_a_reload() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let provider = Arc::new(SpamhausDropProvider::from_text(SAMPLE_DROP, ""));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let provider = Arc::clone(&provider);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        // Each assertion reads exactly one snapshot, so a
                        // reload landing mid-loop cannot make it spuriously
                        // fail. `192.0.2.1` is blocklisted under both lists and
                        // `8.8.8.8` under neither, so a torn or empty snapshot
                        // breaks one of them.
                        assert!(
                            provider.check(v4(192, 0, 2, 1)).is_blocklisted,
                            "a snapshot dropped an entry both lists declare"
                        );
                        assert!(
                            provider.check(v4(8, 8, 8, 8)).is_clean(),
                            "a snapshot blocklisted an address neither list declares"
                        );
                    }
                })
            })
            .collect();

        for i in 0..200 {
            if i % 2 == 0 {
                provider.reload(SAMPLE_DROP, "");
            } else {
                provider.reload(OTHER_DROP, "");
            }
        }
        // 200 iterations, last index 199 is odd => OTHER_DROP was stored last.
        // OTHER_DROP is deliberately *not* the list the provider started on, so
        // a `reload` that builds the new filter but never publishes it leaves
        // SAMPLE_DROP live and fails the final assertions.
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        assert!(
            provider.check(v4(203, 0, 113, 1)).is_blocklisted,
            "the last reload was lost"
        );
        assert!(
            provider.check(v4(1, 10, 16, 1)).is_clean(),
            "a superseded list is still live"
        );
    }
}

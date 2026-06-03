//! Spamhaus DROP / EDROP reference adapter for [`IpReputationProvider`].
//!
//! # What it blocks
//!
//! - **DROP** (`drop.txt`) — the Spamhaus "Don't Route Or Peer" list.  IPv4
//!   CIDR ranges allocated to spam operations, hijacked netblocks, and other
//!   definitely-hostile infrastructure.
//! - **EDROP** (`dropv6.txt`) — the Spamhaus "Extended DROP" IPv6 equivalent.
//!
//! Both lists are parsed into a single [`CidrFilter`] held behind an
//! [`arc_swap::ArcSwap`].  Hot-path lookups call `ArcSwap::load()` (lock-free,
//! allocation-free on the read path) and then do a linear scan over the
//! in-memory CIDR list.
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

use arc_swap::ArcSwap;
use tracing::{debug, warn};

use crate::abuse::cidr::{Cidr, CidrFilter};
use crate::abuse::ip_reputation::{IpReputationProvider, IpReputationVerdict};

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
    /// Arc-swapped CIDR filter.  Lock-free on the read path; replaced atomically
    /// on each successful refresh.
    filter: Arc<ArcSwap<CidrFilter>>,
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
            filter: Arc::new(ArcSwap::from_pointee(filter)),
        }
    }

    /// Creates a provider with an empty (fail-open) filter.
    ///
    /// Call [`spawn_refresh`][Self::spawn_refresh] to start the background
    /// task that populates the filter from the configured URLs.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            filter: Arc::new(ArcSwap::from_pointee(CidrFilter::empty())),
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
    /// Lock-free: loads the current filter snapshot via [`ArcSwap::load`] and
    /// performs a linear scan.  Returns a clean verdict if the filter is empty
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

/// Blocking HTTP GET using `ureq`.  Must be called inside `spawn_blocking`.
fn fetch_url(url: &str) -> Result<String, String> {
    let resp = ureq::get(url)
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
}

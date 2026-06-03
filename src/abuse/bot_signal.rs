//! P-3 BotSignal — pluggable bot-signal trait + UA/JA3/JA4 heuristics adapter.
//!
//! # Design
//!
//! `BotSignalProvider` is the trait that every pluggable bot-signal backend
//! must implement.  The built-in [`HeuristicBotSignalProvider`] ships with
//! Hearth and covers two signal classes:
//!
//! 1. **User-Agent analysis** — woothee category + known scripting-client
//!    substrings + headless-browser markers.
//! 2. **JA3/JA4 header inspection** — checks proxy-injected TLS fingerprint
//!    hashes (`X-JA3-Hash` / `X-JA4-Hash`) against a configurable blocklist of
//!    well-known automated-scanner fingerprints.
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: `BotSignal` is **fail-open**.
//! If a provider implementation panics, encounters a poisoned lock, or loses
//! its backend, it MUST return [`BotSignalVerdict::Allow`] so legitimate users
//! are never blocked by a provider bug.  The hard rate limiter (A-2) and
//! account-lockout remain backstops.
//!
//! # Off hot-path
//!
//! Providers are consulted only at registration, forgot-password, and
//! magic-link flows — never during `validate_token()` or `lookup_session()`.
//! Latency budget is therefore relaxed (≤ 1 ms is fine; sub-µs not required).
//!
//! # Provider slot
//!
//! Wire an external adapter (Cloudflare Bot Management, Datadome, Kasada,
//! Akamai) by implementing [`BotSignalProvider`] and injecting it via the
//! abuse guard.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Input context passed to every [`BotSignalProvider::check`] call.
///
/// All fields are optional; providers MUST handle absent fields gracefully and
/// MUST NOT assume any field will be present.
#[derive(Debug, Clone)]
pub struct BotSignalContext<'a> {
    /// Value of the `User-Agent` request header, if present.
    pub user_agent: Option<&'a str>,

    /// JA3 TLS fingerprint hash injected by a terminating proxy
    /// (e.g. via `X-JA3-Hash`).  Only available when Hearth sits behind a
    /// proxy that extracts TLS ClientHello metadata.
    pub ja3_hash: Option<&'a str>,

    /// JA4 TLS fingerprint hash injected by a terminating proxy
    /// (e.g. via `X-JA4-Hash`).  JA4 is a newer, collision-resistant
    /// alternative to JA3 introduced by FoxIO.
    pub ja4_hash: Option<&'a str>,

    /// Client IP address, if known.  Not used by the heuristic adapter but
    /// available to external adapters that perform IP correlation.
    pub ip: Option<IpAddr>,
}

/// Verdict returned by a [`BotSignalProvider`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotSignalVerdict {
    /// Request appears human.  Proceed normally.
    Allow,

    /// Request carries bot-like signals but no confirmed automation.
    ///
    /// Recommended response: step-up challenge (CAPTCHA, rate-tighten).
    /// Do not outright deny without additional corroboration.
    Suspect {
        /// Human-readable reason for the suspect verdict (for logging only;
        /// MUST NOT be returned to the client verbatim).
        reason: &'static str,
    },

    /// Request is strongly identified as automated tooling.
    ///
    /// Recommended response: deny or tarpit (A-17).
    Block {
        /// Human-readable reason (for logging only; MUST NOT be returned to
        /// the client verbatim).
        reason: &'static str,
    },
}

impl BotSignalVerdict {
    /// `true` when the verdict is [`BotSignalVerdict::Allow`].
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// `true` when the verdict is [`BotSignalVerdict::Block`].
    #[must_use]
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

/// Pluggable bot-signal provider trait (P-3 extension point).
///
/// Implement this trait to integrate Cloudflare Bot Management, Datadome,
/// Kasada, Akamai Bot Manager, or a custom ML classifier.  The built-in
/// reference adapter [`HeuristicBotSignalProvider`] ships with Hearth.
///
/// # Contract
///
/// - `check()` MUST be synchronous (no I/O in the critical path).
///   External adapters that require network calls should cache results and
///   refresh asynchronously via a background task.
/// - `check()` MUST fail-open: return [`BotSignalVerdict::Allow`] on any
///   internal error so that legitimate users are never blocked.
/// - `check()` MUST NOT log tokens, passwords, or PII.
pub trait BotSignalProvider: Send + Sync {
    /// Evaluates the request context and returns a bot-signal verdict.
    fn check(&self, ctx: &BotSignalContext<'_>) -> BotSignalVerdict;
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op provider (fail-open default)
// ─────────────────────────────────────────────────────────────────────────────

/// No-op bot-signal provider.
///
/// Always returns [`BotSignalVerdict::Allow`].  This is the safe default for
/// deployments that have not yet configured a provider: no request is ever
/// blocked by this implementation.
pub struct NoopBotSignalProvider;

impl BotSignalProvider for NoopBotSignalProvider {
    fn check(&self, _ctx: &BotSignalContext<'_>) -> BotSignalVerdict {
        BotSignalVerdict::Allow
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Heuristic reference adapter
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`HeuristicBotSignalProvider`].
///
/// Serialised under `security.providers.bot_signal` in `hearth.yaml`.
#[derive(Debug, Clone, Default)]
pub struct BotSignalConfig {
    /// Additional JA3 hashes to block beyond the built-in blocklist.
    ///
    /// Each entry is a 32-character lowercase hex MD5 string.
    pub extra_ja3_blocklist: Vec<String>,

    /// Additional JA4 hashes (or prefixes) to block beyond the built-in
    /// blocklist.  JA4 strings are `t{version}{proto}` prefixed tuples;
    /// prefix matching (`starts_with`) is used if the entry is shorter than
    /// a full JA4 string.
    pub extra_ja4_blocklist: Vec<String>,
}

/// Built-in heuristic bot-signal adapter (P-3 reference implementation).
///
/// Applies three signal layers in priority order:
///
/// 1. **JA3/JA4 blocklist** — hashes injected by a terminating proxy.
///    A match → [`BotSignalVerdict::Block`].
/// 2. **User-Agent crawler detection** — `woothee` category + known
///    scripting-client substrings.  A match → Block.
/// 3. **Headless browser / suspicious UA markers** — headless Chrome,
///    PhantomJS, Selenium, etc.  A match → [`BotSignalVerdict::Suspect`].
///
/// Missing UA → Suspect; unrecognised → Allow.
///
/// # JA3/JA4 note
///
/// JA3 and JA4 hashes must be injected by the proxy tier (Nginx, HAProxy,
/// Cloudflare, etc.).  When these headers are absent, the layer is skipped.
/// Hearth does not perform TLS fingerprinting of its own connections.
///
/// The built-in JA3 blocklist contains publicly documented automated-scanner
/// fingerprints from the Salesforce/FoxIO JA3/JA4 projects and community
/// threat-intel feeds.  Treat it as a starting point; add site-specific
/// entries via [`BotSignalConfig::extra_ja3_blocklist`].
#[derive(Debug)]
pub struct HeuristicBotSignalProvider {
    /// Merged JA3 hash blocklist (built-in + operator-supplied).
    ja3_blocklist: HashSet<String>,
    /// Merged JA4 prefix/hash blocklist.
    ja4_blocklist: HashSet<String>,
}

impl HeuristicBotSignalProvider {
    /// Constructs the provider, merging the built-in blocklists with any
    /// operator-supplied extras from `config`.
    #[must_use]
    pub fn new(config: BotSignalConfig) -> Self {
        let mut ja3 = HashSet::new();
        for &h in BUILTIN_JA3_BLOCKLIST {
            ja3.insert(h.to_owned());
        }
        for h in config.extra_ja3_blocklist {
            ja3.insert(h.to_ascii_lowercase());
        }

        let mut ja4 = HashSet::new();
        for &h in BUILTIN_JA4_BLOCKLIST {
            ja4.insert(h.to_owned());
        }
        for h in config.extra_ja4_blocklist {
            ja4.insert(h);
        }

        Self {
            ja3_blocklist: ja3,
            ja4_blocklist: ja4,
        }
    }

    /// Constructs the provider with default (built-in-only) blocklists.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(BotSignalConfig::default())
    }

    fn check_ja3(&self, hash: &str) -> Option<BotSignalVerdict> {
        let lower = hash.to_ascii_lowercase();
        if self.ja3_blocklist.contains(&lower) {
            Some(BotSignalVerdict::Block {
                reason: "JA3 hash matched scanner blocklist",
            })
        } else {
            None
        }
    }

    fn check_ja4(&self, hash: &str) -> Option<BotSignalVerdict> {
        // Full-match first, then prefix-match for shorter blocklist entries.
        if self.ja4_blocklist.contains(hash) {
            return Some(BotSignalVerdict::Block {
                reason: "JA4 hash matched scanner blocklist",
            });
        }
        for entry in &self.ja4_blocklist {
            if !entry.is_empty() && hash.starts_with(entry.as_str()) {
                return Some(BotSignalVerdict::Block {
                    reason: "JA4 prefix matched scanner blocklist",
                });
            }
        }
        None
    }
}

impl BotSignalProvider for HeuristicBotSignalProvider {
    fn check(&self, ctx: &BotSignalContext<'_>) -> BotSignalVerdict {
        // ── Layer 1: JA3 fingerprint ────────────────────────────────────────
        if let Some(ja3) = ctx.ja3_hash {
            if let Some(v) = self.check_ja3(ja3) {
                return v;
            }
        }

        // ── Layer 2: JA4 fingerprint ────────────────────────────────────────
        if let Some(ja4) = ctx.ja4_hash {
            if let Some(v) = self.check_ja4(ja4) {
                return v;
            }
        }

        // ── Layer 3: User-Agent analysis ────────────────────────────────────
        match ctx.user_agent {
            None => BotSignalVerdict::Suspect {
                reason: "missing User-Agent header",
            },
            Some("") => BotSignalVerdict::Suspect {
                reason: "empty User-Agent header",
            },
            Some(ua) => check_ua(ua),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UA analysis helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Scripting-client UA substrings that indicate automated HTTP libraries.
/// Matched case-insensitively.  Order is not significant.
const SCRIPTING_UA_PATTERNS: &[&str] = &[
    "python-requests",
    "python-urllib",
    "python/",
    "libwww-perl",
    "lwp-trivial",
    "perl/",
    "scrapy/",
    "go-http-client/",
    "curl/",
    "wget/",
    "java/",
    "apache-httpclient",
    "okhttp/",
    "aiohttp/",
    "httpx/",
    "node-fetch",
    "got/",
    "axios/",
    "superagent/",
    "undici/",
    "grpc-go/",
    "grpc-python/",
    "grpc-java/",
    "restsharp/",
    "guzzlehttp/",
    "faraday/",
    "pycurl/",
    "ruby/",
    "cfnetwork/", // iOS CFNetwork raw HTTP (often automation)
    "libcurl/",
];

/// Headless/automation-framework markers.
/// Matched case-insensitively; result is Suspect (not Block) since they can
/// appear in legitimate E2E test environments.
const HEADLESS_UA_PATTERNS: &[&str] = &[
    "headlesschrome",
    "headless",
    "phantomjs",
    "selenium",
    "webdriver",
    "puppeteer",
    "playwright",
    "slimerbrowser",
    "slimerjs",
];

fn check_ua(ua: &str) -> BotSignalVerdict {
    // ── woothee category check ──────────────────────────────────────────────
    let parser = woothee::parser::Parser::new();
    if let Some(result) = parser.parse(ua) {
        if result.category == "crawler" {
            return BotSignalVerdict::Block {
                reason: "User-Agent category: crawler",
            };
        }
    }

    let ua_lower = ua.to_ascii_lowercase();

    // ── Scripting-client substring check ───────────────────────────────────
    for pattern in SCRIPTING_UA_PATTERNS {
        if ua_lower.contains(pattern) {
            return BotSignalVerdict::Block {
                reason: "User-Agent: known scripting client",
            };
        }
    }

    // ── Headless / automation-framework check ───────────────────────────────
    for pattern in HEADLESS_UA_PATTERNS {
        if ua_lower.contains(pattern) {
            return BotSignalVerdict::Suspect {
                reason: "User-Agent: headless browser or automation framework",
            };
        }
    }

    // ── Unusually short UA (< 10 chars after trimming) — likely tooling ─────
    if ua.trim().len() < 10 {
        return BotSignalVerdict::Suspect {
            reason: "User-Agent: unusually short",
        };
    }

    BotSignalVerdict::Allow
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in blocklists
// ─────────────────────────────────────────────────────────────────────────────

/// JA3 hashes (lowercase hex MD5) associated with known automated scanners
/// and vulnerability probing tools.
///
/// Source: Salesforce JA3 project, FoxIO community feeds, and public honeypot
/// data.  This is a starting point; the list is intentionally conservative to
/// minimise false positives.  Operator-supplied extras are merged at startup
/// via [`BotSignalConfig::extra_ja3_blocklist`].
///
/// **Important:** JA3 hashes can collide between legitimate clients and bots
/// when they share the same TLS implementation.  Always pair JA3 blocking with
/// other signals (rate limits, UA, IP reputation) to reduce false positives.
const BUILTIN_JA3_BLOCKLIST: &[&str] = &[
    // zgrab2 / masscan default TLS fingerprint (common CVE scanner)
    "de9f2c7fd25e1b3afad3e85a0226f5aa",
    // Nmap NSE TLS scanning module
    "a0e9f5d64349fb13191bc781f81f42e1",
    // Metasploit auxiliary scanner TLS default
    "6bca5e68e18e4768f9c9f5ec99e0f0cf",
    // Generic automated probe (publicised in honeypot feeds)
    "6734f37431670b3ab4292b8f60f29984",
    // Shodan crawler TLS fingerprint
    "c35b0a3b6f8d8f3339e7c85e3c48bc79",
    // Censys.io scan agent
    "3b5074b1b5d032e5620f69f9f700ff0e",
    // BinaryEdge scanner
    "f436523bfb00d5a3c71e3f5c4d63c36f",
];

/// JA4 strings or prefixes associated with automated scanning tools.
///
/// JA4 format: `t{TLS version}{SNI flag}{ext count}{ALPN}{cipher count}_{cipher list}_{ext list}`
/// Prefix entries (shorter than a full JA4 string) match any hash beginning
/// with that prefix.
const BUILTIN_JA4_BLOCKLIST: &[&str] = &[
    // Placeholder: community JA4 blocklists are still nascent (2024).
    // Populate via BotSignalConfig::extra_ja4_blocklist until a vetted list
    // is published by the FoxIO JA4 project.
];

// ─────────────────────────────────────────────────────────────────────────────
// Shared static accessor (avoids repeated heap allocation in tests)
// ─────────────────────────────────────────────────────────────────────────────

static DEFAULT_PROVIDER: OnceLock<HeuristicBotSignalProvider> = OnceLock::new();

/// Returns a shared reference to the default heuristic provider built from
/// the built-in blocklists only.
///
/// Useful for handler code that does not need per-realm configuration.
pub fn default_heuristic_provider() -> &'static HeuristicBotSignalProvider {
    DEFAULT_PROVIDER.get_or_init(HeuristicBotSignalProvider::default_config)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> HeuristicBotSignalProvider {
        HeuristicBotSignalProvider::default_config()
    }

    fn ctx_ua(ua: &str) -> BotSignalContext<'_> {
        BotSignalContext {
            user_agent: Some(ua),
            ja3_hash: None,
            ja4_hash: None,
            ip: None,
        }
    }

    fn ctx_no_ua() -> BotSignalContext<'static> {
        BotSignalContext {
            user_agent: None,
            ja3_hash: None,
            ja4_hash: None,
            ip: None,
        }
    }

    fn ctx_ja3(hash: &str) -> BotSignalContext<'_> {
        BotSignalContext {
            user_agent: Some(
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            ),
            ja3_hash: Some(hash),
            ja4_hash: None,
            ip: None,
        }
    }

    // ── No-op provider ──────────────────────────────────────────────────────

    /// Noop provider always allows regardless of UA or JA3.
    #[test]
    fn noop_always_allows() {
        let p = NoopBotSignalProvider;
        assert_eq!(p.check(&ctx_no_ua()), BotSignalVerdict::Allow);
        assert_eq!(
            p.check(&BotSignalContext {
                user_agent: None,
                ja3_hash: Some("de9f2c7fd25e1b3afad3e85a0226f5aa"),
                ja4_hash: None,
                ip: None,
            }),
            BotSignalVerdict::Allow
        );
    }

    // ── Missing / empty UA ──────────────────────────────────────────────────

    /// A missing User-Agent is suspicious.
    #[test]
    fn missing_ua_is_suspect() {
        let v = provider().check(&ctx_no_ua());
        assert!(matches!(v, BotSignalVerdict::Suspect { .. }));
    }

    /// An empty User-Agent string is suspicious.
    #[test]
    fn empty_ua_is_suspect() {
        let v = provider().check(&ctx_ua(""));
        assert!(matches!(v, BotSignalVerdict::Suspect { .. }));
    }

    /// A very short UA (< 10 chars) is suspicious.
    #[test]
    fn very_short_ua_is_suspect() {
        let v = provider().check(&ctx_ua("bot"));
        assert!(matches!(v, BotSignalVerdict::Suspect { .. }));
    }

    // ── Scripting-client UAs ────────────────────────────────────────────────

    /// curl is blocked as a scripting client.
    #[test]
    fn curl_ua_is_blocked() {
        let v = provider().check(&ctx_ua("curl/8.4.0"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// python-requests is blocked.
    #[test]
    fn python_requests_ua_is_blocked() {
        let v = provider().check(&ctx_ua("python-requests/2.31.0"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// wget is blocked.
    #[test]
    fn wget_ua_is_blocked() {
        let v = provider().check(&ctx_ua("Wget/1.21.4 (linux-gnu)"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// Go HTTP client is blocked.
    #[test]
    fn go_http_client_is_blocked() {
        let v = provider().check(&ctx_ua("Go-http-client/2.0"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// Java/OpenJDK HTTP client is blocked.
    #[test]
    fn java_ua_is_blocked() {
        let v = provider().check(&ctx_ua("Java/11.0.20"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    // ── Crawler UAs ─────────────────────────────────────────────────────────

    /// Googlebot is blocked (woothee "crawler" category).
    #[test]
    fn googlebot_ua_is_blocked() {
        let v = provider().check(&ctx_ua(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        ));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    // ── Headless / automation ───────────────────────────────────────────────

    /// HeadlessChrome is suspect (could be legitimate E2E test).
    #[test]
    fn headless_chrome_is_suspect() {
        let v = provider().check(&ctx_ua(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/114.0.0.0 Safari/537.36",
        ));
        assert!(matches!(v, BotSignalVerdict::Suspect { .. }), "got {v:?}");
    }

    /// Selenium WebDriver fingerprint is suspect.
    #[test]
    fn selenium_ua_is_suspect() {
        let v = provider().check(&ctx_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Selenium/4.10",
        ));
        assert!(matches!(v, BotSignalVerdict::Suspect { .. }), "got {v:?}");
    }

    // ── Normal browser UAs ──────────────────────────────────────────────────

    /// A standard Firefox UA is allowed.
    #[test]
    fn firefox_ua_is_allowed() {
        let v = provider().check(&ctx_ua(
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ));
        assert_eq!(v, BotSignalVerdict::Allow, "got {v:?}");
    }

    /// A standard Chrome UA is allowed.
    #[test]
    fn chrome_ua_is_allowed() {
        let v = provider().check(&ctx_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        ));
        assert_eq!(v, BotSignalVerdict::Allow, "got {v:?}");
    }

    /// Mobile Safari is allowed.
    #[test]
    fn mobile_safari_ua_is_allowed() {
        let v = provider().check(&ctx_ua(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
             AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ));
        assert_eq!(v, BotSignalVerdict::Allow, "got {v:?}");
    }

    // ── JA3 blocklist ───────────────────────────────────────────────────────

    /// A known scanner JA3 hash is blocked even with a legitimate-looking UA.
    #[test]
    fn known_scanner_ja3_is_blocked() {
        let v = provider().check(&ctx_ja3("de9f2c7fd25e1b3afad3e85a0226f5aa"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// JA3 check is case-insensitive (uppercase hex is normalised).
    #[test]
    fn ja3_check_is_case_insensitive() {
        let v = provider().check(&ctx_ja3("DE9F2C7FD25E1B3AFAD3E85A0226F5AA"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// An unknown JA3 hash does not trigger blocking.
    #[test]
    fn unknown_ja3_is_allowed() {
        let v = provider().check(&ctx_ja3("aaaabbbbccccdddd00001111ffffffff"));
        // UA is a normal Firefox UA so verdict should be Allow.
        assert_eq!(v, BotSignalVerdict::Allow, "got {v:?}");
    }

    /// Absent JA3 header does not block.
    #[test]
    fn absent_ja3_does_not_block() {
        let v = provider().check(&BotSignalContext {
            user_agent: Some(
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            ),
            ja3_hash: None,
            ja4_hash: None,
            ip: None,
        });
        assert_eq!(v, BotSignalVerdict::Allow, "got {v:?}");
    }

    // ── Operator-supplied extra blocklist ───────────────────────────────────

    /// Operator can extend the JA3 blocklist at startup.
    #[test]
    fn extra_ja3_blocklist_works() {
        let p = HeuristicBotSignalProvider::new(BotSignalConfig {
            extra_ja3_blocklist: vec!["deadbeef00000000deadbeef00000000".to_owned()],
            extra_ja4_blocklist: Vec::new(),
        });
        let v = p.check(&ctx_ja3("deadbeef00000000deadbeef00000000"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    /// Operator-supplied extra JA3 is normalised to lowercase.
    #[test]
    fn extra_ja3_normalised_to_lowercase() {
        let p = HeuristicBotSignalProvider::new(BotSignalConfig {
            extra_ja3_blocklist: vec!["DEADBEEF00000000DEADBEEF00000000".to_owned()],
            extra_ja4_blocklist: Vec::new(),
        });
        let v = p.check(&ctx_ja3("deadbeef00000000deadbeef00000000"));
        assert!(matches!(v, BotSignalVerdict::Block { .. }), "got {v:?}");
    }

    // ── Verdict helpers ─────────────────────────────────────────────────────

    #[test]
    fn verdict_allow_is_allow() {
        assert!(BotSignalVerdict::Allow.is_allow());
        assert!(!BotSignalVerdict::Allow.is_block());
    }

    #[test]
    fn verdict_block_is_block() {
        let v = BotSignalVerdict::Block { reason: "test" };
        assert!(!v.is_allow());
        assert!(v.is_block());
    }
}

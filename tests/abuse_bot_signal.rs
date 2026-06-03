//! Integration tests for P-3 BotSignalProvider (UA + JA3/JA4 heuristics).
//!
//! D-4 taxonomy:
//! - **Unit**: verdict correctness for every signal class.
//! - **Adversarial**: evasion attempts (obfuscated UA, mixed-case JA3,
//!   extra whitespace, partial UA spoofing).
//!
//! Closes: HEA-1204 §P-3 (BotSignal trait + reference adapter).

use hearth::abuse::bot_signal::{
    BotSignalConfig, BotSignalContext, BotSignalProvider, BotSignalVerdict,
    HeuristicBotSignalProvider, NoopBotSignalProvider,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p() -> HeuristicBotSignalProvider {
    HeuristicBotSignalProvider::default_config()
}

fn ctx(ua: &str) -> BotSignalContext<'_> {
    BotSignalContext {
        user_agent: Some(ua),
        ja3_hash: None,
        ja4_hash: None,
        ip: None,
    }
}

fn ctx_ja3<'a>(ua: &'a str, ja3: &'a str) -> BotSignalContext<'a> {
    BotSignalContext {
        user_agent: Some(ua),
        ja3_hash: Some(ja3),
        ja4_hash: None,
        ip: None,
    }
}

const FIREFOX_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0";
const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// ─────────────────────────────────────────────────────────────────────────────
// No-op provider
// ─────────────────────────────────────────────────────────────────────────────

/// Noop provider allows everything — no false positives ever.
#[test]
fn p3_noop_allows_bot_ua() {
    let v = NoopBotSignalProvider.check(&ctx("python-requests/2.31.0"));
    assert_eq!(v, BotSignalVerdict::Allow);
}

/// Noop provider allows even a known scanner JA3.
#[test]
fn p3_noop_allows_known_ja3() {
    let v = NoopBotSignalProvider.check(&ctx_ja3(FIREFOX_UA, "de9f2c7fd25e1b3afad3e85a0226f5aa"));
    assert_eq!(v, BotSignalVerdict::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: UA signal class
// ─────────────────────────────────────────────────────────────────────────────

/// Standard Firefox UA is allowed.
#[test]
fn p3_unit_firefox_allow() {
    assert_eq!(p().check(&ctx(FIREFOX_UA)), BotSignalVerdict::Allow);
}

/// Standard Chrome UA is allowed.
#[test]
fn p3_unit_chrome_allow() {
    assert_eq!(p().check(&ctx(CHROME_UA)), BotSignalVerdict::Allow);
}

/// Missing UA → Suspect.
#[test]
fn p3_unit_missing_ua_suspect() {
    let ctx = BotSignalContext {
        user_agent: None,
        ja3_hash: None,
        ja4_hash: None,
        ip: None,
    };
    assert!(matches!(p().check(&ctx), BotSignalVerdict::Suspect { .. }));
}

/// Empty UA → Suspect.
#[test]
fn p3_unit_empty_ua_suspect() {
    assert!(matches!(
        p().check(&ctx("")),
        BotSignalVerdict::Suspect { .. }
    ));
}

/// curl → Block.
#[test]
fn p3_unit_curl_block() {
    assert!(matches!(
        p().check(&ctx("curl/8.4.0")),
        BotSignalVerdict::Block { .. }
    ));
}

/// wget → Block.
#[test]
fn p3_unit_wget_block() {
    assert!(matches!(
        p().check(&ctx("Wget/1.21.4")),
        BotSignalVerdict::Block { .. }
    ));
}

/// python-requests → Block.
#[test]
fn p3_unit_python_requests_block() {
    assert!(matches!(
        p().check(&ctx("python-requests/2.28.2")),
        BotSignalVerdict::Block { .. }
    ));
}

/// Go-http-client → Block.
#[test]
fn p3_unit_go_http_client_block() {
    assert!(matches!(
        p().check(&ctx("Go-http-client/1.1")),
        BotSignalVerdict::Block { .. }
    ));
}

/// Googlebot (woothee crawler category) → Block.
#[test]
fn p3_unit_googlebot_block() {
    assert!(matches!(
        p().check(&ctx(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        )),
        BotSignalVerdict::Block { .. }
    ));
}

/// HeadlessChrome → Suspect (not Block — could be legitimate E2E test).
#[test]
fn p3_unit_headless_chrome_suspect() {
    assert!(matches!(
        p().check(&ctx(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
             HeadlessChrome/114.0.0.0 Safari/537.36"
        )),
        BotSignalVerdict::Suspect { .. }
    ));
}

/// Puppeteer-embedded UA → Suspect.
#[test]
fn p3_unit_puppeteer_suspect() {
    assert!(matches!(
        p().check(&ctx(
            "Mozilla/5.0 AppleWebKit/537.36 Chrome/114 Safari/537.36 Puppeteer/21"
        )),
        BotSignalVerdict::Suspect { .. }
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: JA3 signal class
// ─────────────────────────────────────────────────────────────────────────────

/// Known scanner JA3 → Block (even with legitimate-looking UA).
#[test]
fn p3_unit_known_ja3_block() {
    assert!(matches!(
        p().check(&ctx_ja3(FIREFOX_UA, "de9f2c7fd25e1b3afad3e85a0226f5aa")),
        BotSignalVerdict::Block { .. }
    ));
}

/// Second known scanner JA3 → Block.
#[test]
fn p3_unit_second_known_ja3_block() {
    assert!(matches!(
        p().check(&ctx_ja3(CHROME_UA, "a0e9f5d64349fb13191bc781f81f42e1")),
        BotSignalVerdict::Block { .. }
    ));
}

/// Unknown JA3 does not block.
#[test]
fn p3_unit_unknown_ja3_allow() {
    assert_eq!(
        p().check(&ctx_ja3(FIREFOX_UA, "00000000000000000000000000000000")),
        BotSignalVerdict::Allow
    );
}

/// Absent JA3 (None) does not trigger block.
#[test]
fn p3_unit_absent_ja3_allow() {
    assert_eq!(p().check(&ctx(FIREFOX_UA)), BotSignalVerdict::Allow);
}

/// JA3 block takes precedence over a suspicious UA.
#[test]
fn p3_unit_ja3_block_over_suspect_ua() {
    // Headless UA would be Suspect; known JA3 should still Block.
    let v = p().check(&BotSignalContext {
        user_agent: Some("HeadlessChrome/114.0.0.0"),
        ja3_hash: Some("de9f2c7fd25e1b3afad3e85a0226f5aa"),
        ja4_hash: None,
        ip: None,
    });
    assert!(matches!(v, BotSignalVerdict::Block { .. }));
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: evasion attempts
// ─────────────────────────────────────────────────────────────────────────────

/// Mixing a scripting-client string into an otherwise legitimate UA is still detected.
///
/// Real bots sometimes prepend a browser UA to their own to evade checks.
/// Because we do substring matching, "python-requests/2.0 Mozilla/5.0" still hits.
#[test]
fn p3_adversarial_mixed_ua_still_blocked() {
    let ua = "Mozilla/5.0 (compatible; python-requests/2.31.0; rv:109.0) Firefox/115.0";
    assert!(matches!(
        p().check(&ctx(ua)),
        BotSignalVerdict::Block { .. }
    ));
}

/// Uppercase scripting client UA is still caught (case-insensitive).
#[test]
fn p3_adversarial_uppercase_scripting_ua_blocked() {
    let ua = "PYTHON-REQUESTS/2.31.0";
    assert!(matches!(
        p().check(&ctx(ua)),
        BotSignalVerdict::Block { .. }
    ));
}

/// JA3 hash with uppercase hex is still matched (normalised to lowercase).
#[test]
fn p3_adversarial_uppercase_ja3_still_blocked() {
    assert!(matches!(
        p().check(&ctx_ja3(FIREFOX_UA, "DE9F2C7FD25E1B3AFAD3E85A0226F5AA")),
        BotSignalVerdict::Block { .. }
    ));
}

/// JA3 hash that is one character different from a blocked hash is NOT blocked.
///
/// Ensures we do exact-match, not prefix or fuzzy comparison.
#[test]
fn p3_adversarial_near_match_ja3_not_blocked() {
    // Differs in last char from the known masscan hash.
    let v = p().check(&ctx_ja3(FIREFOX_UA, "de9f2c7fd25e1b3afad3e85a0226f5ab"));
    assert_eq!(v, BotSignalVerdict::Allow);
}

/// Empty JA3 string does not block.
#[test]
fn p3_adversarial_empty_ja3_not_blocked() {
    assert_eq!(p().check(&ctx_ja3(FIREFOX_UA, "")), BotSignalVerdict::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator-supplied blocklists
// ─────────────────────────────────────────────────────────────────────────────

/// Operator can add custom JA3 hashes at startup.
#[test]
fn p3_extra_ja3_blocklist_blocks() {
    let p = HeuristicBotSignalProvider::new(BotSignalConfig {
        extra_ja3_blocklist: vec!["cafebabe00000000cafebabe00000000".to_owned()],
        extra_ja4_blocklist: Vec::new(),
    });
    assert!(matches!(
        p.check(&ctx_ja3(FIREFOX_UA, "cafebabe00000000cafebabe00000000")),
        BotSignalVerdict::Block { .. }
    ));
}

/// Operator's extra JA3 does not block a different hash.
#[test]
fn p3_extra_ja3_only_blocks_matching_hash() {
    let p = HeuristicBotSignalProvider::new(BotSignalConfig {
        extra_ja3_blocklist: vec!["cafebabe00000000cafebabe00000000".to_owned()],
        extra_ja4_blocklist: Vec::new(),
    });
    assert_eq!(
        p.check(&ctx_ja3(FIREFOX_UA, "deadbeef00000000deadbeef00000000")),
        BotSignalVerdict::Allow
    );
}

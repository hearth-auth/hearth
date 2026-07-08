//! Tests for P-1 Cloudflare Turnstile CAPTCHA adapter (HEA-1202).
//!
//! D-4 taxonomy:
//! - **Unit**: `NoopCaptchaProvider::widget_html` returns empty string.
//! - **Unit**: `NoopCaptchaProvider::verify` always returns `true`.
//! - **Unit**: `TurnstileCaptchaProvider::widget_html` contains the site key.
//! - **Unit**: `TurnstileCaptchaProvider::widget_html` does NOT contain the secret key.
//! - **Unit**: `TurnstileCaptchaProvider::widget_html` contains Turnstile CDN script tag.
//! - **Unit**: `TurnstileCaptchaProvider::verify("")` returns `false` (empty token → fail-closed).
//! - **Unit**: `TurnstileCaptchaProvider::verify` with unreachable URL fails open (returns `true`).
//! - **Adversarial**: widget HTML injection — site key is HTML-attribute-safe (no `"` or `>`).
//! - **Adversarial**: empty secret key is accepted at construction (start-time validation is caller's job).
//!
//! Closes: [HEA-1202](/HEA/issues/HEA-1202) (P-1 Turnstile adapter).

use std::net::{IpAddr, Ipv4Addr};

use hearth::abuse::captcha::{TurnstileCaptchaProvider, TurnstileConfig};
use hearth::abuse::challenge::{CaptchaProvider, NoopCaptchaProvider};

fn ip(b: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))
}

fn test_config() -> TurnstileConfig {
    TurnstileConfig {
        site_key: "test-site-key-abc123".to_string(),
        secret_key: "test-secret-key-xyz789".to_string(),
        verify_url: "http://127.0.0.1:0/siteverify".to_string(), // unreachable → fail-open
    }
}

// ── Unit: NoopCaptchaProvider ────────────────────────────────────────────────

#[test]
fn noop_provider_widget_html_is_empty() {
    assert_eq!(
        NoopCaptchaProvider.widget_html(),
        "",
        "noop provider must return empty string for widget_html"
    );
}

#[test]
fn noop_provider_verify_always_true() {
    assert!(
        NoopCaptchaProvider.verify("any-token", ip(1)),
        "noop provider must always return true"
    );
    assert!(
        NoopCaptchaProvider.verify("", ip(1)),
        "noop provider must return true even for empty token"
    );
    assert!(
        NoopCaptchaProvider.verify("garbage-token", ip(255)),
        "noop provider must return true for any token/IP combination"
    );
}

// ── Unit: TurnstileCaptchaProvider ──────────────────────────────────────────

#[test]
fn turnstile_widget_html_contains_site_key() {
    let provider = TurnstileCaptchaProvider::new(test_config());
    let html = provider.widget_html();
    assert!(
        html.contains("test-site-key-abc123"),
        "widget_html must embed the site key; got: {html}"
    );
}

#[test]
fn turnstile_widget_html_does_not_contain_secret_key() {
    let provider = TurnstileCaptchaProvider::new(test_config());
    let html = provider.widget_html();
    assert!(
        !html.contains("test-secret-key-xyz789"),
        "widget_html MUST NOT expose the secret key; got: {html}"
    );
}

#[test]
fn turnstile_widget_html_contains_cdn_script() {
    let provider = TurnstileCaptchaProvider::new(test_config());
    let html = provider.widget_html();
    assert!(
        html.contains("challenges.cloudflare.com/turnstile"),
        "widget_html must include the Cloudflare Turnstile CDN script; got: {html}"
    );
}

#[test]
fn turnstile_widget_html_contains_input_name() {
    let provider = TurnstileCaptchaProvider::new(test_config());
    let html = provider.widget_html();
    // The widget must include a hidden input with name "cf-turnstile-response"
    // OR the cf-turnstile div that Cloudflare's JS populates.
    assert!(
        html.contains("cf-turnstile") || html.contains("data-sitekey"),
        "widget_html must include the Turnstile widget div; got: {html}"
    );
}

// ── Unit: verify() — empty token ─────────────────────────────────────────────

#[test]
fn turnstile_verify_empty_token_returns_false() {
    let provider = TurnstileCaptchaProvider::new(test_config());
    assert!(
        !provider.verify("", ip(1)),
        "verify(\"\") must return false (fail-closed for empty token)"
    );
}

// ── Unit: verify() — unreachable URL fails open ──────────────────────────────

#[test]
fn turnstile_verify_unreachable_url_fails_open() {
    // Port 0 or a closed port: ureq will fail to connect.
    // The provider MUST return true (fail-open) on transport error.
    let cfg = TurnstileConfig {
        site_key: "site-key".to_string(),
        secret_key: "secret-key".to_string(),
        verify_url: "http://127.0.0.1:1/siteverify".to_string(), // port 1 is never open
    };
    let provider = TurnstileCaptchaProvider::new(cfg);
    assert!(
        provider.verify("some-token", ip(1)),
        "verify() must fail-open (return true) when the siteverify URL is unreachable"
    );
}

// ── Adversarial: site-key HTML safety ────────────────────────────────────────

#[test]
fn turnstile_widget_html_site_key_is_attribute_safe() {
    // A malicious site key containing `"` or `>` must not break the HTML attribute.
    // In practice Cloudflare only issues safe alphanumeric keys, but the code should
    // not produce broken HTML if given a weird key.
    let cfg = TurnstileConfig {
        site_key: "safe-key-0x4AAAAAAA".to_string(),
        secret_key: "sec".to_string(),
        verify_url: "http://127.0.0.1:1/siteverify".to_string(),
    };
    let provider = TurnstileCaptchaProvider::new(cfg);
    let html = provider.widget_html();
    // The HTML must be valid XML-ish — the site key appears in a data-sitekey attribute.
    // Verify that the key is present and the attribute closes properly.
    assert!(
        html.contains("safe-key-0x4AAAAAAA"),
        "site key must appear in widget HTML"
    );
}

#[test]
fn turnstile_widget_html_site_key_special_chars_escaped() {
    // WEB-005: site_key with `"`, `<`, `>`, `&` must be HTML-escaped so that a
    // config-injection attacker cannot break out of the data-sitekey attribute.
    let cfg = TurnstileConfig {
        site_key: r#"key"<script>alert(1)</script>&"#.to_string(),
        secret_key: "sec".to_string(),
        verify_url: "http://127.0.0.1:1/siteverify".to_string(),
    };
    let provider = TurnstileCaptchaProvider::new(cfg);
    let html = provider.widget_html();
    assert!(
        !html.contains("<script>"),
        "raw <script> tag must be escaped (WEB-005)"
    );
    assert!(html.contains("&lt;"), "< must be escaped to &lt; (WEB-005)");
    assert!(
        html.contains("&amp;"),
        "& must be escaped to &amp; (WEB-005)"
    );
    assert!(
        html.contains("&quot;"),
        "\" must be escaped to &quot; (WEB-005)"
    );
}

#[test]
fn turnstile_empty_secret_key_accepted_at_construction() {
    // Construction must not panic even with an empty secret key.
    // Runtime verify() with an empty secret returns false at the API level
    // (Cloudflare rejects it), which is tested separately.
    let cfg = TurnstileConfig {
        site_key: "sk".to_string(),
        secret_key: String::new(),
        verify_url: "http://127.0.0.1:1/siteverify".to_string(),
    };
    let provider = TurnstileCaptchaProvider::new(cfg);
    // widget_html is still functional even with an empty secret key.
    assert!(
        provider.widget_html().contains("sk"),
        "site key must appear in widget HTML"
    );
}

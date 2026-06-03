//! Cloudflare Turnstile reference adapter for [`CaptchaProvider`] (P-1 — HEA-1202).
//!
//! # Module contents
//!
//! | Item | Purpose |
//! |------|---------|
//! | [`TurnstileConfig`] | Construction-time configuration for the adapter |
//! | [`TurnstileCaptchaProvider`] | Implements [`CaptchaProvider`] via Cloudflare Turnstile |
//!
//! # Wiring
//!
//! Configure under `security.captcha` in `hearth.yaml`:
//!
//! ```yaml
//! security:
//!   captcha:
//!     provider: turnstile
//!     turnstile:
//!       site_key: "0x4AAAAAAA..."
//!       secret_key: "0x4AAAAAAA..."   # or set HEARTH_TURNSTILE_SECRET_KEY
//! ```
//!
//! Then pass `Arc::new(TurnstileCaptchaProvider::new(config))` to
//! `WebState::with_captcha_provider()`.
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: transport errors, DNS failures, and
//! Cloudflare API timeouts return `true` (allow) so legitimate users are never
//! blocked while Cloudflare is unavailable. A `tracing::warn` event is emitted
//! on every fail-open so operators can detect the condition in their logs.
//!
//! The one fail-**closed** case: an empty response token.  An empty string
//! cannot be a valid Turnstile response and is almost certainly a programmatic
//! caller (bot) bypassing the widget.  We return `false` immediately without
//! hitting the Cloudflare API.

use std::net::IpAddr;

use serde::Deserialize;
use tracing::warn;

use crate::abuse::challenge::CaptchaProvider;

// ─────────────────────────────────────────────────────────────────────────────
// Default verify URL
// ─────────────────────────────────────────────────────────────────────────────

/// Default Cloudflare Turnstile siteverify endpoint.
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Construction-time configuration for [`TurnstileCaptchaProvider`].
///
/// Created from `security.captcha.turnstile` in `hearth.yaml` (see
/// [`crate::config::types::TurnstileYaml`]).
#[derive(Debug, Clone)]
pub struct TurnstileConfig {
    /// Cloudflare Turnstile **site key** (public — safe to embed in HTML).
    pub site_key: String,
    /// Cloudflare Turnstile **secret key** (private — MUST NOT be sent to clients).
    pub secret_key: String,
    /// Siteverify endpoint override.  Defaults to the Cloudflare production URL.
    /// Set to a local URL in tests to avoid real network calls.
    pub verify_url: String,
}

impl TurnstileConfig {
    /// Builds a production config using the official Cloudflare verify endpoint.
    #[must_use]
    pub fn new(site_key: String, secret_key: String) -> Self {
        Self {
            site_key,
            secret_key,
            verify_url: TURNSTILE_VERIFY_URL.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Turnstile response type (internal)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    /// Included for diagnostics; not surfaced to clients.
    #[serde(default, rename = "error-codes")]
    #[allow(dead_code)]
    error_codes: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// TurnstileCaptchaProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Cloudflare Turnstile CAPTCHA provider (P-1 reference adapter).
///
/// Implements [`CaptchaProvider`]:
///
/// - `widget_html()` returns a pre-built `<script>` + `<div>` pair embedding
///   the site key.  The string is computed once at construction and served from
///   a `String` field, so subsequent calls are zero-allocation.
/// - `verify()` POSTs the response token to Cloudflare's siteverify API using
///   the blocking `ureq` client.  The caller (form handler) MUST invoke this
///   via `tokio::task::spawn_blocking` to avoid blocking the Tokio event loop.
///
/// # Security
///
/// The `secret_key` is stored in memory and is never exposed via `Debug`,
/// `Display`, or any derived trait.  `widget_html()` only embeds the
/// (public) `site_key`.
pub struct TurnstileCaptchaProvider {
    /// Secret key for server-side verification.  Not `pub`, never logged.
    secret_key: String,
    /// Siteverify API URL.
    verify_url: String,
    /// Pre-built widget HTML (allocated once at construction).
    widget_html: String,
}

impl std::fmt::Debug for TurnstileCaptchaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnstileCaptchaProvider")
            .field("verify_url", &self.verify_url)
            .field("widget_html_len", &self.widget_html.len())
            .finish_non_exhaustive()
    }
}

impl TurnstileCaptchaProvider {
    /// Constructs a new adapter from the given config.
    ///
    /// Pre-builds the widget HTML so `widget_html()` is allocation-free.
    #[must_use]
    pub fn new(config: TurnstileConfig) -> Self {
        let widget_html = build_widget_html(&config.site_key);
        Self {
            secret_key: config.secret_key,
            verify_url: config.verify_url,
            widget_html,
        }
    }
}

impl CaptchaProvider for TurnstileCaptchaProvider {
    fn widget_html(&self) -> &str {
        &self.widget_html
    }

    /// Verifies a Turnstile response token against the Cloudflare siteverify API.
    ///
    /// # Blocking
    ///
    /// This method performs a synchronous HTTP POST via `ureq`.  Call it inside
    /// `tokio::task::spawn_blocking` from async handlers.
    ///
    /// # Fail-open / fail-closed
    ///
    /// - Empty `token` → returns `false` (fail-closed: no widget was shown or
    ///   a bot bypassed it).
    /// - Transport error or malformed API response → returns `true` (fail-open:
    ///   Cloudflare unavailable should not block legitimate users).
    fn verify(&self, token: &str, ip: IpAddr) -> bool {
        if token.is_empty() {
            warn!("turnstile: empty token submitted — failing closed");
            return false;
        }

        let body = serde_json::json!({
            "secret":   self.secret_key,
            "response": token,
            "remoteip": ip.to_string(),
        });

        let result = ureq::post(&self.verify_url)
            .header("Content-Type", "application/json")
            .send_json(&body);

        match result {
            Err(e) => {
                warn!(
                    error = %e,
                    "turnstile: siteverify request failed — failing open"
                );
                true
            }
            Ok(mut resp) => match resp.body_mut().read_json::<TurnstileVerifyResponse>() {
                Ok(data) => {
                    if !data.success && !data.error_codes.is_empty() {
                        warn!(
                            error_codes = ?data.error_codes,
                            "turnstile: verification failed"
                        );
                    }
                    data.success
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "turnstile: failed to parse siteverify response — failing open"
                    );
                    true
                }
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget HTML builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the Turnstile widget HTML snippet for a given site key.
///
/// Inserted verbatim into login/registration templates at the
/// `<!-- captcha-widget-slot -->` comment.  The snippet loads the Turnstile
/// JavaScript and renders the interactive widget; Cloudflare's JS populates a
/// hidden `cf-turnstile-response` field that the form submits as `captcha_token`.
fn build_widget_html(site_key: &str) -> String {
    format!(
        r#"<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile mt-2" data-sitekey="{site_key}" data-response-field-name="captcha_token" data-theme="dark"></div>"#,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::abuse::challenge::NoopCaptchaProvider;

    fn ip(b: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))
    }

    fn unreachable_config() -> TurnstileConfig {
        TurnstileConfig {
            site_key: "0xSITEKEY".to_string(),
            secret_key: "0xSECRET".to_string(),
            verify_url: "http://127.0.0.1:1/siteverify".to_string(),
        }
    }

    // ── NoopCaptchaProvider ──────────────────────────────────────────────────

    #[test]
    fn noop_widget_empty() {
        assert_eq!(NoopCaptchaProvider.widget_html(), "");
    }

    #[test]
    fn noop_verify_always_true() {
        assert!(NoopCaptchaProvider.verify("", ip(1)));
        assert!(NoopCaptchaProvider.verify("token", ip(1)));
    }

    // ── widget_html ──────────────────────────────────────────────────────────

    #[test]
    fn widget_contains_site_key() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        assert!(p.widget_html().contains("0xSITEKEY"));
    }

    #[test]
    fn widget_does_not_contain_secret_key() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        assert!(!p.widget_html().contains("0xSECRET"));
    }

    #[test]
    fn widget_contains_turnstile_cdn() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        assert!(p
            .widget_html()
            .contains("challenges.cloudflare.com/turnstile"));
    }

    #[test]
    fn widget_contains_response_field_name() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        assert!(p.widget_html().contains("captcha_token"));
    }

    // ── verify() ─────────────────────────────────────────────────────────────

    #[test]
    fn verify_empty_token_fails_closed() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        assert!(
            !p.verify("", ip(1)),
            "empty token must be rejected (fail-closed)"
        );
    }

    #[test]
    fn verify_transport_error_fails_open() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        assert!(
            p.verify("valid-looking-token", ip(1)),
            "transport failure must fail-open"
        );
    }

    // ── Debug does not leak secret_key ───────────────────────────────────────

    #[test]
    fn debug_does_not_expose_secret_key() {
        let p = TurnstileCaptchaProvider::new(unreachable_config());
        let debug_str = format!("{p:?}");
        assert!(
            !debug_str.contains("0xSECRET"),
            "Debug impl must not expose the secret key"
        );
    }
}

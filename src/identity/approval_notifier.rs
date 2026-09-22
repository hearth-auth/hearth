//! Approval webhook notifier (Phase C.5 — durable at-least-once delivery).
//!
//! Delivers `ApprovalWebhookPayload` via HTTP POST to per-realm configured
//! endpoints. Uses HMAC-SHA256 signing when a secret is configured.
//!
//! # Durability guarantee
//!
//! The caller writes an outbox record to WAL *before* calling this module.
//! If the delivery succeeds, the outbox record is deleted. If it fails (or
//! the process crashes before deletion), the outbox record survives and the
//! background recovery scanner will redeliver on the next startup or scan.
//!
//! # Signature scheme
//!
//! Follows the same convention as `webhook/dispatcher.rs`:
//! ```text
//! X-Hearth-Signature-256: sha256=<hex(HMAC-SHA256(secret, body))>
//! X-Hearth-Event: approval_requested
//! X-Hearth-Delivery: <delivery_id>
//! ```

use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

use crate::identity::types::{ApprovalWebhookConfig, ApprovalWebhookPayload};

type HmacSha256 = Hmac<Sha256>;

const EVENT_TYPE: &str = "approval_requested";

// ── Transport trait ──────────────────────────────────────────────────────────

/// Injectable HTTP transport for approval webhook delivery.
///
/// Trait-based so tests can capture deliveries without making real HTTP calls.
/// The production implementation adds an SSRF guard (M7) before each send.
pub trait ApprovalWebhookTransport: Send + Sync {
    /// Sends the signed webhook payload to `url`.
    ///
    /// - `body`: pre-serialized JSON payload bytes
    /// - `event_type`: value for `X-Hearth-Event` header
    /// - `delivery_id`: value for `X-Hearth-Delivery` header
    /// - `signature`: optional `X-Hearth-Signature-256` value (`"sha256=<hex>"`)
    /// - `timeout_ms`: the realm's `approval_webhook.timeout_ms`
    ///
    /// `timeout_ms` is part of the signature because it had nowhere else to
    /// go (task 26.37). It parsed, validated and reached
    /// `ApprovalWebhookConfig` — and `deliver` never handed it to the
    /// transport, which built a `ureq` config with no timeout of any kind.
    /// The call runs inside `tokio::task::block_in_place`, so an approver's
    /// endpoint that completes the handshake and then stops responding took a
    /// Tokio worker thread out of service permanently.
    fn send(
        &self,
        url: &str,
        body: &[u8],
        event_type: &str,
        delivery_id: &str,
        signature: Option<&str>,
        timeout_ms: u64,
    ) -> Result<(), String>;
}

/// Connect timeout as a fraction of the realm's overall budget.
///
/// A connect that has not completed in half the total budget will not leave
/// time for a response, so splitting the operator's single number this way
/// needs no second config key.
fn approval_connect_timeout(timeout_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(timeout_ms.max(1) / 2 + 1)
}

/// Builds the `ureq` config for one approval-webhook delivery.
///
/// # Task 26.37
///
/// ureq 3.3.0's `Timeouts::default()` leaves every field `None` except
/// `await_100`, so the previous config — `https_only` and `max_redirects`
/// only — bounded nothing. `timeout_ms` was already in
/// `ApprovalWebhookConfig`, already validated, and simply never reached here.
pub(crate) fn approval_agent_config(timeout_ms: u64) -> ureq::config::Config {
    ureq::config::Config::builder()
        .timeout_connect(Some(approval_connect_timeout(timeout_ms)))
        .timeout_global(Some(std::time::Duration::from_millis(timeout_ms.max(1))))
        .https_only(true)
        .max_redirects(crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS)
        .build()
}

// ── Production ureq transport (with SSRF guard) ──────────────────────────────

/// Production `ureq`-backed transport.
///
/// Runs the blocking ureq call inside `block_in_place` when invoked from a
/// multi-thread Tokio runtime. Applies `check_webhook_url` as a pre-flight
/// SSRF guard on every delivery attempt (DNS-rebinding-resistant).
pub(crate) struct UreqApprovalTransport;

impl ApprovalWebhookTransport for UreqApprovalTransport {
    fn send(
        &self,
        url: &str,
        body: &[u8],
        event_type: &str,
        delivery_id: &str,
        signature: Option<&str>,
        timeout_ms: u64,
    ) -> Result<(), String> {
        let url = url.to_string();
        let body = body.to_vec();
        let event_type = event_type.to_string();
        let delivery_id = delivery_id.to_string();
        let signature = signature.map(str::to_string);

        let do_request = move || -> Result<(), String> {
            // SSRF guard: resolve destination and reject private/reserved ranges.
            // Called pre-flight on every attempt to defend against DNS rebinding.
            crate::webhook::ssrf::check_webhook_url(&url)
                .map_err(|e| format!("SSRF guard rejected approval webhook URL: {e}"))?;

            // Do not follow redirects: check_webhook_url only validated the
            // initial host, so a 3xx could redirect to an internal target (W1).
            // ssrf_agent SSRF-validates the connect-time DNS lookup, closing
            // the DNS-rebinding TOCTOU left open by the pre-flight check above
            // (W1 residual risk, HEA-1762).
            let config = approval_agent_config(timeout_ms);
            let agent = crate::webhook::ssrf::ssrf_agent(config);

            let mut req = agent
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Hearth-Event", &event_type)
                .header("X-Hearth-Delivery", &delivery_id);

            if let Some(ref sig) = signature {
                req = req.header("X-Hearth-Signature-256", sig.as_str());
            }

            req.send(&body[..])
                .map_err(|e| format!("HTTP error: {e}"))
                .and_then(|resp| {
                    let status: u16 = resp.status().into();
                    if (200..300).contains(&status) {
                        Ok(())
                    } else {
                        Err(format!("non-2xx response: {status}"))
                    }
                })
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(do_request)
            }
            _ => do_request(),
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Approval webhook delivery client.
///
/// Wraps a transport, handles signing and header assembly. Injectable via
/// [`ApprovalWebhookClient::with_transport`] for tests.
pub struct ApprovalWebhookClient {
    transport: Arc<dyn ApprovalWebhookTransport>,
}

impl Default for ApprovalWebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalWebhookClient {
    /// Creates a production client backed by [`UreqApprovalTransport`].
    pub fn new() -> Self {
        Self {
            transport: Arc::new(UreqApprovalTransport),
        }
    }

    /// Creates a client with an injected transport (for tests).
    pub fn with_transport(transport: Arc<dyn ApprovalWebhookTransport>) -> Self {
        Self { transport }
    }

    /// Delivers `payload` to the endpoint described by `config`.
    ///
    /// Returns `Ok(())` on HTTP 2xx, `Err(reason)` on any failure.
    pub(crate) fn deliver(
        &self,
        config: &ApprovalWebhookConfig,
        payload: &ApprovalWebhookPayload,
    ) -> Result<(), String> {
        let body = serde_json::to_vec(payload).map_err(|e| format!("serialization error: {e}"))?;
        let signature = config.secret.as_deref().map(|s| sign_body(s, &body));

        self.transport.send(
            &config.url,
            &body,
            EVENT_TYPE,
            &payload.delivery_id,
            signature.as_deref(),
            config.timeout_ms,
        )
    }
}

/// Signs `body` with HMAC-SHA256 using `secret`.
///
/// Returns `"sha256=<hex>"` — the same format used by `webhook/dispatcher.rs`
/// and GitHub's webhook signature convention.
fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(result))
}

/// Logs a warning when approval webhook delivery fails.
///
/// The outbox record persists — the background scanner will retry.
pub(crate) fn log_delivery_failure(request_id: &str, reason: &str) {
    warn!(
        request_id = %request_id,
        reason = %reason,
        "approval webhook delivery failed; outbox record retained for retry"
    );
}

/// Logs a debug message on successful delivery.
pub(crate) fn log_delivery_success(request_id: &str, url: &str) {
    debug!(
        request_id = %request_id,
        url = %url,
        "approval webhook delivered successfully"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Task 26.37 — the realm's `timeout_ms` must become a real bound.
    ///
    /// ureq 3.3.0's `Timeouts::default()` leaves every field `None` except
    /// `await_100`, so the previous config — `https_only` and `max_redirects`
    /// only — bounded nothing. The call runs inside
    /// `tokio::task::block_in_place`, so an approver's endpoint that completes
    /// the handshake and then stops responding took a Tokio *worker* thread
    /// out of service permanently.
    #[test]
    fn approval_agent_config_bounds_both_timeouts() {
        let config = approval_agent_config(2000);
        let timeouts = config.timeouts();

        assert_eq!(
            timeouts.global,
            Some(std::time::Duration::from_secs(2)),
            "the global bound must be the operator's number, not a default"
        );
        let connect = timeouts
            .connect
            .expect("a connect bound must be set, or a half-open handshake never returns");
        assert!(
            connect > std::time::Duration::ZERO && connect <= std::time::Duration::from_secs(2),
            "the connect bound must be positive and inside the overall budget; got {connect:?}"
        );
        assert!(
            config.https_only(),
            "approval webhook egress stays https-only"
        );
        assert_eq!(
            config.max_redirects(),
            crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS,
            "approval webhook egress must use the shared redirect cap"
        );
    }

    /// Control — a pathological `timeout_ms` must still produce a usable bound.
    ///
    /// `0` would otherwise build a zero-duration connect timeout, which is not
    /// a tighter limit but a delivery that can never succeed.
    #[test]
    fn approval_agent_config_survives_a_zero_timeout() {
        let timeouts = approval_agent_config(0).timeouts();
        assert!(
            timeouts
                .connect
                .is_some_and(|d| d > std::time::Duration::ZERO),
            "a zero budget must not become a zero connect timeout"
        );
        assert!(
            timeouts
                .global
                .is_some_and(|d| d > std::time::Duration::ZERO),
            "a zero budget must not become a zero global timeout"
        );
    }

    #[test]
    fn sign_body_format() {
        let sig = sign_body("my-secret", b"hello");
        assert!(
            sig.starts_with("sha256="),
            "signature must start with sha256="
        );
        assert_eq!(sig.len(), 7 + 64, "sha256= prefix + 64 hex chars");
    }

    #[test]
    fn sign_body_deterministic() {
        let sig1 = sign_body("secret", b"payload");
        let sig2 = sign_body("secret", b"payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_body_differs_by_key_and_payload() {
        assert_ne!(sign_body("key1", b"payload"), sign_body("key2", b"payload"));
        assert_ne!(sign_body("key", b"a"), sign_body("key", b"b"));
    }
}

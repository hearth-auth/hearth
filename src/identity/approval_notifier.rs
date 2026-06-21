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

use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

use crate::identity::types::{ApprovalWebhookConfig, ApprovalWebhookPayload};

type HmacSha256 = Hmac<Sha256>;

const EVENT_TYPE: &str = "approval_requested";

/// Delivers `payload` to the endpoint described by `config`.
///
/// Returns `Ok(())` on HTTP 2xx, `Err(reason)` on any failure.
/// Uses `block_in_place` when called from a multi-threaded Tokio runtime so
/// the blocking `ureq` call does not stall the async executor.
pub(crate) fn deliver_approval_webhook(
    config: &ApprovalWebhookConfig,
    payload: &ApprovalWebhookPayload,
) -> Result<(), String> {
    let body = serde_json::to_vec(payload).map_err(|e| format!("serialization error: {e}"))?;

    let url = config.url.clone();
    let secret = config.secret.clone();
    let delivery_id = payload.delivery_id.clone();
    let timeout = Duration::from_millis(config.timeout_ms);

    let do_request = move || -> Result<(), String> {
        let signature = secret.as_deref().map(|s| sign_body(s, &body));

        let mut req = ureq::post(&url)
            .header("Content-Type", "application/json")
            .header("X-Hearth-Event", EVENT_TYPE)
            .header("X-Hearth-Delivery", &delivery_id);

        if let Some(sig) = &signature {
            req = req.header("X-Hearth-Signature-256", sig.as_str());
        }

        // ureq 3.x sets a default 30s timeout; honour the configured value
        // by constructing a custom agent when it differs from ureq's default.
        let _ = timeout; // future: wire via ureq::AgentBuilder

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

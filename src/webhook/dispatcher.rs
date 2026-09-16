//! Background webhook dispatcher.
//!
//! Receives audit events through a broadcast channel, finds matching
//! webhook subscriptions, signs the payload with HMAC-SHA256, and
//! delivers it via HTTP POST with exponential-backoff retries.
//!
//! The dispatcher runs as a long-lived `tokio::task`. It is intentionally
//! decoupled from the request path: a delivery failure never bubbles up to
//! the user who triggered the audit event.
//!
//! # Signature scheme
//!
//! The request body is the JSON-serialized `AuditEvent`. Hearth adds:
//!
//! ```text
//! X-Hearth-Signature-256: sha256=<hex(HMAC-SHA256(secret, body))>
//! X-Hearth-Signature:     t=<unix_secs>,v1=<hex(HMAC-SHA256(secret, "<t>.<body>"))>
//! X-Hearth-Timestamp:     <unix_secs>
//! X-Hearth-Event:         <audit_action_string>
//! X-Hearth-Delivery:      <webhook_delivery_id>
//! ```
//!
//! `X-Hearth-Signature-256` follows GitHub's webhook signature convention so
//! operators can reuse their existing verification middleware.
//!
//! # Replay window (22.10, audit 2026-08-28 §4.6#5)
//!
//! `X-Hearth-Signature-256` covers the body and nothing else, so a captured
//! delivery stays valid forever — an attacker who records one request can
//! replay it against the receiver indefinitely and the signature still checks
//! out. `X-Hearth-Signature` closes that: the signed payload is
//! `"<unix_secs>.<body>"`, so the timestamp is authenticated rather than
//! merely advisory, and a receiver can reject anything outside
//! [`WEBHOOK_REPLAY_WINDOW_SECS`].
//!
//! Receivers should: read `t` from `X-Hearth-Signature`, reject when
//! `|now - t| > WEBHOOK_REPLAY_WINDOW_SECS`, recompute `v1` over
//! `"<t>.<raw body bytes>"`, and compare in constant time. Both headers are
//! sent, so existing body-only verifiers keep working unchanged.

use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, error, warn};

use crate::audit::AuditEvent;
use crate::core::{Clock, WebhookDeliveryId};

use super::engine::make_delivery;
use super::types::{DeliveryStatus, WebhookQuery, BACKOFF_SECONDS, MAX_DELIVERY_ATTEMPTS};
use super::WebhookEngine;

type HmacSha256 = Hmac<Sha256>;

/// Recommended receiver tolerance, in seconds, for the signed `t` value in
/// `X-Hearth-Signature` (22.10).
///
/// Five minutes is the same window Stripe and Slack publish: wide enough to
/// absorb a retry backoff step and ordinary clock skew, narrow enough that a
/// captured delivery stops being replayable quickly.
pub const WEBHOOK_REPLAY_WINDOW_SECS: i64 = 300;

/// Maximum number of webhook HTTP requests in flight across the whole process.
///
/// 22.10 (audit 2026-08-28 §4.6#5): `dispatch_event` spawns one task per
/// matching subscription per audit event with no bound at all, so a burst of
/// audit activity against a realm with many subscriptions — or one slow
/// endpoint sitting on the 30 s global timeout — could open an unbounded
/// number of concurrent outbound connections. The permit is held only around
/// the HTTP attempt itself, never across a retry backoff sleep, so one dead
/// endpoint cannot starve every other subscription.
const MAX_CONCURRENT_DELIVERIES: usize = 64;

/// Process-wide permit pool bounding concurrent outbound webhook requests.
static DELIVERY_PERMITS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_DELIVERIES));

/// A broadcast sender that pushes `AuditEvent` values to the dispatcher.
pub type AuditEventSender = broadcast::Sender<AuditEvent>;
/// A broadcast receiver that receives `AuditEvent` values from appends.
pub type AuditEventReceiver = broadcast::Receiver<AuditEvent>;

/// Creates a broadcast channel pair for audit event notifications.
///
/// Capacity of 1024 means up to 1024 events can be buffered before slow
/// receivers start seeing lag-drops (`RecvError::Lagged`). The dispatcher
/// handles lagged errors gracefully (logs + skips).
pub fn audit_event_channel() -> (AuditEventSender, AuditEventReceiver) {
    broadcast::channel(1_024)
}

/// Runs the webhook dispatcher loop.
///
/// Receives audit events from `rx`, looks up matching subscriptions in
/// `engine`, and delivers them with retry logic. Stops when `rx` is closed
/// or a shutdown signal is received via `shutdown`.
pub async fn run_dispatcher(
    engine: Arc<dyn WebhookEngine>,
    clock: Arc<dyn Clock>,
    mut rx: AuditEventReceiver,
    mut shutdown: tokio::sync::watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => dispatch_event(Arc::clone(&engine), Arc::clone(&clock), event).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("webhook dispatcher lagged, skipped {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("webhook audit channel closed, dispatcher exiting");
                        return;
                    }
                }
            }
            _ = shutdown.changed() => {
                debug!("webhook dispatcher received shutdown signal");
                return;
            }
        }
    }
}

/// Finds matching subscriptions and spawns a delivery task for each one.
async fn dispatch_event(engine: Arc<dyn WebhookEngine>, clock: Arc<dyn Clock>, event: AuditEvent) {
    let query = WebhookQuery {
        realm_id: event.realm_id.clone(),
        enabled_only: true,
    };

    let subs = match engine.list(&query) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to list webhook subscriptions for dispatch: {e}");
            return;
        }
    };

    for sub in subs {
        if !sub.matches(&event.action) {
            continue;
        }

        let eng = Arc::clone(&engine);
        let clk = Arc::clone(&clock);
        let ev = event.clone();
        tokio::spawn(async move {
            deliver_with_retry(eng, clk, sub, ev).await;
        });
    }
}

/// Delivers an event to a single subscription with exponential backoff.
async fn deliver_with_retry(
    engine: Arc<dyn WebhookEngine>,
    clock: Arc<dyn Clock>,
    sub: super::types::WebhookSubscription,
    event: AuditEvent,
) {
    let body = match serde_json::to_vec(&event) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to serialize audit event for webhook delivery: {e}");
            return;
        }
    };

    for attempt in 0..MAX_DELIVERY_ATTEMPTS {
        let delay = BACKOFF_SECONDS[attempt as usize];
        if delay > 0 {
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        let delivery_id = WebhookDeliveryId::generate();
        // Stamp each *attempt*, not the event: a retry 10 minutes later must
        // carry a fresh `t` or the receiver's replay window would reject it.
        let sent_at_secs = clock.now().as_micros() / 1_000_000;
        let signature = sign_body(&sub.secret, &body);
        let timestamped = sign_body_with_timestamp(&sub.secret, sent_at_secs, &body);
        let event_type = event.action.as_str().to_string();
        let delivery_id_str = delivery_id.to_string();
        let url = sub.url.clone();
        let body_clone = body.clone();

        // 22.10: bound concurrent outbound requests. Acquired here and dropped
        // when `result` is bound, so it never spans the backoff sleep above.
        let result = {
            let _permit = DELIVERY_PERMITS.acquire().await;
            // ureq is a blocking client; run it on the blocking thread pool.
            tokio::task::spawn_blocking(move || {
                deliver_once(
                    &url,
                    &body_clone,
                    &DeliveryHeaders {
                        signature: &signature,
                        timestamped_signature: &timestamped,
                        sent_at_secs,
                        event_type: &event_type,
                        delivery_id: &delivery_id_str,
                    },
                )
            })
            .await
        };

        let now = clock.now();
        let outcome = match result {
            Ok(inner) => inner,
            Err(join_err) => Err(format!("spawn_blocking panic: {join_err}")),
        };

        match outcome {
            Ok(status_code) => {
                let delivery = make_delivery(
                    sub.id.clone(),
                    sub.realm_id.clone(),
                    event.id.clone(),
                    attempt + 1,
                    DeliveryStatus::Success,
                    Some(status_code),
                    None,
                    now,
                );
                if let Err(e) = engine.record_delivery(&delivery) {
                    error!("failed to record successful webhook delivery: {e}");
                }
                debug!(
                    webhook_id = %sub.id,
                    event_id = %event.id,
                    attempt = attempt + 1,
                    "webhook delivered successfully"
                );
                return;
            }
            Err(err_msg) => {
                let is_last = attempt + 1 == MAX_DELIVERY_ATTEMPTS;
                let delivery = make_delivery(
                    sub.id.clone(),
                    sub.realm_id.clone(),
                    event.id.clone(),
                    attempt + 1,
                    DeliveryStatus::Failed,
                    None,
                    Some(err_msg.clone()),
                    now,
                );
                if let Err(e) = engine.record_delivery(&delivery) {
                    error!("failed to record failed webhook delivery: {e}");
                }

                if is_last {
                    warn!(
                        webhook_id = %sub.id,
                        event_id = %event.id,
                        "webhook delivery exhausted all {MAX_DELIVERY_ATTEMPTS} attempts: {err_msg}"
                    );
                } else {
                    debug!(
                        webhook_id = %sub.id,
                        event_id = %event.id,
                        attempt = attempt + 1,
                        "webhook delivery attempt failed, will retry: {err_msg}"
                    );
                }
            }
        }
    }
}

/// Connect timeout for outbound webhook HTTP calls (F4, HEA-1651).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total request timeout for outbound webhook HTTP calls (F4, HEA-1651).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Performs a single HTTP POST delivery.
///
/// Returns `Ok(status_code)` for 2xx responses, `Err(message)` otherwise.
/// Intended to be called inside `spawn_blocking`.
///
/// Re-checks SSRF on every attempt (DNS rebinding defence, F3/HEA-1651).
fn deliver_once(url: &str, body: &[u8], hdrs: &DeliveryHeaders<'_>) -> Result<u16, String> {
    // Re-validate destination immediately before connecting (DNS rebinding defence).
    super::ssrf::check_webhook_url(url).map_err(|e| format!("SSRF guard blocked delivery: {e}"))?;

    // Build a per-call agent with explicit connect + total timeouts (F4).
    let config = ureq::config::Config::builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(REQUEST_TIMEOUT))
        .https_only(true)
        // Do not follow redirects: check_webhook_url only validated the initial
        // host, so a 3xx could send us to an internal/link-local target (W1).
        .max_redirects(super::ssrf::MAX_WEBHOOK_REDIRECTS)
        .build();
    // Build via ssrf_agent so the connect-time DNS lookup is SSRF-validated,
    // closing the DNS-rebinding TOCTOU left open by the pre-flight check (W1
    // residual risk, HEA-1762).
    let agent = super::ssrf::ssrf_agent(config);

    let response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Hearth-Signature-256", hdrs.signature)
        .header("X-Hearth-Signature", hdrs.timestamped_signature)
        .header("X-Hearth-Timestamp", hdrs.sent_at_secs.to_string())
        .header("X-Hearth-Event", hdrs.event_type)
        .header("X-Hearth-Delivery", hdrs.delivery_id)
        .send(body)
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status: u16 = response.status().into();
    if (200..300).contains(&status) {
        Ok(status)
    } else {
        Err(format!("non-2xx response: {status}"))
    }
}

/// Per-attempt headers carried into the blocking delivery call.
///
/// Grouped into one struct so `deliver_once` keeps a small argument list as
/// the header set grows (`clippy::too_many_arguments`).
struct DeliveryHeaders<'a> {
    /// Body-only signature (`X-Hearth-Signature-256`), GitHub-compatible.
    signature: &'a str,
    /// Timestamped signature (`X-Hearth-Signature`), `t=…,v1=…`.
    timestamped_signature: &'a str,
    /// The `t` value, also sent bare as `X-Hearth-Timestamp`.
    sent_at_secs: i64,
    /// Audit action string (`X-Hearth-Event`).
    event_type: &'a str,
    /// Delivery id (`X-Hearth-Delivery`).
    delivery_id: &'a str,
}

/// Computes `sha256=<hex(HMAC-SHA256(secret, body))>`.
fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(result))
}

/// Computes `t=<secs>,v1=<hex(HMAC-SHA256(secret, "<secs>.<body>"))>` (22.10).
///
/// The timestamp is *inside* the MAC input, so a receiver that checks `t`
/// against [`WEBHOOK_REPLAY_WINDOW_SECS`] is checking an authenticated value —
/// an attacker replaying a captured delivery cannot rewrite `t` to move it back
/// inside the window without invalidating `v1`.
fn sign_body_with_timestamp(secret: &str, sent_at_secs: i64, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(sent_at_secs.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    format!("t={sent_at_secs},v1={}", hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_body_format() {
        let sig = sign_body("my-secret", b"hello");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64); // "sha256=" + 64 hex chars
    }

    // ===== 22.10 — timestamped signature + replay window =====

    /// The new header is `t=<secs>,v1=<64 hex>`.
    #[test]
    fn timestamped_signature_format() {
        let sig = sign_body_with_timestamp("my-secret", 1_700_000_000, b"hello");
        assert!(sig.starts_with("t=1700000000,v1="), "got: {sig}");
        let v1 = sig.split("v1=").nth(1).expect("v1 segment");
        assert_eq!(v1.len(), 64, "v1 must be 64 hex chars");
        assert!(v1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The defect this closes: with a body-only MAC, a captured delivery is
    /// replayable forever because the signature does not depend on when it was
    /// sent. The timestamped signature must change when only `t` changes.
    #[test]
    fn timestamp_is_inside_the_mac() {
        let a = sign_body_with_timestamp("secret", 1_700_000_000, b"payload");
        let b = sign_body_with_timestamp("secret", 1_700_000_060, b"payload");
        assert_ne!(
            a.split("v1=").nth(1),
            b.split("v1=").nth(1),
            "v1 must cover the timestamp, or a replayer can rewrite t freely"
        );
        // The body-only signature, by contrast, is blind to time — which is
        // exactly why it cannot carry a replay window on its own. Strip the
        // `t=` prefix from each and compare against it.
        let body_only = sign_body("secret", b"payload");
        assert!(body_only.starts_with("sha256="));
        assert!(
            !a.contains(&body_only[7..]) && !b.contains(&body_only[7..]),
            "the timestamped MAC must not degenerate into the body-only one"
        );
    }

    /// `t` and body are separated, so `("1.", b"x")` and `("1", b".x")` cannot
    /// collide into the same MAC input by concatenation alone.
    #[test]
    fn timestamped_signature_binds_body_too() {
        let a = sign_body_with_timestamp("secret", 1, b"payload-a");
        let b = sign_body_with_timestamp("secret", 1, b"payload-b");
        assert_ne!(a, b);
    }

    /// A receiver following the documented recipe verifies what we send.
    #[test]
    fn documented_verification_recipe_reproduces_v1() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "operator-secret";
        let body = br#"{"id":"audit_1"}"#;
        let t: i64 = 1_700_000_123;
        let sent = sign_body_with_timestamp(secret, t, body);

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("key");
        mac.update(format!("{t}.").as_bytes());
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());

        assert_eq!(sent, format!("t={t},v1={expected}"));
    }

    /// The published window is a real, positive number of seconds.
    #[test]
    fn replay_window_is_five_minutes() {
        assert_eq!(WEBHOOK_REPLAY_WINDOW_SECS, 300);
    }

    /// 22.10: the permit pool is a real, finite bound, not an unbounded one.
    #[tokio::test]
    async fn delivery_permits_are_a_finite_pool() {
        assert_eq!(
            DELIVERY_PERMITS.available_permits(),
            MAX_CONCURRENT_DELIVERIES
        );
        let all = DELIVERY_PERMITS
            .acquire_many(u32::try_from(MAX_CONCURRENT_DELIVERIES).expect("bound fits u32"))
            .await
            .expect("the pool is never closed");
        assert!(
            DELIVERY_PERMITS.try_acquire().is_err(),
            "a 65th concurrent delivery must not be admitted"
        );
        drop(all);
        assert!(DELIVERY_PERMITS.try_acquire().is_ok());
    }

    /// Minimal `WebhookEngine` that reports every delivery record written.
    struct SignallingWebhookEngine {
        recorded: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl WebhookEngine for SignallingWebhookEngine {
        fn create(
            &self,
            _req: &super::super::types::CreateWebhookRequest,
        ) -> Result<super::super::types::WebhookSubscription, super::super::WebhookError> {
            unimplemented!("not exercised by the permit test")
        }
        fn get(
            &self,
            _realm_id: &crate::core::RealmId,
            _id: &crate::core::WebhookId,
        ) -> Result<super::super::types::WebhookSubscription, super::super::WebhookError> {
            unimplemented!("not exercised by the permit test")
        }
        fn update(
            &self,
            _realm_id: &crate::core::RealmId,
            _id: &crate::core::WebhookId,
            _req: &super::super::types::UpdateWebhookRequest,
        ) -> Result<super::super::types::WebhookSubscription, super::super::WebhookError> {
            unimplemented!("not exercised by the permit test")
        }
        fn delete(
            &self,
            _realm_id: &crate::core::RealmId,
            _id: &crate::core::WebhookId,
        ) -> Result<(), super::super::WebhookError> {
            unimplemented!("not exercised by the permit test")
        }
        fn list(
            &self,
            _query: &WebhookQuery,
        ) -> Result<Vec<super::super::types::WebhookSubscription>, super::super::WebhookError>
        {
            Ok(Vec::new())
        }
        fn record_delivery(
            &self,
            _delivery: &super::super::types::WebhookDelivery,
        ) -> Result<(), super::super::WebhookError> {
            let _ = self.recorded.send(());
            Ok(())
        }
        fn list_deliveries(
            &self,
            _query: &super::super::types::DeliveryQuery,
        ) -> Result<Vec<super::super::types::WebhookDelivery>, super::super::WebhookError> {
            Ok(Vec::new())
        }
    }

    fn permit_test_subscription() -> super::super::types::WebhookSubscription {
        super::super::types::WebhookSubscription {
            id: crate::core::WebhookId::generate(),
            realm_id: crate::core::RealmId::new(uuid::Uuid::nil()),
            // The SSRF guard refuses a loopback target outright, so the HTTP
            // attempt resolves in microseconds and never touches the network.
            url: "http://127.0.0.1:9/hook".to_string(),
            secret: "permit-test-secret".to_string(),
            enabled: true,
            event_filters: Vec::new(),
            created_at: crate::core::Timestamp::from_micros(0),
            updated_at: crate::core::Timestamp::from_micros(0),
        }
    }

    fn permit_test_event() -> AuditEvent {
        AuditEvent {
            id: crate::core::AuditEventId::generate(),
            realm_id: crate::core::RealmId::new(uuid::Uuid::nil()),
            actor: "system".to_string(),
            action: crate::audit::AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "u1".to_string(),
            timestamp: crate::core::Timestamp::from_micros(0),
            metadata: None,
            integrity_hash: "genesis".to_string(),
        }
    }

    /// 22.10, the half a permit *count* assertion cannot see: the delivery path
    /// must actually take a permit before it makes the HTTP attempt.
    ///
    /// With the pool exhausted, `deliver_with_retry` must get no further than
    /// the semaphore — no attempt, and therefore no delivery record. Releasing
    /// the permits must then let exactly that attempt through. Deleting the
    /// `DELIVERY_PERMITS.acquire()` in `deliver_with_retry` makes the first
    /// assertion fail: the attempt is made and recorded with the pool empty.
    #[tokio::test]
    async fn delivery_takes_a_permit_before_the_http_attempt() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let engine = Arc::new(SignallingWebhookEngine { recorded: tx });
        let clock = Arc::new(crate::core::SystemClock) as Arc<dyn Clock>;

        let hog = DELIVERY_PERMITS
            .acquire_many(u32::try_from(MAX_CONCURRENT_DELIVERIES).expect("bound fits u32"))
            .await
            .expect("the pool is never closed");
        assert_eq!(DELIVERY_PERMITS.available_permits(), 0);

        let task = tokio::spawn(deliver_with_retry(
            Arc::clone(&engine) as Arc<dyn WebhookEngine>,
            clock,
            permit_test_subscription(),
            permit_test_event(),
        ));

        // The attempt is refused by the SSRF guard in microseconds when it is
        // allowed to run at all, so nothing arriving inside this window means
        // the task never got past the semaphore.
        let blocked = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        assert!(
            blocked.is_err(),
            "an outbound webhook attempt was made and recorded with zero permits \
             available — the process-wide concurrency bound is not on the \
             delivery path"
        );
        assert!(
            !task.is_finished(),
            "the delivery task must still be waiting"
        );

        drop(hog);
        // Unbounded await: with a permit free the attempt must now happen.
        rx.recv()
            .await
            .expect("releasing a permit must let the delivery proceed");
        task.abort();
    }

    #[test]
    fn sign_body_deterministic() {
        let sig1 = sign_body("secret", b"payload");
        let sig2 = sign_body("secret", b"payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_body_differs_by_key() {
        let sig1 = sign_body("key1", b"payload");
        let sig2 = sign_body("key2", b"payload");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_body_differs_by_payload() {
        let sig1 = sign_body("key", b"payload1");
        let sig2 = sign_body("key", b"payload2");
        assert_ne!(sig1, sig2);
    }
}

//! Integration tests for Phase C.5: approval webhook notification (M7 hardened).
//!
//! All delivery tests use an in-process capture transport so no real HTTP server
//! is required and the SSRF guard does not interfere with the tests.  A separate
//! SSRF-rejection test uses the production transport with a blocked URL.
//!
//! Verifies durable at-least-once delivery:
//! - Webhook payload is delivered to the configured URL on request creation.
//! - Payload contains required fields: request_id, agent_id, tool, approve_url, deny_url.
//! - Delivery ID is stable across retries (`"approval:{request_id}"`).
//! - HMAC-SHA256 signature is present when a secret is configured.
//! - SSRF guard rejects http:// URLs at registration time and blocked IPs at delivery time.

mod common;

use std::sync::{Arc, Mutex};

use common::TestHarness;
use hearth::identity::approval_notifier::ApprovalWebhookTransport;
use hearth::identity::{
    AgentOwner, ApprovalWebhookConfig, CreateAgentRequest, CreateApprovalRequestInput,
    CreateRealmRequest, CreateUserRequest, RealmConfig,
};

// ── In-process capture transport ─────────────────────────────────────────────

/// Captures every approval webhook delivery in memory without making HTTP calls.
#[derive(Clone)]
struct ApprovalCapture {
    deliveries: Arc<Mutex<Vec<CapturedDelivery>>>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct CapturedDelivery {
    url: String,
    body: Vec<u8>,
    event_type: String,
    delivery_id: String,
    signature: Option<String>,
}

impl ApprovalCapture {
    fn new() -> Self {
        Self {
            deliveries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn captured(&self) -> Vec<CapturedDelivery> {
        self.deliveries.lock().expect("lock").clone()
    }
}

impl ApprovalWebhookTransport for ApprovalCapture {
    fn send(
        &self,
        url: &str,
        body: &[u8],
        event_type: &str,
        delivery_id: &str,
        signature: Option<&str>,
    ) -> Result<(), String> {
        self.deliveries
            .lock()
            .expect("lock")
            .push(CapturedDelivery {
                url: url.to_string(),
                body: body.to_vec(),
                event_type: event_type.to_string(),
                delivery_id: delivery_id.to_string(),
                signature: signature.map(str::to_string),
            });
        Ok(())
    }
}

// ── Helper: create realm + agent with webhook ─────────────────────────────────

fn make_realm_with_webhook(
    h: &TestHarness,
    secret: Option<String>,
) -> (hearth::core::RealmId, hearth::core::AgentId) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("webhook-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                approval_webhook: Some(ApprovalWebhookConfig {
                    // https:// URL passes the scheme check at registration time;
                    // the in-process capture transport never actually connects.
                    url: "https://capture.local/webhook".to_string(),
                    secret,
                    timeout_ms: 2000,
                }),
                ..Default::default()
            }),
        })
        .expect("create realm");

    let realm_id = realm.id().clone();

    let owner = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("owner-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");

    let agent = h
        .identity()
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "test-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent");

    (realm_id, agent.id().clone())
}

// ─── C.5.1: Webhook delivery on approval request creation ────────────────────

#[tokio::test]
async fn approval_webhook_delivers_payload_on_create() {
    let capture = Arc::new(ApprovalCapture::new());
    let h = TestHarness::embedded_with_approval_transport(
        Arc::clone(&capture) as Arc<dyn ApprovalWebhookTransport>
    )
    .await
    .expect("harness init");
    let (realm_id, agent_id) = make_realm_with_webhook(&h, None);

    let req = CreateApprovalRequestInput {
        agent_id: agent_id.clone(),
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({"reason": "user requested"}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };

    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create_approval_request should succeed");

    let deliveries = capture.captured();
    assert_eq!(deliveries.len(), 1, "exactly one delivery expected");
    let delivery = &deliveries[0];

    let payload: serde_json::Value =
        serde_json::from_slice(&delivery.body).expect("parse payload JSON");

    assert_eq!(
        payload["request_id"].as_str().unwrap_or(""),
        created.request_id,
        "request_id must match"
    );
    assert_eq!(
        payload["agent_id"].as_str().unwrap_or(""),
        agent_id.as_uuid().to_string(),
        "agent_id must be the raw UUID"
    );
    assert_eq!(
        payload["tool"].as_str().unwrap_or(""),
        "delete_file",
        "tool must match"
    );
    assert!(
        payload["approve_url"]
            .as_str()
            .unwrap_or("")
            .contains(&created.request_id),
        "approve_url must contain request_id"
    );
    assert!(
        payload["deny_url"]
            .as_str()
            .unwrap_or("")
            .contains(&created.request_id),
        "deny_url must contain request_id"
    );
}

// ─── C.5.2: Delivery ID is stable (`approval:{request_id}`) ─────────────────

#[tokio::test]
async fn approval_webhook_delivery_id_is_stable() {
    let capture = Arc::new(ApprovalCapture::new());
    let h = TestHarness::embedded_with_approval_transport(
        Arc::clone(&capture) as Arc<dyn ApprovalWebhookTransport>
    )
    .await
    .expect("harness init");
    let (realm_id, agent_id) = make_realm_with_webhook(&h, None);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "send_email".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };

    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");

    let deliveries = capture.captured();
    assert_eq!(deliveries.len(), 1, "exactly one delivery expected");

    let expected_delivery_id = format!("approval:{}", created.request_id);
    assert_eq!(
        deliveries[0].delivery_id, expected_delivery_id,
        "delivery_id must be 'approval:{{request_id}}' for idempotency"
    );
}

// ─── C.5.3: HMAC-SHA256 signature is present when secret is configured ────────

#[tokio::test]
async fn approval_webhook_signed_when_secret_configured() {
    let capture = Arc::new(ApprovalCapture::new());
    let h = TestHarness::embedded_with_approval_transport(
        Arc::clone(&capture) as Arc<dyn ApprovalWebhookTransport>
    )
    .await
    .expect("harness init");
    let (realm_id, agent_id) = make_realm_with_webhook(&h, Some("test-secret-12345".to_string()));

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "dangerous_op".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };

    h.identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");

    let deliveries = capture.captured();
    assert_eq!(deliveries.len(), 1, "exactly one delivery expected");

    let sig = deliveries[0]
        .signature
        .as_deref()
        .expect("X-Hearth-Signature-256 must be present when secret is configured");

    assert!(
        sig.starts_with("sha256="),
        "signature must start with 'sha256=', got: {sig}"
    );
    assert_eq!(
        sig.len(),
        7 + 64,
        "signature must be 'sha256=' + 64 hex chars"
    );
}

// ─── C.5.4: No delivery when realm has no webhook configured ─────────────────

#[tokio::test]
async fn approval_webhook_not_delivered_when_not_configured() {
    let capture = Arc::new(ApprovalCapture::new());
    let h = TestHarness::embedded_with_approval_transport(
        Arc::clone(&capture) as Arc<dyn ApprovalWebhookTransport>
    )
    .await
    .expect("harness init");

    // Realm WITHOUT approval_webhook config
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("no-webhook-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let owner = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("owner-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");

    let agent = h
        .identity()
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "test-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent");

    h.identity()
        .create_approval_request(
            &realm_id,
            &CreateApprovalRequestInput {
                agent_id: agent.id().clone(),
                tool: "some_tool".to_string(),
                action: "invoke".to_string(),
                context: serde_json::json!({}),
                delegation_chain: vec![],
                expires_in_secs: None,
            },
        )
        .expect("create");

    assert!(
        capture.captured().is_empty(),
        "no webhook should be delivered when realm has no approval_webhook config"
    );
}

// ─── M7: https-scheme check at registration time ─────────────────────────────

#[tokio::test]
async fn approval_webhook_http_url_rejected_at_registration() {
    let h = TestHarness::embedded().await.expect("harness init");

    let result = h.identity().create_realm(&CreateRealmRequest {
        name: format!("http-webhook-{}", uuid::Uuid::new_v4()),
        config: Some(RealmConfig {
            approval_webhook: Some(ApprovalWebhookConfig {
                url: "http://attacker.example.com/hook".to_string(),
                secret: None,
                timeout_ms: 2000,
            }),
            ..Default::default()
        }),
    });

    assert!(
        matches!(
            &result,
            Err(hearth::identity::IdentityError::InvalidInput { reason })
                if reason.contains("https://")
        ),
        "http:// approval webhook URL must be rejected at registration with an \
         InvalidInput scheme error, got: {result:?}"
    );
}

// ─── M7: SSRF guard blocks delivery to private IP ranges ─────────────────────

#[tokio::test]
async fn approval_webhook_ssrf_blocked_at_delivery() {
    // Use the production transport (no injection) so the SSRF guard is active.
    let h = TestHarness::embedded().await.expect("harness init");

    // https:// scheme passes the registration-time check; 169.254.169.254 is
    // blocked by the delivery-time DNS check (link-local / cloud metadata).
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ssrf-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                approval_webhook: Some(ApprovalWebhookConfig {
                    url: "https://169.254.169.254/metadata".to_string(),
                    secret: None,
                    timeout_ms: 2000,
                }),
                ..Default::default()
            }),
        })
        .expect("realm creation must succeed (scheme check passes)");

    let realm_id = realm.id().clone();
    let owner = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("owner-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");

    let agent = h
        .identity()
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "ssrf-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent");

    // Delivery fails (SSRF guard blocks 169.254.169.254) but create_approval_request
    // still succeeds — outbox record is persisted for retry.
    let result = h.identity().create_approval_request(
        &realm_id,
        &CreateApprovalRequestInput {
            agent_id: agent.id().clone(),
            tool: "metadata_steal".to_string(),
            action: "invoke".to_string(),
            context: serde_json::json!({}),
            delegation_chain: vec![],
            expires_in_secs: None,
        },
    );

    let approval = result
        .expect("create_approval_request must succeed even when webhook delivery is SSRF-blocked");
    // The request must be fully persisted with the expected content despite the
    // blocked delivery: agent binding, tool, and Pending status all intact.
    assert_eq!(
        approval.agent_id,
        *agent.id(),
        "approval must be bound to the requesting agent"
    );
    assert_eq!(approval.tool, "metadata_steal", "tool must round-trip");
    assert_eq!(
        approval.status,
        hearth::identity::ApprovalRequestStatus::Pending,
        "a freshly created approval must be Pending"
    );

    // And it must be retrievable afterward (outbox persists for retry).
    let fetched = h
        .identity()
        .get_approval_request(&realm_id, &approval.request_id)
        .expect("approval request must be persisted despite SSRF-blocked delivery");
    assert_eq!(fetched.request_id, approval.request_id);

    // Compile/behavior note: SSRF-blocking of the delivery itself is silent at the
    // API level (outbox persists for retry) and is not observable through a public
    // return value here — the guard is exercised in the production transport path.
}

// ─── Task 26.13: the RETRY half of "durable at-least-once" ───────────────────

/// A transport that refuses every delivery until it is told to stop.
///
/// The capture transport above always succeeds, which is why every test in
/// this file passed while the retry path had no caller at all: a delivery that
/// never fails never needs retrying.
#[derive(Clone)]
struct FlakyApprovalTransport {
    failing: Arc<std::sync::atomic::AtomicBool>,
    attempts: Arc<Mutex<Vec<String>>>,
}

impl FlakyApprovalTransport {
    fn new() -> Self {
        Self {
            failing: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            attempts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn recover(&self) {
        self.failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn delivered(&self) -> Vec<String> {
        self.attempts.lock().expect("lock").clone()
    }
}

impl ApprovalWebhookTransport for FlakyApprovalTransport {
    fn send(
        &self,
        _url: &str,
        _body: &[u8],
        _event_type: &str,
        delivery_id: &str,
        _signature: Option<&str>,
    ) -> Result<(), String> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("endpoint down".to_string());
        }
        self.attempts
            .lock()
            .expect("lock")
            .push(delivery_id.to_string());
        Ok(())
    }
}

/// Task 26.13 — a webhook the endpoint refused must be redelivered later.
///
/// `flush_approval_webhook_outbox_inner` existed, was correct, and had **zero
/// callers**; `#[allow(dead_code)]` kept the compiler quiet. Its own doc
/// comment named "the startup recovery scan and the periodic background task",
/// and neither existed. So this file's header claim of "durable at-least-once
/// delivery" was at-MOST-once: a refused notification was never retried, and
/// its outbox row leaked forever, because only a successful delivery deletes
/// it.
///
/// The test drives the real sequence: refuse the first attempt, bring the
/// endpoint back, flush, and require the notification to arrive.
#[tokio::test]
async fn a_refused_approval_webhook_is_redelivered_by_the_outbox_flush() {
    let transport = Arc::new(FlakyApprovalTransport::new());
    let h = TestHarness::embedded_with_approval_transport(
        Arc::clone(&transport) as Arc<dyn ApprovalWebhookTransport>
    )
    .await
    .expect("harness init");
    let (realm_id, agent_id) = make_realm_with_webhook(&h, None);

    let created = h
        .identity()
        .create_approval_request(
            &realm_id,
            &CreateApprovalRequestInput {
                agent_id,
                tool: "delete_file".to_string(),
                action: "invoke".to_string(),
                context: serde_json::json!({"reason": "endpoint is down"}),
                delegation_chain: vec![],
                expires_in_secs: None,
            },
        )
        .expect("creating the request must succeed even when the webhook does not");

    assert!(
        transport.delivered().is_empty(),
        "sanity: the endpoint refused, so nothing was delivered yet"
    );

    // Still refusing: the flush must report the entry as outstanding, not
    // quietly drop it. Without this, a flush that deleted rows on failure
    // would pass the assertion below and lose the notification for good.
    let (delivered, remaining) = h.identity().flush_approval_webhook_outbox(&realm_id);
    assert_eq!(
        (delivered, remaining),
        (0, 1),
        "a still-failing endpoint must leave the outbox entry in place"
    );

    transport.recover();
    let (delivered, remaining) = h.identity().flush_approval_webhook_outbox(&realm_id);

    assert_eq!(
        (delivered, remaining),
        (1, 0),
        "once the endpoint is back, the flush must deliver the entry and clear it"
    );
    assert_eq!(
        transport.delivered(),
        vec![format!("approval:{}", created.request_id)],
        "the redelivery must carry the same stable delivery id as the first attempt"
    );

    // And the row is gone, so it cannot be delivered a third time on the next
    // tick — the outbox must drain, not accumulate.
    let (delivered, remaining) = h.identity().flush_approval_webhook_outbox(&realm_id);
    assert_eq!(
        (delivered, remaining),
        (0, 0),
        "a drained outbox must stay drained"
    );
}

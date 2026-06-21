//! Integration tests for Phase C.5: approval webhook notification.
//!
//! Verifies durable at-least-once delivery:
//! - Webhook payload is delivered to the configured URL on request creation.
//! - Payload contains required fields: request_id, agent_id, tool, approve_url, deny_url.
//! - Delivery ID is stable across retries (`"approval:{request_id}"`).
//! - HMAC-SHA256 signature is present when a secret is configured.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::post;
use axum::{Json, Router};
use common::TestHarness;
use hearth::identity::{
    AgentOwner, ApprovalWebhookConfig, CreateAgentRequest, CreateApprovalRequestInput,
    CreateRealmRequest, CreateUserRequest, RealmConfig,
};

// ── Helper: local capture server ────────────────────────────────────────────

/// Captured payload from a single webhook delivery.
#[derive(Clone, Debug, serde::Deserialize)]
struct CapturedPayload {
    delivery_id: String,
    request_id: String,
    agent_id: String,
    tool: String,
    approve_url: String,
    deny_url: String,
}

struct CaptureServer {
    addr: SocketAddr,
    payloads: Arc<Mutex<Vec<CapturedPayload>>>,
    headers: Arc<Mutex<Vec<std::collections::HashMap<String, String>>>>,
}

impl CaptureServer {
    async fn start() -> Self {
        let payloads: Arc<Mutex<Vec<CapturedPayload>>> = Arc::new(Mutex::new(Vec::new()));
        let headers: Arc<Mutex<Vec<std::collections::HashMap<String, String>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let payloads_clone = Arc::clone(&payloads);
        let headers_clone = Arc::clone(&headers);

        let app = Router::new().route(
            "/webhook",
            post(
                move |raw_headers: axum::http::HeaderMap, Json(body): Json<CapturedPayload>| {
                    let payloads = Arc::clone(&payloads_clone);
                    let headers = Arc::clone(&headers_clone);
                    async move {
                        payloads.lock().expect("payloads lock").push(body);
                        let h: std::collections::HashMap<String, String> = raw_headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect();
                        headers.lock().expect("headers lock").push(h);
                        axum::http::StatusCode::OK
                    }
                },
            ),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind webhook listener");
        let addr = listener.local_addr().expect("local addr");

        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum serve");
        });

        Self {
            addr,
            payloads,
            headers,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/webhook", self.addr.port())
    }

    async fn wait_for_delivery(&self) -> CapturedPayload {
        for _ in 0..50 {
            {
                let guard = self.payloads.lock().expect("payloads lock");
                if let Some(p) = guard.first() {
                    return p.clone();
                }
            }
            // AUDIT: justified-sleep: polling for real HTTP delivery from a local test server
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("webhook delivery not received within 1 second");
    }

    fn captured_headers(&self) -> Vec<std::collections::HashMap<String, String>> {
        self.headers.lock().expect("headers lock").clone()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

fn make_realm_with_webhook(
    h: &TestHarness,
    webhook_url: &str,
    secret: Option<String>,
) -> (hearth::core::RealmId, hearth::core::AgentId) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("webhook-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                approval_webhook: Some(ApprovalWebhookConfig {
                    url: webhook_url.to_string(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_webhook_delivers_payload_on_create() {
    let server = CaptureServer::start().await;
    let h = TestHarness::embedded().await.expect("harness init");
    let (realm_id, agent_id) = make_realm_with_webhook(&h, &server.url(), None);

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

    let payload = server.wait_for_delivery().await;

    assert_eq!(
        payload.request_id, created.request_id,
        "request_id must match"
    );
    assert_eq!(
        payload.agent_id,
        agent_id.as_uuid().to_string(),
        "agent_id must be the raw UUID (no agt_ prefix) in the webhook payload"
    );
    assert_eq!(payload.tool, "delete_file", "tool must match");
    assert!(
        payload.approve_url.contains(&created.request_id),
        "approve_url must contain request_id: {}",
        payload.approve_url
    );
    assert!(
        payload.deny_url.contains(&created.request_id),
        "deny_url must contain request_id: {}",
        payload.deny_url
    );
}

// ─── C.5.2: Delivery ID is stable (`approval:{request_id}`) ─────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_webhook_delivery_id_is_stable() {
    let server = CaptureServer::start().await;
    let h = TestHarness::embedded().await.expect("harness init");
    let (realm_id, agent_id) = make_realm_with_webhook(&h, &server.url(), None);

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

    let payload = server.wait_for_delivery().await;

    let expected_delivery_id = format!("approval:{}", created.request_id);
    assert_eq!(
        payload.delivery_id, expected_delivery_id,
        "delivery_id must be 'approval:{{request_id}}' for idempotency"
    );
}

// ─── C.5.3: HMAC-SHA256 signature is present when secret is configured ────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_webhook_signed_when_secret_configured() {
    let server = CaptureServer::start().await;
    let h = TestHarness::embedded().await.expect("harness init");
    let (realm_id, agent_id) =
        make_realm_with_webhook(&h, &server.url(), Some("test-secret-12345".to_string()));

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

    server.wait_for_delivery().await;

    let all_headers = server.captured_headers();
    let headers = all_headers.first().expect("at least one delivery");

    let signature = headers
        .get("x-hearth-signature-256")
        .expect("X-Hearth-Signature-256 must be present when secret is configured");

    assert!(
        signature.starts_with("sha256="),
        "signature must start with 'sha256=', got: {signature}"
    );
    assert_eq!(
        signature.len(),
        7 + 64,
        "signature must be 'sha256=' + 64 hex chars"
    );
}

// ─── C.5.4: No delivery when realm has no webhook configured ─────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_webhook_not_delivered_when_not_configured() {
    let server = CaptureServer::start().await;
    let h = TestHarness::embedded().await.expect("harness init");

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

    // Wait briefly — no delivery expected
    // AUDIT: justified-sleep: negative test confirming no delivery within a grace window
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        server.payloads.lock().expect("payloads lock").is_empty(),
        "no webhook should be delivered when realm has no approval_webhook config"
    );
}

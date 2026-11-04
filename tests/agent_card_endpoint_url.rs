//! #632, part 3 (OpenSpec `fix-spec-drift-defects` task 2.1): an agent has an
//! optional `endpoint_url`, and its Agent Card serves it as `url`
//! (`agent-identity`, "Regression — the card has no endpoint URL").
//!
//! The card always served `url: ""`, because an agent had no endpoint field.
//! Now the card serves the agent's endpoint, and leaves `url` out for an agent
//! that has none.

mod common;

use serde_json::{json, Value};

struct Api {
    client: reqwest::Client,
    base: String,
    realm_id: String,
    owner_id: String,
    token: String,
}

impl Api {
    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("Bearer {}", self.token))
            .header("X-Realm-ID", &self.realm_id)
    }

    /// `POST /v1/agents` with `extra` fields; returns the status and body.
    async fn create(&self, extra: Value) -> (u16, Value) {
        let mut body = json!({
            "display_name": "Card Agent",
            "owner_type": "user",
            "owner_id": self.owner_id,
            "capabilities": ["urn:hearth:capability:email:send"],
        });
        for (k, v) in extra.as_object().expect("object") {
            body[k] = v.clone();
        }
        let resp = self
            .auth(self.client.post(format!("{}/v1/agents", self.base)))
            .json(&body)
            .send()
            .await
            .expect("create request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn patch(&self, agent_id: &str, body: Value) -> u16 {
        self.auth(
            self.client
                .patch(format!("{}/v1/agents/{agent_id}", self.base)),
        )
        .json(&body)
        .send()
        .await
        .expect("patch request")
        .status()
        .as_u16()
    }

    async fn card(&self, agent_id: &str) -> Value {
        let resp = self
            .auth(self.client.get(format!(
                "{}/.well-known/agent.json?agent_id={agent_id}",
                self.base
            )))
            .send()
            .await
            .expect("card request");
        assert_eq!(resp.status().as_u16(), 200, "the card is served");
        resp.json().await.expect("card json")
    }
}

async fn api(h: &common::TestHarness) -> Api {
    let base = h.base_url().expect("base_url").to_string();
    let client = reqwest::Client::new();
    let boot: Value = client
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap")
        .json()
        .await
        .expect("bootstrap json");
    Api {
        client,
        base,
        realm_id: boot["realm_id"].as_str().expect("realm_id").to_string(),
        owner_id: boot["user_id"].as_str().expect("user_id").to_string(),
        token: boot["access_token"]
            .as_str()
            .expect("access_token")
            .to_string(),
    }
}

async fn harness() -> common::TestHarness {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
    common::TestHarness::server_with_agent_auth()
        .await
        .expect("server harness")
}

/// Scenario "Regression — the card has no endpoint URL", and an update and a
/// clear of the endpoint.
#[tokio::test]
async fn the_card_serves_the_agent_endpoint() {
    let h = harness().await;
    let api = api(&h).await;

    let (status, created) = api
        .create(json!({"endpoint_url": "https://agent.example.com/a2a"}))
        .await;
    assert_eq!(status, 201, "create with an endpoint: {created}");
    assert_eq!(created["endpoint_url"], "https://agent.example.com/a2a");
    let agent_id = created["id"].as_str().expect("id").to_string();
    assert_eq!(
        api.card(&agent_id).await["url"],
        "https://agent.example.com/a2a"
    );

    let status = api
        .patch(
            &agent_id,
            json!({"endpoint_url": "https://agent.example.com/v2"}),
        )
        .await;
    assert_eq!(status, 200, "update the endpoint");
    assert_eq!(
        api.card(&agent_id).await["url"],
        "https://agent.example.com/v2"
    );

    let status = api.patch(&agent_id, json!({"endpoint_url": ""})).await;
    assert_eq!(status, 200, "an empty endpoint clears it");
    let card = api.card(&agent_id).await;
    assert!(card.get("url").is_none(), "a cleared endpoint: {card}");
}

/// An agent with no endpoint gets a card without `url`, not `url: ""`.
#[tokio::test]
async fn an_agent_without_an_endpoint_has_no_card_url() {
    let h = harness().await;
    let api = api(&h).await;

    let (status, created) = api.create(json!({})).await;
    assert_eq!(status, 201, "create without an endpoint: {created}");
    let agent_id = created["id"].as_str().expect("id").to_string();
    let card = api.card(&agent_id).await;
    assert!(card.get("url").is_none(), "no endpoint, no url: {card}");
}

/// The endpoint must be an absolute `https` URL.
#[tokio::test]
async fn a_non_https_endpoint_is_refused() {
    let h = harness().await;
    let api = api(&h).await;

    for bad in [
        "http://agent.example.com/a2a",
        "agent.example.com",
        "https://",
        "javascript:alert(1)",
    ] {
        // `400`, not the `422` of an unknown field: the value is refused.
        let (status, body) = api.create(json!({"endpoint_url": bad})).await;
        assert_eq!(status, 400, "{bad} must be refused: {body}");
    }
}

//! Injectable HTTP transport for federation connectors.
//!
//! Federation needs both GET (JWKS, discovery, `/user`, userinfo) and
//! POST (token exchange). The email subsystem's `HttpTransport` only
//! exposes POST; rather than widen that trait (used by 5 adapters), we
//! ship a federation-local transport that mirrors the same pattern.
//!
//! Production code uses [`UreqFederationTransport`]; tests use
//! [`StubFederationTransport`] to record requests and return canned
//! JSON without touching the network.

use std::sync::Mutex;

use crate::identity::IdentityError;

/// A request to be dispatched by the transport.
#[derive(Debug, Clone)]
pub struct FedHttpRequest {
    /// HTTP method (`"GET"` or `"POST"`).
    pub method: &'static str,
    /// Target URL.
    pub url: String,
    /// Header pairs as `(name, value)`.
    pub headers: Vec<(String, String)>,
    /// Request body. Empty for GET.
    pub body: Vec<u8>,
    /// `Content-Type` for the body when `method == "POST"`.
    pub content_type: Option<String>,
}

/// A response returned by the transport.
#[derive(Debug, Clone)]
pub struct FedHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body decoded as UTF-8.
    pub body: String,
}

/// Injectable HTTP transport for federation adapters.
///
/// MUST be `Send + Sync` so the transport can be held inside `Arc`
/// shared across tasks.
pub trait FederationHttpTransport: Send + Sync {
    /// Dispatches an HTTP request and returns the response.
    fn send(&self, request: &FedHttpRequest) -> Result<FedHttpResponse, IdentityError>;
}

/// Production transport built on `ureq`.
///
/// A plain synchronous implementation. Callers that run inside a Tokio
/// async context (e.g. `FederationService::callback`) MUST wrap calls to
/// `send` in `tokio::task::spawn_blocking` so the blocking ureq I/O runs
/// on the dedicated blocking thread pool instead of occupying an async
/// executor thread.
pub struct UreqFederationTransport;

/// Connect timeout for one federation upstream fetch.
const FED_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Total timeout for one federation upstream fetch, connect included.
const FED_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Builds the `ureq` configuration every federation upstream fetch uses.
///
/// `jwks_uri`, `token_endpoint` and `userinfo_endpoint` all come from realm
/// configuration a tenant admin controls and are dereferenced server-side, so
/// they are SSRF sinks and carry the same hardening as webhook egress
/// (audit §4.6#2):
///
/// - redirects capped at the shared `webhook::ssrf::MAX_WEBHOOK_REDIRECTS` — a
///   `3xx` from an SSRF-checked public host must not walk the request to an
///   unchecked internal one;
/// - `https_only`, so a plaintext upstream never reaches the network;
/// - a bounded connect *and* total time, so an upstream that never responds
///   cannot pin a blocking thread indefinitely.
fn federation_agent_config() -> ureq::config::Config {
    ureq::config::Config::builder()
        .timeout_connect(Some(FED_CONNECT_TIMEOUT))
        .timeout_global(Some(FED_REQUEST_TIMEOUT))
        .https_only(true)
        .max_redirects(crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS)
        .build()
}

impl FederationHttpTransport for UreqFederationTransport {
    fn send(&self, request: &FedHttpRequest) -> Result<FedHttpResponse, IdentityError> {
        // Pre-flight: refuse a non-https scheme and any host that resolves into
        // a private, loopback, link-local or cloud-metadata range before a
        // socket is opened.
        crate::webhook::ssrf::check_webhook_url(&request.url).map_err(|e| {
            IdentityError::FederationUpstreamError {
                provider: "transport".to_string(),
                reason: format!("SSRF guard blocked federation upstream fetch: {e}"),
            }
        })?;

        // `ssrf_agent` re-checks the addresses ureq is about to connect to,
        // collapsing the pre-flight and the connect lookup into one and closing
        // the DNS-rebinding race the pre-flight alone leaves open.
        let agent = crate::webhook::ssrf::ssrf_agent(federation_agent_config());

        // ureq 3.x distinguishes WithBody vs WithoutBody at the type
        // level, so we branch at the top and build each call path
        // independently.
        let response = match request.method {
            "GET" => {
                let mut req = agent.get(&request.url);
                for (name, value) in &request.headers {
                    req = req.header(name.as_str(), value.as_str());
                }
                req.call()
                    .map_err(|e| IdentityError::FederationUpstreamError {
                        provider: "transport".to_string(),
                        reason: format!("HTTP request failed: {e}"),
                    })?
            }
            "POST" => {
                let mut req = agent.post(&request.url);
                for (name, value) in &request.headers {
                    req = req.header(name.as_str(), value.as_str());
                }
                if let Some(ct) = &request.content_type {
                    req = req.header("Content-Type", ct.as_str());
                }
                req.send(&request.body)
                    .map_err(|e| IdentityError::FederationUpstreamError {
                        provider: "transport".to_string(),
                        reason: format!("HTTP request failed: {e}"),
                    })?
            }
            other => {
                return Err(IdentityError::FederationUpstreamError {
                    provider: "transport".to_string(),
                    reason: format!("unsupported HTTP method: {other}"),
                });
            }
        };

        let status: u16 = response.status().into();
        let body = response.into_body().read_to_string().map_err(|e| {
            IdentityError::FederationUpstreamError {
                provider: "transport".to_string(),
                reason: format!("failed to read response body: {e}"),
            }
        })?;

        Ok(FedHttpResponse { status, body })
    }
}

/// A canned response keyed by URL + method for test stubs.
#[derive(Debug, Clone)]
pub struct StubResponse {
    /// HTTP method the response matches (`"GET"` / `"POST"`).
    pub method: &'static str,
    /// URL the response matches (exact match).
    pub url: String,
    /// Status to return.
    pub status: u16,
    /// Body to return.
    pub body: String,
}

/// Test-only transport that records requests and returns canned responses.
///
/// Matching is strict: the first stubbed response whose `(method, url)`
/// matches is returned. Unmatched requests return 501 with an explanatory
/// body so tests fail loudly.
pub struct StubFederationTransport {
    stubs: Mutex<Vec<StubResponse>>,
    recorded: Mutex<Vec<FedHttpRequest>>,
}

impl StubFederationTransport {
    /// Creates a stub with no canned responses.
    pub fn new() -> Self {
        Self {
            stubs: Mutex::new(Vec::new()),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Adds a canned response for a `(method, url)` pair.
    pub fn stub(
        &self,
        method: &'static str,
        url: impl Into<String>,
        status: u16,
        body: impl Into<String>,
    ) {
        self.stubs.lock().expect("lock").push(StubResponse {
            method,
            url: url.into(),
            status,
            body: body.into(),
        });
    }

    /// Returns the requests the stub has received, in order.
    pub fn recorded(&self) -> Vec<FedHttpRequest> {
        self.recorded.lock().expect("lock").clone()
    }
}

impl Default for StubFederationTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationHttpTransport for StubFederationTransport {
    fn send(&self, request: &FedHttpRequest) -> Result<FedHttpResponse, IdentityError> {
        self.recorded.lock().expect("lock").push(request.clone());
        let stubs = self.stubs.lock().expect("lock");
        for s in stubs.iter() {
            if s.method == request.method && s.url == request.url {
                return Ok(FedHttpResponse {
                    status: s.status,
                    body: s.body.clone(),
                });
            }
        }
        // No match — return a loud failure so tests see it immediately.
        Ok(FedHttpResponse {
            status: 501,
            body: format!(
                "StubFederationTransport: no stub registered for {} {}",
                request.method, request.url
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_records_requests_and_returns_matching_response() {
        let stub = StubFederationTransport::new();
        stub.stub("GET", "https://idp.example/jwks", 200, r#"{"keys":[]}"#);

        let req = FedHttpRequest {
            method: "GET",
            url: "https://idp.example/jwks".to_string(),
            headers: vec![],
            body: vec![],
            content_type: None,
        };
        let resp = stub.send(&req).expect("stub should succeed");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, r#"{"keys":[]}"#);

        let recorded = stub.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].url, "https://idp.example/jwks");
        assert_eq!(recorded[0].method, "GET");
    }

    #[test]
    fn stub_returns_501_for_unmatched_requests() {
        let stub = StubFederationTransport::new();
        let req = FedHttpRequest {
            method: "GET",
            url: "https://missing.example/".to_string(),
            headers: vec![],
            body: vec![],
            content_type: None,
        };
        let resp = stub
            .send(&req)
            .expect("stub should still return a response");
        assert_eq!(resp.status, 501);
        assert!(resp.body.contains("no stub registered"));
    }

    #[test]
    fn stub_matches_on_method_and_url_tuple() {
        let stub = StubFederationTransport::new();
        stub.stub("POST", "https://idp.example/token", 200, "post-body");
        stub.stub("GET", "https://idp.example/token", 200, "get-body");

        let post = FedHttpRequest {
            method: "POST",
            url: "https://idp.example/token".to_string(),
            headers: vec![],
            body: vec![],
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        };
        let get = FedHttpRequest {
            method: "GET",
            url: "https://idp.example/token".to_string(),
            headers: vec![],
            body: vec![],
            content_type: None,
        };
        assert_eq!(stub.send(&post).expect("ok").body, "post-body");
        assert_eq!(stub.send(&get).expect("ok").body, "get-body");
    }

    #[test]
    fn transport_trait_is_object_safe() {
        fn assert_object_safe(_: &dyn FederationHttpTransport) {}
        let stub = StubFederationTransport::new();
        assert_object_safe(&stub);
    }

    /// Verifies `UreqFederationTransport::send` is a plain sync function
    /// with no runtime-flavor branching. The service layer wraps it in
    /// `spawn_blocking`, so this test exercises that call path directly.
    ///
    /// We point at port 1 (always refused) to keep the test offline;
    /// the important property is "no panic from block_in_place".
    #[tokio::test]
    async fn ureq_transport_send_is_sync_callable_from_spawn_blocking() {
        let result = tokio::task::spawn_blocking(|| {
            UreqFederationTransport.send(&FedHttpRequest {
                method: "GET",
                url: "http://127.0.0.1:1".to_string(),
                headers: vec![],
                body: vec![],
                content_type: None,
            })
        })
        .await
        .expect("spawn_blocking completed — transport is sync and panic-free");
        // Connection refused is the expected outcome; what matters is no panic.
        assert!(result.is_err(), "port 1 should refuse the connection");
    }

    // ── Egress hardening on the federation transport (audit §4.6#2) ───────

    // The SSRF-refusal behaviour of `UreqFederationTransport` itself is pinned
    // in `tests/federation_ssrf_guard.rs`, which exercises the public
    // transport. This unit test covers the half that is private to this
    // module: the agent configuration those refusals ride on.

    /// The transport must cap redirects so a `3xx` cannot walk an
    /// SSRF-checked public host to an unchecked internal one, and must bound
    /// both connect and total time.
    #[test]
    fn federation_agent_config_caps_redirects_and_sets_timeouts() {
        let config = federation_agent_config();
        assert_eq!(
            config.max_redirects(),
            crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS,
            "federation egress must use the shared redirect cap"
        );
        let timeouts = config.timeouts();
        assert_eq!(
            timeouts.connect,
            Some(FED_CONNECT_TIMEOUT),
            "federation egress must bound connect time"
        );
        assert_eq!(
            timeouts.global,
            Some(FED_REQUEST_TIMEOUT),
            "federation egress must bound total request time"
        );
        assert!(
            config.https_only(),
            "federation egress must refuse plaintext"
        );
    }
}

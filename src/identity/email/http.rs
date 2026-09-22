//! Injectable HTTP transport for email provider adapters.
//!
//! Production code uses [`UreqTransport`] which wraps `ureq` with
//! `block_in_place` for multi-thread Tokio runtimes. Tests use
//! [`StubHttpTransport`] to record requests for assertions.

use std::sync::Mutex;

use super::EmailError;

/// An HTTP request to be sent by the transport.
pub struct HttpRequest {
    /// Target URL.
    pub url: String,
    /// HTTP headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
    /// Content-Type header value for the body.
    pub content_type: String,
}

/// An HTTP response from the transport.
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body as a string.
    pub body: String,
}

/// Trait for injectable HTTP transports.
///
/// Provider adapters are generic over this trait so tests can swap in
/// [`StubHttpTransport`] without touching the network.
pub trait HttpTransport: Send + Sync {
    /// Sends an HTTP POST request and returns the response.
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, EmailError>;
}

/// Production HTTP transport using `ureq`.
///
/// Wraps blocking I/O in `block_in_place` when a multi-thread Tokio
/// runtime is detected (same pattern as SMTP sender).
pub struct UreqTransport;

/// Connect timeout for one email-provider API call.
const EMAIL_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Total timeout for one email-provider API call, connect included.
const EMAIL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Builds the `ureq` configuration every email-provider API call uses.
///
/// [`UreqTransport::post`] previously called bare `ureq::post`, which uses
/// `Config::default()`. In ureq 3.3.0 that leaves **every** timeout unset
/// except `await_100` — no global, connect, resolve, send or receive bound.
/// The call runs inside `tokio::task::block_in_place`, so it occupies a Tokio
/// *worker* thread rather than a `spawn_blocking` thread: a provider that
/// completes the TCP handshake and then stops responding costs one core's
/// worth of runtime capacity permanently, and nothing ever unsticks it.
///
/// The values match `federation_agent_config`, the closest sibling egress
/// path (`src/identity/federation/http.rs`), and the redirect cap is the
/// shared `webhook::ssrf::MAX_WEBHOOK_REDIRECTS`. `https_only` is safe to
/// assert here because every provider endpoint this transport is given is a
/// hard-coded `https://` constant (`sendgrid.rs`, `postmark.rs`,
/// `mailgun.rs`, `mailtrap.rs`) — none is operator-configurable.
///
/// The SSRF address checks that guard webhook and federation egress are
/// deliberately *not* applied: those exist because a tenant admin chooses the
/// URL. Here the URL is a compile-time constant, and an SSRF DNS check would
/// only add a way for a provider's own resolution to fail the send.
fn email_agent_config() -> ureq::config::Config {
    ureq::config::Config::builder()
        .timeout_connect(Some(EMAIL_CONNECT_TIMEOUT))
        .timeout_global(Some(EMAIL_REQUEST_TIMEOUT))
        .https_only(true)
        .max_redirects(crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS)
        .build()
}

impl HttpTransport for UreqTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, EmailError> {
        let do_request = || {
            let agent = ureq::Agent::new_with_config(email_agent_config());
            let mut req = agent
                .post(&request.url)
                .header("Content-Type", &request.content_type);

            for (name, value) in &request.headers {
                req = req.header(name.as_str(), value.as_str());
            }

            let response = req.send(&request.body).map_err(|e| EmailError::Transport {
                reason: format!("HTTP request failed: {e}"),
            })?;

            let status: u16 = response.status().into();
            let body =
                response
                    .into_body()
                    .read_to_string()
                    .map_err(|e| EmailError::Transport {
                        reason: format!("failed to read response body: {e}"),
                    })?;

            Ok(HttpResponse { status, body })
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(do_request)
            }
            _ => do_request(),
        }
    }
}

/// A recorded HTTP request for test assertions.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// The target URL.
    pub url: String,
    /// HTTP headers.
    pub headers: Vec<(String, String)>,
    /// Request body as bytes.
    pub body: Vec<u8>,
    /// Content-Type of the request.
    pub content_type: String,
}

/// A test HTTP transport that records requests and returns canned responses.
pub struct StubHttpTransport {
    requests: Mutex<Vec<RecordedRequest>>,
    response_status: u16,
    response_body: String,
}

impl StubHttpTransport {
    /// Creates a stub that returns a successful (200) response.
    pub fn success() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response_status: 200,
            response_body: String::new(),
        }
    }

    /// Creates a stub that returns an error response.
    pub fn error(status: u16, body: &str) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response_status: status,
            response_body: body.to_string(),
        }
    }

    /// Returns all recorded requests.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("lock").clone()
    }
}

impl HttpTransport for StubHttpTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, EmailError> {
        let recorded = RecordedRequest {
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            content_type: request.content_type.clone(),
        };
        self.requests.lock().expect("lock").push(recorded);

        Ok(HttpResponse {
            status: self.response_status,
            body: self.response_body.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_records_requests() {
        let stub = StubHttpTransport::success();
        let req = HttpRequest {
            url: "https://api.example.com/send".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer key".to_string())],
            body: b"hello".to_vec(),
            content_type: "application/json".to_string(),
        };

        let resp = stub.post(&req).expect("stub should succeed");
        assert_eq!(resp.status, 200);

        let recorded = stub.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].url, "https://api.example.com/send");
        assert_eq!(recorded[0].headers[0].0, "Authorization");
        assert_eq!(recorded[0].body, b"hello");
    }

    // ── Egress hardening on the email provider transport (finding E-4) ─────

    /// `UreqTransport::post` called bare `ureq::post`, which uses
    /// `Config::default()`. In ureq 3.3.0 every timeout there is `None` except
    /// `await_100`. The call runs inside `block_in_place`, so a provider that
    /// completes the TCP handshake and then stops responding pins a Tokio
    /// *worker* thread permanently. Matches `federation_agent_config`.
    #[test]
    fn email_agent_config_bounds_timeouts_and_caps_redirects() {
        let config = email_agent_config();
        let timeouts = config.timeouts();
        assert_eq!(
            timeouts.connect,
            Some(EMAIL_CONNECT_TIMEOUT),
            "email provider egress must bound connect time"
        );
        assert_eq!(
            timeouts.global,
            Some(EMAIL_REQUEST_TIMEOUT),
            "email provider egress must bound total request time"
        );
        assert!(
            config.https_only(),
            "every email provider endpoint is https; plaintext must be refused"
        );
        assert_eq!(
            config.max_redirects(),
            crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS,
            "email provider egress must use the shared redirect cap"
        );
    }

    /// Proves the configuration above is the one `post` actually applies.
    /// Under ureq's default config a plaintext URL is permitted and this call
    /// would fail with a connection error instead of an https-only refusal,
    /// so the assertion is on the refusal reason, not merely on `is_err()`.
    #[test]
    fn ureq_transport_applies_its_config_to_every_send() {
        let req = HttpRequest {
            // Port 1 refuses instantly, so this test never waits on the network
            // whichever way the guard goes.
            url: "http://127.0.0.1:1/v3/mail/send".to_string(),
            headers: vec![],
            body: b"{}".to_vec(),
            content_type: "application/json".to_string(),
        };
        // `HttpResponse` is not `Debug`, so match rather than `expect_err`.
        let msg = match UreqTransport.post(&req) {
            Ok(_) => panic!("a plaintext provider URL must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("configured for https only"),
            "post() must use the hardened agent config; got: {msg}"
        );
    }

    #[test]
    fn stub_returns_error_response() {
        let stub = StubHttpTransport::error(403, "forbidden");
        let req = HttpRequest {
            url: "https://api.example.com/send".to_string(),
            headers: vec![],
            body: vec![],
            content_type: "application/json".to_string(),
        };

        let resp = stub.post(&req).expect("stub should return response");
        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, "forbidden");
    }
}

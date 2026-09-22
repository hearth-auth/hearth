//! Pluggable HTTP transport for SMS providers.
//!
//! Provider adapters are generic over [`SmsHttpTransport`] so tests can swap in
//! [`StubSmsHttpTransport`] without touching the network.

use std::sync::Mutex;

use super::SmsError;

/// An outbound HTTP request to an SMS provider API.
pub struct SmsHttpRequest {
    /// Target URL.
    pub url: String,
    /// Additional headers beyond Content-Type (name, value pairs).
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
    /// Content-Type header value.
    pub content_type: String,
}

/// An HTTP response from the SMS provider.
pub struct SmsHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body as a string.
    pub body: String,
}

/// Trait for injectable HTTP transports.
///
/// Provider adapters are generic over this trait so tests can swap in
/// [`StubSmsHttpTransport`] without touching the network.
pub trait SmsHttpTransport: Send + Sync {
    /// Sends an HTTP POST request and returns the response.
    fn post(&self, request: &SmsHttpRequest) -> Result<SmsHttpResponse, SmsError>;
}

/// Production HTTP transport using `ureq`.
///
/// Wraps blocking I/O in `block_in_place` when a multi-thread Tokio
/// runtime is detected (same pattern as the email SMTP/HTTP senders).
pub struct UreqSmsTransport;

/// Connect timeout for one SMS-provider API call.
const SMS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Total timeout for one SMS-provider API call, connect included.
const SMS_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Builds the `ureq` configuration every SMS-provider API call uses.
///
/// [`UreqSmsTransport::post`] previously called bare `ureq::post`, which uses
/// `Config::default()`. In ureq 3.3.0 that leaves **every** timeout unset
/// except `await_100` — no global, connect, resolve, send or receive bound.
/// The call runs inside `tokio::task::block_in_place`, so it occupies a Tokio
/// *worker* thread rather than a `spawn_blocking` thread: a provider that
/// completes the TCP handshake and then stops responding costs one core's
/// worth of runtime capacity permanently, and nothing ever unsticks it. An
/// OTP send sits on the login path, so the queue behind it is user-facing.
///
/// The values match `federation_agent_config`, the closest sibling egress
/// path (`src/identity/federation/http.rs`), and the redirect cap is the
/// shared `webhook::ssrf::MAX_WEBHOOK_REDIRECTS`. `https_only` is safe to
/// assert here because every provider endpoint this transport is given is
/// built from a hard-coded `https://` constant (`twilio.rs`, `sns.rs`) —
/// neither is operator-configurable.
fn sms_agent_config() -> ureq::config::Config {
    ureq::config::Config::builder()
        .timeout_connect(Some(SMS_CONNECT_TIMEOUT))
        .timeout_global(Some(SMS_REQUEST_TIMEOUT))
        .https_only(true)
        .max_redirects(crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS)
        .build()
}

impl SmsHttpTransport for UreqSmsTransport {
    fn post(&self, request: &SmsHttpRequest) -> Result<SmsHttpResponse, SmsError> {
        let do_request = || {
            let agent = ureq::Agent::new_with_config(sms_agent_config());
            let mut req = agent
                .post(&request.url)
                .header("Content-Type", &request.content_type);

            for (name, value) in &request.headers {
                req = req.header(name.as_str(), value.as_str());
            }

            let response = req.send(&request.body).map_err(|e| SmsError::Transport {
                reason: format!("HTTP request failed: {e}"),
            })?;

            let status: u16 = response.status().into();
            let body = response.into_body().read_to_string().unwrap_or_default();

            Ok(SmsHttpResponse { status, body })
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(do_request)
            }
            _ => do_request(),
        }
    }
}

/// Recorded request entry for test inspection.
#[derive(Clone, Debug)]
pub struct RecordedSmsRequest {
    /// Target URL.
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
    /// Content-Type header value.
    pub content_type: String,
}

/// Test HTTP transport that records requests and returns canned responses.
pub struct StubSmsHttpTransport {
    requests: Mutex<Vec<RecordedSmsRequest>>,
    response_status: u16,
    response_body: String,
}

impl StubSmsHttpTransport {
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
    pub fn requests(&self) -> Vec<RecordedSmsRequest> {
        #[allow(clippy::unwrap_used)] // INVARIANT: test-only, never poisoned
        self.requests.lock().unwrap().clone()
    }
}

impl SmsHttpTransport for StubSmsHttpTransport {
    fn post(&self, request: &SmsHttpRequest) -> Result<SmsHttpResponse, SmsError> {
        let recorded = RecordedSmsRequest {
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            content_type: request.content_type.clone(),
        };
        #[allow(clippy::unwrap_used)] // INVARIANT: test-only, never poisoned
        self.requests.lock().unwrap().push(recorded);

        Ok(SmsHttpResponse {
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
        let stub = StubSmsHttpTransport::success();
        let req = SmsHttpRequest {
            url: "https://api.example.com/sms".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer key".to_string())],
            body: b"hello".to_vec(),
            content_type: "application/json".to_string(),
        };

        let resp = stub.post(&req).expect("stub should succeed");
        assert_eq!(resp.status, 200);

        let recorded = stub.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].url, "https://api.example.com/sms");
        assert_eq!(recorded[0].headers[0].0, "Authorization");
        assert_eq!(recorded[0].body, b"hello");
    }

    // ── Egress hardening on the SMS provider transport (finding E-4) ───────

    /// `UreqSmsTransport::post` called bare `ureq::post`, which uses
    /// `Config::default()`. In ureq 3.3.0 every timeout there is `None` except
    /// `await_100`. The call runs inside `block_in_place`, so a provider that
    /// completes the TCP handshake and then stops responding pins a Tokio
    /// *worker* thread permanently. Matches `federation_agent_config`.
    #[test]
    fn sms_agent_config_bounds_timeouts_and_caps_redirects() {
        let config = sms_agent_config();
        let timeouts = config.timeouts();
        assert_eq!(
            timeouts.connect,
            Some(SMS_CONNECT_TIMEOUT),
            "SMS provider egress must bound connect time"
        );
        assert_eq!(
            timeouts.global,
            Some(SMS_REQUEST_TIMEOUT),
            "SMS provider egress must bound total request time"
        );
        assert!(
            config.https_only(),
            "every SMS provider endpoint is https; plaintext must be refused"
        );
        assert_eq!(
            config.max_redirects(),
            crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS,
            "SMS provider egress must use the shared redirect cap"
        );
    }

    /// Proves the configuration above is the one `post` actually applies.
    /// Under ureq's default config a plaintext URL is permitted and this call
    /// would fail with a connection error instead of an https-only refusal,
    /// so the assertion is on the refusal reason, not merely on `is_err()`.
    #[test]
    fn ureq_sms_transport_applies_its_config_to_every_send() {
        let req = SmsHttpRequest {
            // Port 1 refuses instantly, so this test never waits on the network
            // whichever way the guard goes.
            url: "http://127.0.0.1:1/Messages.json".to_string(),
            headers: vec![],
            body: b"To=%2B15551234567".to_vec(),
            content_type: "application/x-www-form-urlencoded".to_string(),
        };
        // `SmsHttpResponse` is not `Debug`, so match rather than `expect_err`.
        let msg = match UreqSmsTransport.post(&req) {
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
        let stub = StubSmsHttpTransport::error(400, "bad request");
        let req = SmsHttpRequest {
            url: "https://api.example.com/sms".to_string(),
            headers: vec![],
            body: vec![],
            content_type: "application/x-www-form-urlencoded".to_string(),
        };

        let resp = stub.post(&req).expect("stub should return response");
        assert_eq!(resp.status, 400);
        assert_eq!(resp.body, "bad request");
    }
}

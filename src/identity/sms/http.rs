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

impl SmsHttpTransport for UreqSmsTransport {
    fn post(&self, request: &SmsHttpRequest) -> Result<SmsHttpResponse, SmsError> {
        let do_request = || {
            let mut req = ureq::post(&request.url).header("Content-Type", &request.content_type);

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

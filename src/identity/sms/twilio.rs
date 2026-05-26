//! Twilio SMS adapter.
//!
//! Delivers SMS via the Twilio Messaging API:
//! `POST https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json`

use base64::Engine;

use super::http::{SmsHttpRequest, SmsHttpTransport};
use super::{reject_crlf, SmsError, SmsMessage, SmsSecret, SmsSender};

/// Twilio API base URL.
const TWILIO_API_BASE: &str = "https://api.twilio.com/2010-04-01/Accounts";

/// An [`SmsSender`] that delivers via the Twilio Messaging API.
///
/// Generic over [`SmsHttpTransport`] for testability.
pub struct TwilioSmsSender<H: SmsHttpTransport> {
    transport: H,
    account_sid: String,
    auth_token: SmsSecret,
    from: String,
}

impl<H: SmsHttpTransport> TwilioSmsSender<H> {
    /// Creates a new Twilio sender.
    pub fn new(transport: H, account_sid: String, auth_token: SmsSecret, from: String) -> Self {
        Self {
            transport,
            account_sid,
            auth_token,
            from,
        }
    }

    fn api_url(&self) -> String {
        format!("{}/{}/Messages.json", TWILIO_API_BASE, self.account_sid)
    }
}

impl<H: SmsHttpTransport> std::fmt::Debug for TwilioSmsSender<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwilioSmsSender")
            .field("account_sid", &self.account_sid)
            .field("from", &self.from)
            .field("auth_token", &self.auth_token)
            .finish_non_exhaustive()
    }
}

impl<H: SmsHttpTransport> SmsSender for TwilioSmsSender<H> {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        reject_crlf("recipient", &message.to)?;

        let body = form_encode(&[
            ("To", &message.to),
            ("From", &self.from),
            ("Body", &message.body),
        ]);

        // Twilio uses HTTP Basic auth: AccountSid:AuthToken
        let credentials = format!("{}:{}", self.account_sid, self.auth_token.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());

        let request = SmsHttpRequest {
            url: self.api_url(),
            headers: vec![("Authorization".to_string(), format!("Basic {encoded}"))],
            body: body.into_bytes(),
            content_type: "application/x-www-form-urlencoded".to_string(),
        };

        let response = self.transport.post(&request)?;

        if response.status >= 400 {
            return Err(SmsError::Transport {
                reason: format!(
                    "Twilio API returned HTTP {}: {}",
                    response.status,
                    truncate_body(&response.body)
                ),
            });
        }

        tracing::info!(
            recipient = %message.to,
            "sms.send: delivered via Twilio"
        );
        Ok(())
    }
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn url_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                let _ = write!(result, "{:02X}", byte);
            }
        }
    }
    result
}

fn truncate_body(body: &str) -> &str {
    if body.len() > 200 {
        &body[..200]
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::sms::http::StubSmsHttpTransport;

    fn test_sender(stub: StubSmsHttpTransport) -> TwilioSmsSender<StubSmsHttpTransport> {
        TwilioSmsSender::new(
            stub,
            "AC12345678".to_string(),
            SmsSecret::new("test-auth-token".to_string()),
            "+15550001111".to_string(),
        )
    }

    fn test_message() -> SmsMessage {
        SmsMessage {
            to: "+15559876543".to_string(),
            body: "Your verification code is 123456".to_string(),
        }
    }

    #[test]
    fn twilio_sends_form_encoded_body() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        assert_eq!(requests.len(), 1);

        let body = String::from_utf8(requests[0].body.clone()).expect("valid UTF-8");
        assert!(body.contains("To=%2B15559876543"), "To field: {body}");
        assert!(body.contains("From=%2B15550001111"), "From field: {body}");
        assert!(body.contains("Body="), "Body field: {body}");
        assert_eq!(
            requests[0].content_type,
            "application/x-www-form-urlencoded"
        );
    }

    #[test]
    fn twilio_uses_basic_auth() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        let auth = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("Authorization header must be present");

        let encoded = auth.1.strip_prefix("Basic ").expect("Basic prefix");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid base64");
        let creds = String::from_utf8(decoded).expect("valid UTF-8");
        assert_eq!(creds, "AC12345678:test-auth-token");
    }

    #[test]
    fn twilio_uses_correct_url() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        assert!(
            requests[0].url.ends_with("/AC12345678/Messages.json"),
            "URL: {}",
            requests[0].url
        );
    }

    #[test]
    fn twilio_rejects_crlf_in_recipient() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        let msg = SmsMessage {
            to: "+15559876543\r\nX-Injected: header".to_string(),
            body: "code".to_string(),
        };
        assert!(
            matches!(sender.send(&msg), Err(SmsError::InvalidInput { .. })),
            "should reject CRLF in recipient"
        );
    }

    #[test]
    fn twilio_returns_transport_error_on_4xx() {
        let stub = StubSmsHttpTransport::error(400, r#"{"code":21211,"message":"Invalid To"}"#);
        let sender = test_sender(stub);
        let result = sender.send(&test_message());
        assert!(
            matches!(result, Err(SmsError::Transport { .. })),
            "should propagate transport error: {result:?}"
        );
    }

    #[test]
    fn debug_does_not_leak_auth_token() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        let debug = format!("{sender:?}");
        assert!(!debug.contains("test-auth-token"), "debug: {debug}");
    }

    #[test]
    fn url_encode_special_characters() {
        assert_eq!(url_encode("hello world"), "hello+world");
        assert_eq!(url_encode("+15551234567"), "%2B15551234567");
        assert_eq!(url_encode("a=b"), "a%3Db");
    }
}

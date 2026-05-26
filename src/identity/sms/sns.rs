//! AWS SNS SMS adapter.
//!
//! Delivers SMS via the AWS SNS Publish API using Signature Version 4:
//! `POST https://sns.{region}.amazonaws.com/`

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::http::{SmsHttpRequest, SmsHttpTransport};
use super::{reject_crlf, SmsError, SmsMessage, SmsSecret, SmsSender};

type HmacSha256 = Hmac<Sha256>;

/// SNS service name constant for SigV4.
const SERVICE: &str = "sns";

/// An [`SmsSender`] that delivers via AWS SNS Transactional SMS.
///
/// Generic over [`SmsHttpTransport`] for testability. Uses AWS Signature
/// Version 4 for request authentication.
pub struct SnsSmsSender<H: SmsHttpTransport> {
    transport: H,
    region: String,
    access_key_id: String,
    secret_access_key: SmsSecret,
    /// Optional alphanumeric sender ID shown on recipient device (up to 11 chars).
    sender_id: Option<String>,
}

impl<H: SmsHttpTransport> SnsSmsSender<H> {
    /// Creates a new SNS sender.
    pub fn new(
        transport: H,
        region: String,
        access_key_id: String,
        secret_access_key: SmsSecret,
        sender_id: Option<String>,
    ) -> Self {
        Self {
            transport,
            region,
            access_key_id,
            secret_access_key,
            sender_id,
        }
    }

    fn endpoint(&self) -> String {
        format!("https://sns.{}.amazonaws.com/", self.region)
    }
}

impl<H: SmsHttpTransport> std::fmt::Debug for SnsSmsSender<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnsSmsSender")
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("sender_id", &self.sender_id)
            .field("secret_access_key", &self.secret_access_key)
            .finish_non_exhaustive()
    }
}

impl<H: SmsHttpTransport> SmsSender for SnsSmsSender<H> {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        reject_crlf("recipient", &message.to)?;

        let now = OffsetDateTime::now_utc();
        let date_stamp = format!("{:04}{:02}{:02}", now.year(), now.month() as u8, now.day());
        let amz_date = format!(
            "{date_stamp}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );

        // Build form-encoded body for SNS Publish action.
        let mut params = vec![
            ("Action", "Publish"),
            ("Message", message.body.as_str()),
            ("PhoneNumber", message.to.as_str()),
            ("Version", "2010-03-31"),
        ];

        // SNS MessageAttributes for sender ID if configured.
        let sender_id_attr_value = self.sender_id.as_deref().unwrap_or("");
        if self.sender_id.is_some() {
            params.push(("MessageAttributes.entry.1.Name", "AWS.SNS.SMS.SenderID"));
            params.push(("MessageAttributes.entry.1.Value.DataType", "String"));
            params.push((
                "MessageAttributes.entry.1.Value.StringValue",
                sender_id_attr_value,
            ));
            params.push(("MessageAttributes.entry.2.Name", "AWS.SNS.SMS.SMSType"));
            params.push(("MessageAttributes.entry.2.Value.DataType", "String"));
            params.push((
                "MessageAttributes.entry.2.Value.StringValue",
                "Transactional",
            ));
        } else {
            params.push(("MessageAttributes.entry.1.Name", "AWS.SNS.SMS.SMSType"));
            params.push(("MessageAttributes.entry.1.Value.DataType", "String"));
            params.push((
                "MessageAttributes.entry.1.Value.StringValue",
                "Transactional",
            ));
        }

        // Sort parameters for canonical request (required by SigV4).
        params.sort_by_key(|(k, _)| *k);

        let body = params
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Compute SigV4 signature.
        let host = format!("sns.{}.amazonaws.com", self.region);
        let content_type = "application/x-www-form-urlencoded";
        let body_hash = hex_sha256(body.as_bytes());

        let canonical_headers =
            format!("content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\n");
        let signed_headers = "content-type;host;x-amz-date";

        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{body_hash}");

        let credential_scope = format!("{date_stamp}/{}/{SERVICE}/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );

        let signing_key = derive_signing_key(
            self.secret_access_key.expose_secret(),
            &date_stamp,
            &self.region,
            SERVICE,
        );
        let signature = hex_hmac(&signing_key, string_to_sign.as_bytes());

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );

        let request = SmsHttpRequest {
            url: self.endpoint(),
            headers: vec![
                ("Authorization".to_string(), authorization),
                ("X-Amz-Date".to_string(), amz_date),
                ("Host".to_string(), host),
            ],
            body: body.into_bytes(),
            content_type: content_type.to_string(),
        };

        let response = self.transport.post(&request)?;

        if response.status >= 400 {
            return Err(SmsError::Transport {
                reason: format!(
                    "SNS API returned HTTP {}: {}",
                    response.status,
                    truncate_body(&response.body)
                ),
            });
        }

        tracing::info!(
            recipient = %message.to,
            "sms.send: delivered via AWS SNS"
        );
        Ok(())
    }
}

/// Returns the lowercase hex SHA-256 digest of `data`.
fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Returns the lowercase hex HMAC-SHA256 of `data` under `key`.
fn hex_hmac(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Returns the raw HMAC-SHA256 bytes of `data` under `key`.
fn hmac_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derives the SigV4 signing key for a given secret/date/region/service.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_bytes(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_bytes(&k_date, region.as_bytes());
    let k_service = hmac_bytes(&k_region, service.as_bytes());
    hmac_bytes(&k_service, b"aws4_request")
}

fn url_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                let _ = write!(result, "%{:02X}", byte);
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

    fn test_sender(stub: StubSmsHttpTransport) -> SnsSmsSender<StubSmsHttpTransport> {
        SnsSmsSender::new(
            stub,
            "us-east-1".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            SmsSecret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
            None,
        )
    }

    fn test_message() -> SmsMessage {
        SmsMessage {
            to: "+15559876543".to_string(),
            body: "Your verification code is 654321".to_string(),
        }
    }

    #[test]
    fn sns_sends_to_correct_endpoint() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://sns.us-east-1.amazonaws.com/");
    }

    #[test]
    fn sns_includes_sigv4_authorization_header() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        let auth = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("Authorization header must be present");

        assert!(
            auth.1.starts_with("AWS4-HMAC-SHA256 Credential="),
            "Authorization: {}",
            auth.1
        );
        assert!(auth.1.contains("SignedHeaders="), "header: {}", auth.1);
        assert!(auth.1.contains("Signature="), "header: {}", auth.1);
    }

    #[test]
    fn sns_body_contains_publish_action() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        let body = String::from_utf8(requests[0].body.clone()).expect("valid UTF-8");
        assert!(body.contains("Action=Publish"), "body: {body}");
        assert!(body.contains("PhoneNumber=%2B15559876543"), "body: {body}");
    }

    #[test]
    fn sns_rejects_crlf_in_recipient() {
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
    fn sns_returns_transport_error_on_4xx() {
        let stub = StubSmsHttpTransport::error(403, "<ErrorResponse>...</ErrorResponse>");
        let sender = test_sender(stub);
        let result = sender.send(&test_message());
        assert!(
            matches!(result, Err(SmsError::Transport { .. })),
            "should propagate transport error: {result:?}"
        );
    }

    #[test]
    fn debug_does_not_leak_secret_key() {
        let stub = StubSmsHttpTransport::success();
        let sender = test_sender(stub);
        let debug = format!("{sender:?}");
        assert!(
            !debug.contains("wJalrXUtnFEMI"),
            "debug must not expose secret key: {debug}"
        );
    }

    #[test]
    fn sns_with_sender_id_includes_attribute() {
        let stub = StubSmsHttpTransport::success();
        let sender = SnsSmsSender::new(
            stub,
            "us-east-1".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            SmsSecret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
            Some("MyBrand".to_string()),
        );
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        let body = String::from_utf8(requests[0].body.clone()).expect("valid UTF-8");
        assert!(
            body.contains("SenderID"),
            "sender ID attribute missing: {body}"
        );
    }
}

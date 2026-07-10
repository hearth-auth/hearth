//! Pre-token enrichment webhook client (HEA-1324, Gap C-3).
//!
//! Before token issuance, Hearth POSTs a JSON payload to the configured URL
//! with user and session context. The response may include `extra_claims` that
//! are merged into the issued access token.
//!
//! # Auth0 Actions compatibility
//!
//! This is the minimal escape hatch that lets Auth0 "Actions" (formerly Rules)
//! be replicated without a full plugin/SPI framework. Extension logic runs
//! outside the auth server, reducing attack surface.
//!
//! # Signature scheme
//!
//! When `hmac_secret` is configured, the request body is signed with
//! HMAC-SHA256 and the signature is sent as:
//! ```text
//! X-Hearth-Signature-256: sha256=<hex(HMAC-SHA256(secret, body))>
//! ```
//! This follows GitHub's webhook signature convention so operators can reuse
//! their existing verification middleware.
//!
//! **Security note**: `hmac_secret` MUST be set in production. When not set,
//! the webhook endpoint receives unsigned requests and any party that can reach
//! your endpoint can forge enrichment responses. Configure `on_error: fail_closed`
//! together with `hmac_secret` for defense in depth.
//!
//! # Claim merge policy
//!
//! `extra_claims` keys that collide with reserved JWT standard claims
//! (`sub`, `iss`, `aud`, `exp`, `iat`, `sid`, `tid`, `token_type`, `jti`,
//! `fid`, `scope`, `nonce`, `roles`, `groups`, `org_groups`, `permissions`,
//! `required_actions`, `amr`, `cnf`, `sv`, `oid`) are silently dropped —
//! the webhook cannot escalate privileges by overwriting structural claims.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

/// Reserved JWT claim keys that the webhook response must not overwrite.
///
/// Includes all standard JWT fields and Hearth-specific structural claims so
/// extension logic cannot escalate privileges or confuse token validation.
pub const RESERVED_CLAIM_KEYS: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "sid",
    "tid",
    "oid",
    "fid",
    "token_type",
    "scope",
    "nonce",
    "roles",
    "groups",
    "org_groups",
    "permissions",
    "required_actions",
    "amr",
    "cnf",
    "sv",
];

// ──────────────────── error ────────────────────────────────

/// Error returned by the pre-token webhook transport.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PreTokenWebhookError {
    /// HTTP call failed (network error, timeout, or non-2xx response).
    ///
    /// Callers choose fail-open vs fail-closed based on `on_error` policy.
    #[error("pre-token webhook transport error: {reason}")]
    TransportError { reason: String },
    /// Response body was not valid JSON or did not match the expected schema.
    #[error("pre-token webhook response parse error: {reason}")]
    ParseError { reason: String },
}

// ──────────────────── request / response types ────────────────────────────

/// Context payload POSTed to the pre-token webhook URL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreTokenWebhookRequest {
    /// Fixed discriminator so the endpoint knows this is a token enrichment call.
    pub event: &'static str,
    /// Realm in which the token is being issued.
    pub realm_id: String,
    /// Subject user ID (UUID string).
    pub user_id: String,
    /// OAuth client ID requesting the token.
    pub client_id: String,
    /// OAuth 2.0 / OIDC grant type string (e.g. `"authorization_code"`).
    pub grant_type: &'static str,
    /// Space-delimited OAuth scope string, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Session ID bound to this token issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Already-resolved standard claims (roles, groups, permissions, custom).
    /// The webhook may inspect these to inform what extra claims to inject.
    pub existing_claims: ExistingClaims,
}

/// Subset of already-resolved claims included in the webhook request for
/// inspection by the endpoint. Read-only from the webhook's perspective.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExistingClaims {
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

/// Response body returned by the pre-token webhook endpoint.
///
/// The server MUST return HTTP 2xx with a JSON body. Non-2xx is treated as a
/// transport error and handled per the `on_error` policy.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PreTokenWebhookResponse {
    /// Extra claims to merge into the access token's top-level payload.
    ///
    /// Keys that collide with reserved JWT claims are silently dropped.
    #[serde(default)]
    pub extra_claims: BTreeMap<String, serde_json::Value>,
}

// ──────────────────── transport trait ────────────────────────────────────

/// HTTP transport for the pre-token webhook call.
///
/// Trait-based so tests can inject a stub without network I/O.
/// The `url` and `timeout_ms` are passed at call time so the same transport
/// instance can serve all realms with different webhook URLs.
///
/// `body` is the pre-serialized JSON payload. `hmac_sig` is the optional
/// `X-Hearth-Signature-256` header value (e.g. `"sha256=<hex>"`); the
/// transport must include it verbatim when `Some`.
pub trait PreTokenWebhookTransport: Send + Sync {
    /// Fires the webhook at `url` and returns the parsed response.
    fn fire(
        &self,
        url: &str,
        timeout_ms: u64,
        body: &[u8],
        hmac_sig: Option<&str>,
    ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError>;
}

// ──────────────────── production transport ───────────────────────────────

/// Production `ureq`-backed transport.
///
/// Runs the blocking ureq call inside `block_in_place` when invoked from a
/// multi-thread Tokio runtime, matching the pattern used by
/// `src/identity/hibp.rs` and `src/identity/federation/http.rs`.
pub(crate) struct UreqPreTokenWebhookTransport;

impl PreTokenWebhookTransport for UreqPreTokenWebhookTransport {
    fn fire(
        &self,
        url: &str,
        timeout_ms: u64,
        body: &[u8],
        hmac_sig: Option<&str>,
    ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
        let url = url.to_string();
        let timeout = Duration::from_millis(timeout_ms);
        let body = body.to_vec();
        let hmac_sig = hmac_sig.map(str::to_string);

        let do_request = move || -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
            // SSRF guard: pre-flight DNS check (defends against DNS rebinding).
            crate::webhook::ssrf::check_webhook_url(&url).map_err(|e| {
                PreTokenWebhookError::TransportError {
                    reason: format!("SSRF guard rejected pre-token webhook URL: {e}"),
                }
            })?;

            let agent = ureq::config::Config::builder()
                .timeout_global(Some(timeout))
                .build()
                .new_agent();

            let mut req = agent.post(&url).header("Content-Type", "application/json");

            if let Some(ref sig) = hmac_sig {
                req = req.header("X-Hearth-Signature-256", sig.as_str());
            }

            let resp =
                req.send(body.as_slice())
                    .map_err(|e| PreTokenWebhookError::TransportError {
                        reason: e.to_string(),
                    })?;

            let status: u16 = resp.status().into();
            if !(200..300).contains(&status) {
                return Err(PreTokenWebhookError::TransportError {
                    reason: format!("HTTP {status}"),
                });
            }

            let response_body = resp.into_body().read_to_string().map_err(|e| {
                PreTokenWebhookError::TransportError {
                    reason: e.to_string(),
                }
            })?;

            serde_json::from_str(&response_body).map_err(|e| PreTokenWebhookError::ParseError {
                reason: e.to_string(),
            })
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(do_request)
            }
            _ => do_request(),
        }
    }
}

// ──────────────────── client ─────────────────────────────────────────────

/// Pre-token webhook client.
///
/// Wraps a transport and provides signing + claim-merge logic.
/// Injectable via [`PreTokenWebhookClient::with_transport`] for tests.
pub struct PreTokenWebhookClient {
    transport: Arc<dyn PreTokenWebhookTransport>,
}

impl Default for PreTokenWebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PreTokenWebhookClient {
    /// Creates a production client backed by [`UreqPreTokenWebhookTransport`].
    pub fn new() -> Self {
        Self {
            transport: Arc::new(UreqPreTokenWebhookTransport),
        }
    }

    /// Creates a client with an injected transport (for tests).
    pub fn with_transport(transport: Arc<dyn PreTokenWebhookTransport>) -> Self {
        Self { transport }
    }

    /// Calls the webhook and returns only the safe, non-reserved extra claims.
    ///
    /// The caller supplies:
    /// - `url` — the configured webhook URL
    /// - `timeout_ms` — request timeout in milliseconds
    /// - `hmac_secret` — optional HMAC-SHA256 signing secret; when set,
    ///   the serialized body is signed and the result sent as
    ///   `X-Hearth-Signature-256: sha256=<hex>` so the endpoint can
    ///   verify authenticity.
    /// - `request` — the pre-built payload to POST
    ///
    /// Reserved claim keys are stripped from the response before returning.
    pub fn call(
        &self,
        url: &str,
        timeout_ms: u64,
        hmac_secret: Option<&str>,
        request: &PreTokenWebhookRequest,
    ) -> Result<BTreeMap<String, serde_json::Value>, PreTokenWebhookError> {
        let body = serde_json::to_vec(request).map_err(|e| PreTokenWebhookError::ParseError {
            reason: format!("failed to serialize request: {e}"),
        })?;

        let hmac_sig: Option<String> = hmac_secret.map(|secret| {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            // HMAC accepts any key size — `new_from_slice` only errors on
            // zero-length keys, which the config layer rejects at load time.
            #[allow(clippy::expect_used)]
            let mut mac =
                HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key must be non-empty");
            mac.update(&body);
            format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
        });

        let resp = self
            .transport
            .fire(url, timeout_ms, &body, hmac_sig.as_deref())?;

        // Strip reserved keys from the response before merging into the token.
        let safe_claims: BTreeMap<String, serde_json::Value> = resp
            .extra_claims
            .into_iter()
            .filter(|(key, _)| {
                let reserved = RESERVED_CLAIM_KEYS.contains(&key.as_str());
                if reserved {
                    warn!(
                        claim_key = %key,
                        "pre-token webhook attempted to override reserved JWT claim; dropping"
                    );
                }
                !reserved
            })
            .collect();

        Ok(safe_claims)
    }
}

// ──────────────────── claim-merge helper ─────────────────────────────────

/// Merges `extra_claims` into `base` without overwriting reserved keys.
///
/// Extra claims that collide with reserved JWT claim keys are silently dropped.
/// This is a pure function called by the engine after a successful webhook call.
pub fn merge_extra_claims(
    mut base: BTreeMap<String, serde_json::Value>,
    extra: BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    for (key, value) in extra {
        if !RESERVED_CLAIM_KEYS.contains(&key.as_str()) {
            base.insert(key, value);
        }
    }
    base
}

// ──────────────────── unit tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_extra_claims_adds_non_reserved() {
        let base = BTreeMap::new();
        let mut extra = BTreeMap::new();
        extra.insert("tenant_id".to_string(), serde_json::json!("acme"));
        extra.insert("tier".to_string(), serde_json::json!("pro"));

        let merged = merge_extra_claims(base, extra);
        assert_eq!(merged["tenant_id"], serde_json::json!("acme"));
        assert_eq!(merged["tier"], serde_json::json!("pro"));
    }

    #[test]
    fn merge_extra_claims_drops_reserved_sub() {
        let base = BTreeMap::new();
        let mut extra = BTreeMap::new();
        extra.insert("sub".to_string(), serde_json::json!("evil"));
        extra.insert("legitimate".to_string(), serde_json::json!(true));

        let merged = merge_extra_claims(base, extra);
        assert!(!merged.contains_key("sub"), "sub must not be overridable");
        assert_eq!(merged["legitimate"], serde_json::json!(true));
    }

    #[test]
    fn merge_extra_claims_drops_all_reserved_keys() {
        let base = BTreeMap::new();
        let mut extra = BTreeMap::new();
        for key in RESERVED_CLAIM_KEYS {
            extra.insert((*key).to_string(), serde_json::json!("injected"));
        }
        extra.insert("custom_ok".to_string(), serde_json::json!(42));

        let merged = merge_extra_claims(base, extra);
        for key in RESERVED_CLAIM_KEYS {
            assert!(
                !merged.contains_key(*key),
                "reserved key '{key}' should have been dropped"
            );
        }
        assert_eq!(merged["custom_ok"], serde_json::json!(42));
    }

    #[test]
    fn merge_extra_claims_does_not_overwrite_existing_base_claims() {
        let mut base = BTreeMap::new();
        base.insert("existing".to_string(), serde_json::json!("original"));
        let mut extra = BTreeMap::new();
        extra.insert("existing".to_string(), serde_json::json!("overwrite"));
        extra.insert("new".to_string(), serde_json::json!("value"));

        let merged = merge_extra_claims(base, extra);
        // Non-reserved keys in extra overwrite base — this is intentional
        // (webhook can update custom claims it set on a prior call).
        assert_eq!(merged["existing"], serde_json::json!("overwrite"));
        assert_eq!(merged["new"], serde_json::json!("value"));
    }
}

//! Spec §4 — Claims API.
//!
//! [`Claims`] wraps a decoded JWT payload and exposes typed accessors
//! for standard OIDC and Hearth-specific claims.  All reads are local —
//! no network call is made.  Signature verification is the caller's
//! responsibility.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;

use crate::error::HearthError;

/// Typed accessor for a decoded JWT's claims (spec §4).
///
/// Construct via [`Claims::decode`] or pass a pre-decoded [`serde_json::Value`]
/// to [`Claims::from_value`].
pub struct Claims {
    payload: Value,
}

impl std::fmt::Debug for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit the raw payload to avoid accidentally logging sensitive claims.
        f.debug_struct("Claims")
            .field("sub", &self.subject())
            .field("iss", &self.issuer())
            .finish_non_exhaustive()
    }
}

impl Claims {
    /// Decode a JWT string without verifying its signature.
    ///
    /// # Errors
    /// Returns [`HearthError::TokenInvalidError`] if the string is not a
    /// structurally valid JWT or the payload segment cannot be decoded.
    pub fn decode(token: &str) -> Result<Self, HearthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(HearthError::TokenInvalidError {
                reason: "expected three dot-separated segments".into(),
            });
        }
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| HearthError::TokenInvalidError {
                reason: format!("base64 decode: {e}"),
            })?;
        let payload: Value =
            serde_json::from_slice(&payload_bytes).map_err(|e| HearthError::TokenInvalidError {
                reason: format!("JSON parse: {e}"),
            })?;
        Ok(Self { payload })
    }

    /// Construct from a pre-decoded JSON value.
    pub fn from_value(payload: Value) -> Self {
        Self { payload }
    }

    /// Assert the token is temporally valid.
    ///
    /// # Errors
    /// - [`HearthError::TokenExpiredError`] when `exp` is in the past.
    /// - [`HearthError::TokenNotYetValidError`] when `nbf` is in the future.
    pub fn assert_valid(&self, clock_skew_seconds: i64) -> Result<(), HearthError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if let Some(exp) = self.payload.get("exp").and_then(|v| v.as_i64()) {
            if now > exp + clock_skew_seconds {
                return Err(HearthError::TokenExpiredError { expired_at: exp });
            }
        }
        if let Some(nbf) = self.payload.get("nbf").and_then(|v| v.as_i64()) {
            if now < nbf - clock_skew_seconds {
                return Err(HearthError::TokenNotYetValidError { not_before: nbf });
            }
        }
        Ok(())
    }

    // ── Spec §4 accessor methods ─────────────────────────────────────────
    // Method names follow the spec identifiers exactly; allow non_snake_case
    // for camelCase names required by the spec surface.
    #[allow(non_snake_case)]

    /// Return the `sub` (subject) claim.
    pub fn subject(&self) -> &str {
        self.payload
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// Return the `iss` (issuer) claim.
    pub fn issuer(&self) -> &str {
        self.payload
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// Return the `aud` (audiences) claim normalised to a `Vec`.
    pub fn audiences(&self) -> Vec<String> {
        match self.payload.get("aud") {
            None => vec![],
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => vec![],
        }
    }

    /// Return the `exp` claim as a Unix timestamp, or `None` if absent.
    pub fn expiry(&self) -> Option<i64> {
        self.payload.get("exp").and_then(|v| v.as_i64())
    }

    /// Return the `iat` claim as a Unix timestamp, or `None` if absent.
    #[allow(non_snake_case)]
    pub fn issuedAt(&self) -> Option<i64> {
        self.payload.get("iat").and_then(|v| v.as_i64())
    }

    /// Return the `jti` (JWT ID) claim, or `None` if absent.
    #[allow(non_snake_case)]
    pub fn jwtID(&self) -> Option<&str> {
        self.payload.get("jti").and_then(|v| v.as_str())
    }

    /// Return the individual scopes from the `scope` claim.
    pub fn scopes(&self) -> Vec<String> {
        self.payload
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// Return `true` iff the token contains the given scope.
    #[allow(non_snake_case)]
    pub fn hasScope(&self, scope: &str) -> bool {
        self.scopes().iter().any(|s| s == scope)
    }

    /// Return `true` iff the token's `roles` claim contains the given role.
    #[allow(non_snake_case)]
    pub fn hasRole(&self, role: &str) -> bool {
        self.payload
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some(role)))
            .unwrap_or(false)
    }

    /// Return `true` iff the token's `permissions` claim contains the given permission.
    #[allow(non_snake_case)]
    pub fn hasPermission(&self, permission: &str) -> bool {
        self.payload
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some(permission)))
            .unwrap_or(false)
    }

    /// Return the raw space-delimited `scope` claim string, or `""` if absent.
    pub fn scope(&self) -> &str {
        self.payload
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// Return `true` iff the token's `groups` claim contains `group`.
    #[allow(non_snake_case)]
    pub fn inGroup(&self, group: &str) -> bool {
        self.payload
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some(group)))
            .unwrap_or(false)
    }

    /// Return `true` iff the token's `oid` claim exactly matches `org`.
    #[allow(non_snake_case)]
    pub fn inOrg(&self, org: &str) -> bool {
        self.payload
            .get("oid")
            .and_then(|v| v.as_str())
            .map(|s| s == org)
            .unwrap_or(false)
    }

    /// Return the `token_type` claim (`"access"`, `"refresh"`, or `"required_action"`),
    /// or `""` if absent.
    #[allow(non_snake_case)]
    pub fn tokenType(&self) -> &str {
        self.payload
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// Return the `oid` (organization ID) claim, or `None` if absent.
    #[allow(non_snake_case)]
    pub fn organizationId(&self) -> Option<&str> {
        self.payload.get("oid").and_then(|v| v.as_str())
    }

    /// Return the `org_groups` claim (Keycloak-style paths), or an empty vec if absent.
    #[allow(non_snake_case)]
    pub fn orgGroups(&self) -> Vec<String> {
        self.payload
            .get("org_groups")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return an arbitrary claim by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_claims(extra: serde_json::Value) -> Claims {
        let mut base = json!({
            "sub": "user_123",
            "iss": "https://auth.example.com",
            "aud": "myapp",
            "exp": 9999999999i64,
            "iat": 1000000000i64,
            "jti": "jwt-id-1",
            "scope": "openid profile email"
        });
        if let (Some(obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in extra_obj {
                obj.insert(k.clone(), v.clone());
            }
        }
        Claims::from_value(base)
    }

    #[test]
    fn scope_returns_raw_string() {
        let c = make_claims(json!({}));
        assert_eq!(c.scope(), "openid profile email");
    }

    #[test]
    fn scope_absent_returns_empty() {
        let c = Claims::from_value(json!({"sub": "u"}));
        assert_eq!(c.scope(), "");
    }

    #[test]
    fn in_group_true_when_present() {
        let c = make_claims(json!({"groups": ["admins", "devs"]}));
        assert!(c.inGroup("admins"));
        assert!(c.inGroup("devs"));
        assert!(!c.inGroup("other"));
    }

    #[test]
    fn in_group_false_when_claim_absent() {
        let c = make_claims(json!({}));
        assert!(!c.inGroup("admins"));
    }

    #[test]
    fn in_org_true_when_exact_match() {
        let c = make_claims(json!({"oid": "org_abc"}));
        assert!(c.inOrg("org_abc"));
        assert!(!c.inOrg("org_xyz"));
    }

    #[test]
    fn in_org_false_when_claim_absent() {
        let c = make_claims(json!({}));
        assert!(!c.inOrg("org_abc"));
    }

    #[test]
    fn token_type_returns_value() {
        let c = make_claims(json!({"token_type": "access"}));
        assert_eq!(c.tokenType(), "access");

        let c2 = make_claims(json!({"token_type": "required_action"}));
        assert_eq!(c2.tokenType(), "required_action");
    }

    #[test]
    fn token_type_absent_returns_empty() {
        let c = make_claims(json!({}));
        assert_eq!(c.tokenType(), "");
    }

    #[test]
    fn organization_id_returns_oid() {
        let c = make_claims(json!({"oid": "org_abc"}));
        assert_eq!(c.organizationId(), Some("org_abc"));
    }

    #[test]
    fn organization_id_absent_returns_none() {
        let c = make_claims(json!({}));
        assert_eq!(c.organizationId(), None);
    }

    #[test]
    fn org_groups_returns_paths() {
        let c = make_claims(json!({"org_groups": ["/acme/engineers", "/acme/admins"]}));
        assert_eq!(c.orgGroups(), vec!["/acme/engineers", "/acme/admins"]);
    }

    #[test]
    fn org_groups_absent_returns_empty_vec() {
        let c = make_claims(json!({}));
        assert!(c.orgGroups().is_empty());
    }
}

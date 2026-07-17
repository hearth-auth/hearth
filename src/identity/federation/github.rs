//! `GithubConnector` — OAuth2 (not OIDC) relying-party for GitHub.
//!
//! GitHub speaks OAuth 2.0 only; there's no ID token, no JWKS, no
//! discovery. Identity extraction goes through `GET /user` plus (for
//! private emails) `GET /user/emails`. Both endpoints require the
//! `User-Agent` header — GitHub rejects requests without one.
//!
//! `email_verified` is asserted as `true` only for an address GitHub
//! reports as verified in `/user/emails`. The public profile email
//! (`/user.email`) is never trusted on its own — it is accepted only when
//! it also appears as a verified row (S5 / HEA-1751).

use std::sync::Arc;

use serde::Deserialize;

use crate::identity::federation::connector::{AuthorizeUrl, IdpConnector};
use crate::identity::federation::http::{FedHttpRequest, FederationHttpTransport};
use crate::identity::federation::state::pkce_s256_challenge;
use crate::identity::federation::types::{ExternalIdentity, IdpConfig, IdpKind, StateBag};
use crate::identity::IdentityError;

/// GitHub OAuth2 connector.
pub struct GithubConnector {
    config: IdpConfig,
    http: Arc<dyn FederationHttpTransport>,
    redirect_uri: String,
}

impl GithubConnector {
    /// Creates a new GitHub connector.
    pub fn new(
        config: IdpConfig,
        http: Arc<dyn FederationHttpTransport>,
        redirect_uri: String,
    ) -> Self {
        Self {
            config,
            http,
            redirect_uri,
        }
    }
}

impl IdpConnector for GithubConnector {
    fn kind(&self) -> IdpKind {
        IdpKind::GitHub
    }

    fn display_name(&self) -> &str {
        &self.config.display_name
    }

    fn begin(&self, state: &StateBag) -> Result<AuthorizeUrl, IdentityError> {
        let scopes = self.config.scopes.join(" ");
        let challenge = pkce_s256_challenge(&state.pkce_verifier);
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &scopes)
            .append_pair("state", &state.state_token)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .finish();
        let sep = if self.config.authorization_endpoint.contains('?') {
            "&"
        } else {
            "?"
        };
        Ok(AuthorizeUrl(format!(
            "{}{sep}{query}",
            self.config.authorization_endpoint
        )))
    }

    fn exchange(&self, code: &str, state: &StateBag) -> Result<ExternalIdentity, IdentityError> {
        // 1. Exchange code for an access token.
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("client_id", &self.config.client_id)
            .append_pair("client_secret", self.config.client_secret.expose_secret())
            .append_pair("code_verifier", &state.pkce_verifier)
            .finish();
        let resp = self.http.send(&FedHttpRequest {
            method: "POST",
            url: self.config.token_endpoint.clone(),
            headers: vec![
                ("Accept".to_string(), "application/json".to_string()),
                ("User-Agent".to_string(), "Hearth".to_string()),
            ],
            body: body.into_bytes(),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        })?;
        if resp.status < 200 || resp.status >= 300 {
            return Err(IdentityError::FederationUpstreamError {
                provider: IdpKind::GitHub.label().to_string(),
                reason: format!("token endpoint returned {}", resp.status),
            });
        }
        #[derive(Deserialize)]
        struct TokenResp {
            access_token: String,
        }
        let token: TokenResp = serde_json::from_str(&resp.body).map_err(|_| {
            IdentityError::FederationUpstreamError {
                provider: IdpKind::GitHub.label().to_string(),
                reason: "invalid token response".to_string(),
            }
        })?;

        // 2. GET /user with the access token.
        let userinfo_url = self
            .config
            .userinfo_endpoint
            .clone()
            .unwrap_or_else(|| "https://api.github.com/user".to_string());
        let user_resp = self.http.send(&FedHttpRequest {
            method: "GET",
            url: userinfo_url,
            headers: vec![
                (
                    "Authorization".to_string(),
                    format!("Bearer {}", token.access_token),
                ),
                (
                    "Accept".to_string(),
                    "application/vnd.github+json".to_string(),
                ),
                ("User-Agent".to_string(), "Hearth".to_string()),
            ],
            body: Vec::new(),
            content_type: None,
        })?;
        if user_resp.status < 200 || user_resp.status >= 300 {
            return Err(IdentityError::FederationUpstreamError {
                provider: IdpKind::GitHub.label().to_string(),
                reason: format!("/user returned {}", user_resp.status),
            });
        }
        #[derive(Deserialize)]
        struct UserResp {
            id: serde_json::Value, // numeric; stringify for external_sub
            login: String,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            email: Option<String>,
            #[serde(default)]
            avatar_url: Option<String>,
        }
        let user: UserResp = serde_json::from_str(&user_resp.body).map_err(|_| {
            IdentityError::FederationUpstreamError {
                provider: IdpKind::GitHub.label().to_string(),
                reason: "invalid /user response".to_string(),
            }
        })?;

        // 3. GitHub's `/user.email` is the account's *public profile* email,
        //    which GitHub does NOT guarantee has been verified. Trusting it
        //    as verified is an account-takeover vector (S5 / HEA-1751): a
        //    user can set an arbitrary unverified address there and, if we
        //    auto-link on verified email, take over a matching local
        //    account. We therefore always confirm against `/user/emails`
        //    and only accept an address that appears as a verified row.
        let verified = fetch_verified_emails(&*self.http, &token.access_token);
        let (email, email_verified) = resolve_verified_email(user.email.as_deref(), &verified);

        // GitHub doesn't split names; leave first/last empty so the engine
        // can synthesize display_name from the existing `display_name` field.
        Ok(ExternalIdentity {
            idp_id: self.config.id.clone(),
            external_sub: user
                .id
                .as_i64()
                .map(|n| n.to_string())
                .or_else(|| user.id.as_str().map(str::to_string))
                .unwrap_or_else(|| user.login.clone()),
            email,
            email_verified,
            display_name: user.name.unwrap_or(user.login),
            first_name: String::new(),
            last_name: String::new(),
            picture_url: user.avatar_url,
        })
    }
}

/// Fetches the caller's GitHub email addresses and returns only the
/// verified rows as `(email, primary)` pairs.
///
/// Unverified rows are dropped. Returns an empty vec when the call fails,
/// the token lacks the `user:email` scope, or the body cannot be parsed —
/// callers treat "no verified rows" as "no trusted email".
fn fetch_verified_emails(
    http: &dyn FederationHttpTransport,
    access_token: &str,
) -> Vec<(String, bool)> {
    let Ok(resp) = http.send(&FedHttpRequest {
        method: "GET",
        url: "https://api.github.com/user/emails".to_string(),
        headers: vec![
            (
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            ),
            (
                "Accept".to_string(),
                "application/vnd.github+json".to_string(),
            ),
            ("User-Agent".to_string(), "Hearth".to_string()),
        ],
        body: Vec::new(),
        content_type: None,
    }) else {
        return Vec::new();
    };
    if resp.status < 200 || resp.status >= 300 {
        return Vec::new();
    }
    #[derive(Deserialize)]
    struct EmailRow {
        email: String,
        primary: bool,
        verified: bool,
    }
    let rows: Vec<EmailRow> = serde_json::from_str(&resp.body).unwrap_or_default();
    rows.into_iter()
        .filter(|r| r.verified)
        .map(|r| (r.email, r.primary))
        .collect()
}

/// Chooses a trusted email from GitHub's *verified* address list.
///
/// The public profile email (`/user.email`) is only accepted when it also
/// appears among the verified rows. Otherwise we fall back to the verified
/// primary, then any verified address. When nothing is verified we return
/// an empty, unverified result so downstream auto-linking is disabled (a
/// caller must never auto-link on an unverified address — see S5).
fn resolve_verified_email(
    public_email: Option<&str>,
    verified: &[(String, bool)],
) -> (String, bool) {
    if let Some(p) = public_email.filter(|e| !e.is_empty()) {
        if verified.iter().any(|(e, _)| e.eq_ignore_ascii_case(p)) {
            return (p.to_string(), true);
        }
    }
    if let Some((e, _)) = verified.iter().find(|(_, primary)| *primary) {
        return (e.clone(), true);
    }
    if let Some((e, _)) = verified.first() {
        return (e.clone(), true);
    }
    (String::new(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{IdpId, RealmId, Timestamp};
    use crate::identity::federation::http::StubFederationTransport;
    use crate::identity::federation::types::FederationSecret;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn gh_config() -> IdpConfig {
        IdpConfig {
            id: IdpId::new(Uuid::nil()),
            realm_id: RealmId::new(Uuid::nil()),
            name: "github".to_string(),
            kind: IdpKind::GitHub,
            display_name: "GitHub".to_string(),
            issuer: "https://github.com".to_string(),
            authorization_endpoint: "https://github.com/login/oauth/authorize".to_string(),
            token_endpoint: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_endpoint: Some("https://api.github.com/user".to_string()),
            jwks_uri: None,
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
            client_id: "gh-client".to_string(),
            client_secret: FederationSecret::new("gh-secret".to_string()),
            claim_mappings: BTreeMap::new(),
            leeway_seconds: IdpConfig::default_leeway_seconds(),
            want_assertions_signed: false,
            apple: None,
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        }
    }

    fn state() -> StateBag {
        StateBag {
            state_token: "st".to_string(),
            realm_id: RealmId::new(Uuid::nil()),
            idp_id: IdpId::new(Uuid::nil()),
            nonce: "n".to_string(),
            pkce_verifier: "vvvvvv".to_string(),
            return_to: "/".to_string(),
            expires_at: Timestamp::from_micros(0),
            apple_user_json: None,
        }
    }

    #[test]
    fn github_begin_emits_expected_query_parameters() {
        let conn = GithubConnector::new(
            gh_config(),
            Arc::new(StubFederationTransport::new()),
            "https://h/cb".to_string(),
        );
        let url = conn.begin(&state()).expect("url").0;
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=gh-client"));
        assert!(url.contains("state=st"));
        assert!(url.contains("code_challenge="));
        assert!(
            url.contains("scope=read%3Auser+user%3Aemail")
                || url.contains("scope=read%3Auser%20user%3Aemail")
        );
        // No OIDC nonce for GitHub.
        assert!(!url.contains("nonce="));
    }

    #[test]
    fn github_exchange_trusts_public_email_only_when_confirmed_verified() {
        let cfg = gh_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub(
            "POST",
            cfg.token_endpoint.clone(),
            200,
            r#"{"access_token":"abc","token_type":"bearer"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user",
            200,
            r#"{"id":42,"login":"alice","name":"Alice","email":"alice@example.com","avatar_url":"https://a/"}"#,
        );
        // The public profile email is only trusted because it also appears
        // as a verified row in /user/emails.
        stub.stub(
            "GET",
            "https://api.github.com/user/emails",
            200,
            r#"[{"email":"alice@example.com","primary":true,"verified":true}]"#,
        );
        let conn = GithubConnector::new(cfg, stub.clone(), "https://h/cb".to_string());
        let id = conn.exchange("code-xyz", &state()).expect("exchange");
        assert_eq!(id.external_sub, "42");
        assert_eq!(id.email, "alice@example.com");
        assert!(id.email_verified);
        assert_eq!(id.display_name, "Alice");
        assert_eq!(id.picture_url.as_deref(), Some("https://a/"));
    }

    #[test]
    fn github_exchange_does_not_trust_unconfirmed_public_email() {
        // S5 regression: /user.email is present but /user/emails reports it
        // as UNVERIFIED. The public profile address must NOT be trusted or
        // marked verified — otherwise it becomes an account-takeover vector.
        let cfg = gh_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub(
            "POST",
            cfg.token_endpoint.clone(),
            200,
            r#"{"access_token":"abc"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user",
            200,
            r#"{"id":42,"login":"alice","email":"victim@example.com"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user/emails",
            200,
            r#"[{"email":"victim@example.com","primary":true,"verified":false}]"#,
        );
        let conn = GithubConnector::new(cfg, stub.clone(), "https://h/cb".to_string());
        let id = conn.exchange("code", &state()).expect("exchange");
        assert_eq!(id.email, "", "unverified public email must not be surfaced");
        assert!(
            !id.email_verified,
            "unverified public email must not be marked verified"
        );
    }

    #[test]
    fn github_exchange_falls_back_to_user_emails_when_public_email_missing() {
        let cfg = gh_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub(
            "POST",
            cfg.token_endpoint.clone(),
            200,
            r#"{"access_token":"abc"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user",
            200,
            r#"{"id":42,"login":"alice","name":"Alice"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user/emails",
            200,
            r#"[
              {"email":"other@example.com","primary":false,"verified":true},
              {"email":"alice@example.com","primary":true,"verified":true}
            ]"#,
        );
        let conn = GithubConnector::new(cfg, stub.clone(), "https://h/cb".to_string());
        let id = conn.exchange("code", &state()).expect("exchange");
        assert_eq!(id.email, "alice@example.com");
        assert!(id.email_verified);
    }

    #[test]
    fn github_exchange_returns_empty_email_when_all_rows_unverified() {
        let cfg = gh_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub(
            "POST",
            cfg.token_endpoint.clone(),
            200,
            r#"{"access_token":"abc"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user",
            200,
            r#"{"id":42,"login":"alice"}"#,
        );
        stub.stub(
            "GET",
            "https://api.github.com/user/emails",
            200,
            r#"[{"email":"a@b.c","primary":true,"verified":false}]"#,
        );
        let conn = GithubConnector::new(cfg, stub.clone(), "https://h/cb".to_string());
        let id = conn.exchange("code", &state()).expect("exchange");
        assert_eq!(id.email, "");
        assert!(!id.email_verified);
    }

    #[test]
    fn github_exchange_rejects_5xx_on_token_endpoint() {
        let cfg = gh_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub("POST", cfg.token_endpoint.clone(), 500, "oops");
        let conn = GithubConnector::new(cfg, stub, "https://h/cb".to_string());
        assert!(matches!(
            conn.exchange("code", &state()),
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }
}

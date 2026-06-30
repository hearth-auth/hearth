//! HearthClient — OAuth flows, RBAC predicates, JWKS-backed token verification.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand::RngCore;
use reqwest::header;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::claims::Claims;
use crate::error::HearthError;
use crate::jwks_cache::JwksCache;
use crate::types::*;

// ── Discovery doc cache ───────────────────────────────────────────────────────

#[derive(Clone)]
struct DiscoveryDoc {
    token_endpoint: String,
    device_authorization_endpoint: Option<String>,
    jwks_uri: String,
}

impl DiscoveryDoc {
    fn from_json(value: &Value, source_url: &str) -> Result<Self, HearthError> {
        Ok(Self {
            token_endpoint: value["token_endpoint"]
                .as_str()
                .ok_or_else(|| HearthError::DiscoveryError {
                    url: source_url.to_string(),
                    message: "missing token_endpoint".into(),
                })?
                .to_string(),
            device_authorization_endpoint: value["device_authorization_endpoint"]
                .as_str()
                .map(str::to_string),
            jwks_uri: value["jwks_uri"]
                .as_str()
                .ok_or_else(|| HearthError::DiscoveryError {
                    url: source_url.to_string(),
                    message: "missing jwks_uri".into(),
                })?
                .to_string(),
        })
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Configuration parameters for [`HearthClientBuilder`] (spec §1).
pub struct HearthClientConfig {
    pub issuer_url: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// Override JWKS cache TTL. `None` → respect `Cache-Control`, default 5 min.
    pub jwks_ttl: Option<Duration>,
    /// Timeout for all outbound HTTP calls. `None` → 10 s.
    pub http_timeout: Option<Duration>,
}

/// Builder for [`HearthClient`] (spec §1 config table).
///
/// OIDC auto-discovery is deferred until the first call that needs an endpoint URL.
///
/// # Example
/// ```rust,ignore
/// let client = HearthClientBuilder::new("https://auth.example.com/realms/my-realm")
///     .client_id("my-app")
///     .client_secret("s3cr3t")
///     .build();
/// ```
pub struct HearthClientBuilder {
    issuer_url: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    jwks_ttl: Option<Duration>,
    http_timeout: Option<Duration>,
}

impl HearthClientBuilder {
    /// Start building with the Hearth realm issuer URL.
    pub fn new(issuer_url: impl Into<String>) -> Self {
        Self {
            issuer_url: issuer_url.into().trim_end_matches('/').to_string(),
            client_id: None,
            client_secret: None,
            jwks_ttl: None,
            http_timeout: None,
        }
    }

    /// Set the OAuth `client_id` (required for flows that need a client identity).
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// Set the OAuth `client_secret` (required for confidential client flows).
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Override the JWKS cache TTL. Ignores `Cache-Control` from the server.
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_ttl = Some(ttl);
        self
    }

    /// Timeout for all outbound HTTP calls (default: 10 s).
    pub fn http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = Some(timeout);
        self
    }

    /// Consume the builder and produce a [`HearthClient`].
    ///
    /// Discovery is deferred — no network calls are made here.
    pub fn build(self) -> HearthClient {
        let timeout = self.http_timeout.unwrap_or(Duration::from_secs(10));
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client");
        let jwks_cache = JwksCache::new(http.clone(), self.jwks_ttl);
        HearthClient {
            base_url: self.issuer_url.clone(),
            realm_id: String::new(),
            http,
            issuer_url: Some(self.issuer_url),
            client_id: self.client_id,
            client_secret: self.client_secret,
            jwks_cache,
            discovery_cache: Arc::new(Mutex::new(None)),
        }
    }
}

// ── HearthClient ──────────────────────────────────────────────────────────────

/// Client for Hearth OAuth flows, JWKS-backed token verification, and RBAC predicates.
///
/// ## Construction
/// - **Recommended**: [`HearthClientBuilder`] — configures `issuer_url`, `client_id`,
///   `jwks_ttl`, and enables OIDC auto-discovery for all endpoint URLs.
/// - **Simple / backward-compat**: [`HearthClient::new`] — takes `base_url` and
///   `realm_id` directly; skips OIDC discovery.
///
/// Clone is cheap: the inner [`reqwest::Client`] and caches are reference-counted.
#[derive(Clone)]
pub struct HearthClient {
    base_url: String,
    realm_id: String,
    http: reqwest::Client,
    issuer_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    jwks_cache: JwksCache,
    discovery_cache: Arc<Mutex<Option<DiscoveryDoc>>>,
}

impl HearthClient {
    /// Create a client from a base URL and realm ID (no OIDC discovery).
    ///
    /// JWKS is served from `{base_url}/.well-known/jwks.json`.
    /// For full OIDC auto-discovery, use [`HearthClientBuilder`].
    pub fn new(base_url: impl Into<String>, realm_id: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let realm_id = realm_id.into();
        let http = reqwest::Client::builder()
            .default_headers({
                let mut h = header::HeaderMap::new();
                h.insert(
                    "X-Realm-ID",
                    header::HeaderValue::from_str(&realm_id).expect("valid realm id"),
                );
                h
            })
            .build()
            .expect("reqwest client");
        let jwks_cache = JwksCache::new(http.clone(), None);
        Self {
            base_url,
            realm_id,
            http,
            issuer_url: None,
            client_id: None,
            client_secret: None,
            jwks_cache,
            discovery_cache: Arc::new(Mutex::new(None)),
        }
    }

    // ------------------------------------------------------------------
    // Static bootstrap (dev-only)
    // ------------------------------------------------------------------

    pub async fn bootstrap(base_url: &str) -> Result<BootstrapResponse, HearthError> {
        let url = format!("{}/admin/bootstrap", base_url.trim_end_matches('/'));
        let resp = reqwest::Client::new().post(&url).send().await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // Internal: OIDC discovery + JWKS URL seeding
    // ------------------------------------------------------------------

    async fn get_or_fetch_discovery(&self) -> Result<DiscoveryDoc, HearthError> {
        {
            let cache = self.discovery_cache.lock().await;
            if let Some(doc) = cache.as_ref() {
                return Ok(doc.clone());
            }
        }

        let issuer = self.issuer_url.as_deref().unwrap_or(&self.base_url);
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer);

        let resp = self.http.get(&discovery_url).send().await.map_err(|e| {
            HearthError::DiscoveryError {
                url: discovery_url.clone(),
                message: e.to_string(),
            }
        })?;

        let value: Value = resp.json().await.map_err(|e| HearthError::DiscoveryError {
            url: discovery_url.clone(),
            message: format!("JSON parse: {e}"),
        })?;

        let doc = DiscoveryDoc::from_json(&value, &discovery_url)?;
        self.jwks_cache.set_url(&doc.jwks_uri).await;

        let mut cache = self.discovery_cache.lock().await;
        *cache = Some(doc.clone());
        Ok(doc)
    }

    /// Ensure the JWKS cache has a URL to fetch from (lazy init, called by verify_token).
    async fn ensure_jwks_url(&self) -> Result<(), HearthError> {
        if self.issuer_url.is_some() {
            // Discovery sets the JWKS URL as a side-effect.
            self.get_or_fetch_discovery().await?;
        } else {
            // No discovery — use the conventional path under base_url.
            let url = format!("{}/.well-known/jwks.json", self.base_url);
            self.jwks_cache.set_url(url).await;
        }
        Ok(())
    }

    /// Return the token endpoint URL, using discovery when `issuer_url` is configured.
    async fn token_endpoint(&self) -> Result<String, HearthError> {
        if self.issuer_url.is_some() {
            Ok(self.get_or_fetch_discovery().await?.token_endpoint)
        } else {
            Ok(format!("{}/token", self.base_url))
        }
    }

    // ------------------------------------------------------------------
    // §2 verify_token — Ed25519/EdDSA JWKS-backed verification (spec §7.1)
    // ------------------------------------------------------------------

    /// Verify a JWT against Hearth's JWKS and return typed claims (spec §2).
    ///
    /// Executes the five validation steps required by spec §2:
    /// 1. Verify Ed25519/EdDSA signature against cached JWKS (re-fetches on miss).
    /// 2. Verify `exp` is not in the past (5 s clock skew allowed).
    /// 3. Verify `iss` matches the configured issuer URL.
    /// 4. Verify `aud` contains `client_id` when configured.
    /// 5. Verify `iat` is not more than 5 s in the future.
    ///
    /// Returns [`HearthError::RequiredActionError`] when `token_type == "required_action"`.
    pub async fn verify_token(&self, token: &str) -> Result<Claims, HearthError> {
        // Seed the JWKS cache URL if not already done.
        self.ensure_jwks_url().await?;

        // Parse JWT header to get kid + algorithm.
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| HearthError::TokenInvalidError { reason: e.to_string() })?;

        let kid = header.kid.ok_or_else(|| HearthError::TokenInvalidError {
            reason: "JWT header is missing 'kid'".into(),
        })?;

        // Look up key from JWKS cache (fetches + retries on miss, per spec §2).
        let jwk =
            self.jwks_cache.get(&kid).await?.ok_or_else(|| HearthError::JWKSFetchError {
                url: "JWKS".into(),
                message: format!("kid '{kid}' not found in JWKS"),
            })?;

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| HearthError::TokenInvalidError {
            reason: format!("invalid JWK for kid '{kid}': {e}"),
        })?;

        // Steps 2–4: build validation parameters.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 5; // 5 s clock skew

        let issuer = self.issuer_url.as_deref().unwrap_or(&self.base_url);
        validation.set_issuer(&[issuer]);

        if let Some(aud) = &self.client_id {
            validation.set_audience(&[aud.as_str()]);
        } else {
            validation.validate_aud = false;
        }

        // Steps 1–4: signature + exp + iss + aud (jsonwebtoken handles all four).
        let token_data = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation)
            .map_err(|e| map_jwt_error(e, issuer, self.client_id.as_deref()))?;

        let claims = Claims::from_value(token_data.claims);

        // Step 5: iat not in the future (5 s skew).
        if let Some(iat) = claims.issuedAt() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if iat > now + 5 {
                return Err(HearthError::TokenInvalidError {
                    reason: format!("iat {iat} is in the future"),
                });
            }
        }

        // Guard: required_action tokens must never be accepted as access tokens.
        if claims.tokenType() == "required_action" {
            let required_actions = claims
                .get("required_actions")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            return Err(HearthError::RequiredActionError {
                required_actions,
                redirect_uri: None,
            });
        }

        Ok(claims)
    }

    // ------------------------------------------------------------------
    // §4.5.1 Client Credentials Grant (RFC 6749 §4.4)
    // ------------------------------------------------------------------

    /// Obtain a machine-to-machine access token.
    ///
    /// `client_id` and `client_secret` are sent as form body fields per RFC 6749 §2.3.1
    /// (never as query parameters).  The response contains no `refresh_token`.
    pub async fn client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse, HearthError> {
        let token_url = self.token_endpoint().await?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];
        let scope_owned;
        if let Some(s) = scope {
            scope_owned = s.to_string();
            form.push(("scope", &scope_owned));
        }
        let resp = self.http.post(&token_url).form(&form).send().await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // §4.5.2 Device Authorization Flow (RFC 8628)
    // ------------------------------------------------------------------

    /// Initiate a device authorization flow.
    ///
    /// Returns the `device_code`, `user_code`, and `verification_uri` to display to
    /// the user.  Poll with [`HearthClient::poll_device_token`] until the user approves.
    pub async fn start_device_flow(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<DeviceAuthorizationResponse, HearthError> {
        let device_url = if self.issuer_url.is_some() {
            self.get_or_fetch_discovery()
                .await?
                .device_authorization_endpoint
                .ok_or_else(|| HearthError::DiscoveryError {
                    url: "discovery".into(),
                    message: "server does not advertise device_authorization_endpoint".into(),
                })?
        } else {
            format!("{}/device/authorize", self.base_url)
        };

        let mut form: Vec<(&str, &str)> = vec![("client_id", client_id)];
        let scope_owned;
        if let Some(s) = scope {
            scope_owned = s.to_string();
            form.push(("scope", &scope_owned));
        }
        let resp = self.http.post(&device_url).form(&form).send().await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Poll the token endpoint until the device flow completes or the code expires.
    ///
    /// Per RFC 8628 §3.5:
    /// - `authorization_pending` → continues polling.
    /// - `slow_down` → adds 5 s to the polling interval per occurrence.
    /// - `expired_token` → returns [`HearthError::TokenExpiredError`].
    pub async fn poll_device_token(
        &self,
        client_id: &str,
        device_code: &str,
        interval_secs: u64,
    ) -> Result<TokenResponse, HearthError> {
        let token_url = self.token_endpoint().await?;
        let mut interval = interval_secs;

        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let resp = self
                .http
                .post(&token_url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", client_id),
                ])
                .send()
                .await?;

            if resp.status().is_success() {
                return Ok(resp.json().await?);
            }

            let err: OAuthErrorResponse = resp.json().await.map_err(|e| {
                HearthError::Other(format!("device poll: could not parse error response: {e}"))
            })?;

            match err.error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval += 5;
                    continue;
                }
                "expired_token" => {
                    return Err(HearthError::TokenExpiredError { expired_at: 0 });
                }
                _ => {
                    return Err(HearthError::Api {
                        status: 400,
                        message: err.error,
                        details: err.error_description
                            .map(|d| serde_json::json!({"description": d})),
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // §4.5.3 Magic-Link Initiation (Passwordless)
    // ------------------------------------------------------------------

    /// Request a magic-link (passwordless) login email for `email`.
    ///
    /// The server sends an out-of-band email; no tokens are returned.
    pub async fn initiate_magic_link(
        &self,
        email: &str,
        client_id: &str,
        redirect_uri: &str,
        scope: Option<&str>,
    ) -> Result<(), HearthError> {
        let url = format!("{}/v1/passwordless/initiate", self.base_url);
        let mut body = serde_json::json!({
            "email": email,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        });
        if let Some(s) = scope {
            body["scope"] = Value::String(s.to_string());
        }
        let resp = self.http.post(&url).json(&body).send().await?;
        Self::check(&resp)?;
        Ok(())
    }

    /// Exchange a magic-link token for tokens (spec §4.5.3 / §7.2 C-12).
    ///
    /// Completes the passwordless flow started by [`HearthClient::initiate_magic_link`]:
    /// posts `grant_type=urn:hearth:grant-type:magic-link` with the opaque `token`
    /// from the magic-link URL to the token endpoint. The token is sent in the
    /// form body, never the URL.
    pub async fn exchange_magic_link(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<TokenResponse, HearthError> {
        let token_url = self.token_endpoint().await?;
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", "urn:hearth:grant-type:magic-link"),
            ("token", token),
            ("client_id", client_id),
        ];
        let resp = self.http.post(&token_url).form(&form).send().await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // Session-version polling
    // ------------------------------------------------------------------

    /// Retrieve a point-in-time snapshot of all session versions for the caller.
    ///
    /// Use the returned `cursor` for subsequent delta polls.
    pub async fn session_version_snapshot(
        &self,
        access_token: &str,
    ) -> Result<SvSnapshotResponse, HearthError> {
        let resp = self
            .http
            .get(format!("{}/v1/session-version/snapshot", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Poll for session-version changes since `cursor`.
    ///
    /// Clients should call this on a short interval to detect revocations.
    pub async fn session_version_delta(
        &self,
        access_token: &str,
        cursor: &str,
    ) -> Result<SvDeltaResponse, HearthError> {
        let resp = self
            .http
            .get(format!("{}/v1/session-version/delta", self.base_url))
            .query(&[("cursor", cursor)])
            .bearer_auth(access_token)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // OAuth flows (authorization code + PKCE extension)
    // ------------------------------------------------------------------

    /// Build an authorization URL for the authorization code flow.
    ///
    /// Pass `code_challenge` + `code_challenge_method` (typically `"S256"`) to enable
    /// PKCE (RFC 7636).  Use [`crate::pkce::generate_pkce_pair`] to generate the pair,
    /// then pass the verifier to [`HearthClient::exchange_code`].
    pub async fn authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        resource: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
    ) -> Result<AuthorizeResponse, HearthError> {
        let mut params = vec![
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", scope),
            ("state", state),
        ];
        if let Some(r) = resource {
            params.push(("resource", r));
        }
        if let Some(cc) = code_challenge {
            params.push(("code_challenge", cc));
            params.push(("code_challenge_method", code_challenge_method.unwrap_or("S256")));
        }
        let resp = self
            .http
            .get(format!("{}/authorize", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Begin an authorization-code login: generate PKCE, build the authorization URL,
    /// and return the values that must be persisted before redirecting the browser.
    ///
    /// # Developer flow
    /// 1. Call `begin_login(redirect_uri, scopes)` — receive `LoginBeginResult`.
    /// 2. Persist `result.state` and `result.code_verifier` in session storage.
    /// 3. Redirect the browser to `result.authorization_url`.
    /// 4. On the callback route, call `complete_login(code, code_verifier, redirect_uri)`.
    ///
    /// `scopes` defaults to `"openid"` when `None`.
    pub async fn begin_login(
        &self,
        redirect_uri: &str,
        scopes: Option<&str>,
    ) -> Result<LoginBeginResult, HearthError> {
        let client_id = self.client_id.as_deref().ok_or_else(|| {
            HearthError::ConfigurationError {
                message: "client_id is required for begin_login".into(),
            }
        })?;

        let pkce = crate::pkce::generate_pkce_pair();
        let state = Self::generate_state();

        let auth_base = format!("{}/authorize", self.base_url);
        let mut url = reqwest::Url::parse(&auth_base).map_err(|e| {
            HearthError::Other(format!("invalid base_url for begin_login: {e}"))
        })?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", "code");
            pairs.append_pair("client_id", client_id);
            pairs.append_pair("redirect_uri", redirect_uri);
            pairs.append_pair("scope", scopes.unwrap_or("openid"));
            pairs.append_pair("state", &state);
            pairs.append_pair("code_challenge", &pkce.challenge);
            pairs.append_pair("code_challenge_method", pkce.method);
        }

        Ok(LoginBeginResult {
            authorization_url: url.to_string(),
            state,
            code_verifier: pkce.verifier,
        })
    }

    /// Complete an authorization-code login: exchange the callback code for tokens.
    ///
    /// `code_verifier` must be the value returned by [`HearthClient::begin_login`].
    pub async fn complete_login(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, HearthError> {
        let client_id = self.client_id.as_deref().unwrap_or("");
        let client_secret = self.client_secret.as_deref().unwrap_or("");
        self.exchange_code(code, client_id, client_secret, redirect_uri, Some(code_verifier))
            .await
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, HearthError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(cv) = code_verifier {
            form.push(("code_verifier", cv));
        }
        let resp = self
            .http
            .post(format!("{}/token", self.base_url))
            .form(&form)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn refresh_tokens(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, HearthError> {
        let resp = self
            .http
            .post(format!("{}/token", self.base_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn register_client(
        &self,
        req: &RegisterClientRequest,
    ) -> Result<OAuthClient, HearthError> {
        let resp = self
            .http
            .post(format!("{}/clients", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // Protected endpoints
    // ------------------------------------------------------------------

    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfoResponse, HearthError> {
        let resp = self
            .http
            .get(format!("{}/userinfo", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn permissions(
        &self,
        access_token: &str,
    ) -> Result<MePermissionsResponse, HearthError> {
        let resp = self
            .http
            .get(format!("{}/v1/me/permissions", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Call `POST /introspect` and return the live token state (RFC 7662).
    ///
    /// Uses HTTP Basic Auth per RFC 7662 §2.1.  Do **not** cache the response.
    pub async fn introspect(
        &self,
        token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<IntrospectionResponse, HearthError> {
        let resp = self
            .http
            .post(format!("{}/introspect", self.base_url))
            .basic_auth(client_id, Some(client_secret))
            .form(&[("token", token)])
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Mode-aware permission check (spec §3.5).
    ///
    /// - `Embedded` — decodes JWT locally; checks `permissions[]`. No network call.
    /// - `Introspection` — calls `POST /introspect`; validates echoed mode; checks live perms.
    /// - `Decision` — calls `POST /oauth/authorize` per request. Fail-closed on errors.
    pub async fn check_permission(
        &self,
        token: &str,
        permission: &str,
        mode: AccessTokenAuthorization,
        opts: CheckPermissionOpts,
    ) -> Result<bool, HearthError> {
        match mode {
            AccessTokenAuthorization::Embedded => Self::has_permission(token, permission),
            AccessTokenAuthorization::Introspection => {
                let (cid, csec) =
                    opts.client_credentials
                        .ok_or_else(|| HearthError::ConfigurationError {
                            message: "Introspection mode requires client_credentials in CheckPermissionOpts".into(),
                        })?;
                let resp = self.introspect(token, &cid, &csec).await?;
                if !resp.active {
                    return Ok(false);
                }
                if let Some(echoed) = resp.mode {
                    if echoed != AccessTokenAuthorization::Introspection {
                        return Err(HearthError::ModeMismatch {
                            expected: AccessTokenAuthorization::Introspection,
                            actual: echoed,
                        });
                    }
                }
                Ok(resp.permissions.iter().any(|p| p == permission))
            }
            AccessTokenAuthorization::Decision => {
                let body = serde_json::json!({
                    "permission": permission,
                    "organization_id": opts.organization_id,
                    "resource": opts.resource,
                });
                let resp = self
                    .http
                    .post(format!("{}/oauth/authorize", self.base_url))
                    .bearer_auth(token)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| HearthError::AuthorizationFailed {
                        reason: format!("network error: {e}"),
                    })?;
                if !resp.status().is_success() {
                    return Err(HearthError::AuthorizationFailed {
                        reason: format!("HTTP {}", resp.status()),
                    });
                }
                let check: PermissionCheckResponse = resp.json().await.map_err(|e| {
                    HearthError::AuthorizationFailed {
                        reason: format!("JSON decode: {e}"),
                    }
                })?;
                Ok(check.allowed)
            }
        }
    }

    pub async fn jwks(&self) -> Result<JwksDocument, HearthError> {
        let resp = self
            .http
            .get(format!("{}/.well-known/jwks.json", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn discovery(&self) -> Result<Value, HearthError> {
        let resp = self
            .http
            .get(format!("{}/.well-known/openid-configuration", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // RBAC predicates (local, no network call)
    // ------------------------------------------------------------------

    pub fn has_permission(token: &str, permission: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        let perms: Vec<String> = claims
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(perms.iter().any(|p| p == permission))
    }

    pub fn has_role(token: &str, role: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        let roles: Vec<String> = claims
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(roles.iter().any(|r| r == role))
    }

    pub fn in_group(token: &str, group_slug: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        let groups: Vec<String> = claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(groups.iter().any(|g| g == group_slug))
    }

    pub fn in_org(token: &str, org_id: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        Ok(claims.get("oid").and_then(|v| v.as_str()) == Some(org_id))
    }

    fn generate_state() -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn decode_claims(token: &str) -> Result<Value, HearthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return Err(HearthError::Other("invalid JWT format".into()));
        }
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| HearthError::Other(format!("base64 decode: {e}")))?;
        let claims: Value = serde_json::from_slice(&payload)?;
        Ok(claims)
    }

    // ------------------------------------------------------------------
    // WebAuthn
    // ------------------------------------------------------------------

    pub async fn webauthn_register_begin(
        &self,
        access_token: &str,
        rp_id: &str,
        discoverable: bool,
    ) -> Result<Value, HearthError> {
        let resp = self
            .http
            .post(format!("{}/webauthn/register/begin", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({
                "rp_id": rp_id,
                "discoverable": discoverable,
            }))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn webauthn_register_complete(
        &self,
        access_token: &str,
        client_data_json: &str,
        attestation_object: &str,
        origin: &str,
        discoverable: bool,
    ) -> Result<Value, HearthError> {
        let resp = self
            .http
            .post(format!("{}/webauthn/register/complete", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({
                "client_data_json": client_data_json,
                "attestation_object": attestation_object,
                "origin": origin,
                "discoverable": discoverable,
            }))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn webauthn_auth_begin(
        &self,
        rp_id: &str,
        user_id: Option<&str>,
    ) -> Result<Value, HearthError> {
        let mut body = serde_json::json!({ "rp_id": rp_id });
        if let Some(uid) = user_id {
            body["user_id"] = Value::String(uid.to_string());
        }
        let resp = self
            .http
            .post(format!("{}/webauthn/auth/begin", self.base_url))
            .json(&body)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn webauthn_auth_complete(
        &self,
        credential_id: &str,
        client_data_json: &str,
        authenticator_data: &str,
        signature: &str,
        origin: &str,
        user_handle: Option<&str>,
    ) -> Result<Value, HearthError> {
        let mut body = serde_json::json!({
            "credential_id": credential_id,
            "client_data_json": client_data_json,
            "authenticator_data": authenticator_data,
            "signature": signature,
            "origin": origin,
        });
        if let Some(uh) = user_handle {
            body["user_handle"] = Value::String(uh.to_string());
        }
        let resp = self
            .http
            .post(format!("{}/webauthn/auth/complete", self.base_url))
            .json(&body)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn check(resp: &reqwest::Response) -> Result<(), HearthError> {
        let status = resp.status().as_u16();
        if status < 400 {
            return Ok(());
        }
        Err(HearthError::Api {
            status,
            message: format!("{}", resp.status()),
            details: None,
        })
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// RFC 6749 / RFC 8628 JSON error response shape.
#[derive(serde::Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Map a `jsonwebtoken` error to the typed spec §5 variant.
fn map_jwt_error(
    err: jsonwebtoken::errors::Error,
    issuer: &str,
    audience: Option<&str>,
) -> HearthError {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::ExpiredSignature => HearthError::TokenExpiredError { expired_at: 0 },
        ErrorKind::ImmatureSignature => HearthError::TokenNotYetValidError { not_before: 0 },
        ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm | ErrorKind::InvalidKeyFormat => {
            HearthError::TokenInvalidError { reason: err.to_string() }
        }
        ErrorKind::InvalidIssuer => HearthError::TokenIssuerError {
            expected: issuer.to_string(),
            actual: "unknown".to_string(),
        },
        ErrorKind::InvalidAudience => HearthError::TokenAudienceError {
            expected: audience.unwrap_or("").to_string(),
            actual: vec![],
        },
        _ => HearthError::TokenInvalidError { reason: err.to_string() },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use serde_json::json;

    // ── Key generation helpers ────────────────────────────────────────────

    /// Returns `(pkcs8_der, raw_32_byte_public_key)`.
    fn make_ed25519_pkcs8() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = kp.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), pub_key)
    }

    fn pkcs8_to_pem(der: &[u8]) -> Vec<u8> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem.into_bytes()
    }

    fn make_test_jwt(claims: &serde_json::Value, pkcs8_der: &[u8], kid: &str) -> String {
        let pem = pkcs8_to_pem(pkcs8_der);
        let key = EncodingKey::from_ed_pem(&pem).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &key).unwrap()
    }

    fn make_jwk(kid: &str, pub_key_bytes: &[u8]) -> jsonwebtoken::jwk::Jwk {
        let x = URL_SAFE_NO_PAD.encode(pub_key_bytes);
        let jwk_json = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "kid": kid,
            "alg": "EdDSA",
            "use": "sig"
        });
        serde_json::from_value(jwk_json).unwrap()
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Build a HearthClient with a pre-seeded JWKS cache (no live server needed).
    async fn client_with_cached_jwk(
        kid: &str,
        jwk: jsonwebtoken::jwk::Jwk,
        client_id: Option<&str>,
    ) -> HearthClient {
        let http = reqwest::Client::new();
        let cache = JwksCache::new(http.clone(), None);
        // Set a dummy URL so set_url guard is satisfied (won't be fetched because key is fresh).
        cache.set_url("https://auth.example.com/.well-known/jwks.json").await;
        cache.inject_for_test(kid, jwk).await;

        HearthClient {
            base_url: "https://auth.example.com".to_string(),
            realm_id: "realm-1".to_string(),
            http,
            issuer_url: None, // No discovery in unit tests
            client_id: client_id.map(str::to_string),
            client_secret: None,
            jwks_cache: cache,
            discovery_cache: Arc::new(Mutex::new(None)),
        }
    }

    // ── verify_token: error path (no live server or keys) ────────────────

    #[tokio::test]
    async fn verify_token_rejects_malformed_jwt() {
        let client = HearthClient::new("https://auth.example.com", "realm-1");
        let err = client.verify_token("not.a.jwt").await.unwrap_err();
        assert!(
            matches!(err, HearthError::TokenInvalidError { .. }),
            "expected TokenInvalidError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_token_rejects_jwt_without_kid() {
        // Craft a JWT with no kid in the header.
        let header_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\"}");
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"u1\"}");
        let token = format!("{header_b64}.{payload_b64}.fakesig");

        let client = HearthClient::new("https://auth.example.com", "realm-1");
        let err = client.verify_token(&token).await.unwrap_err();
        assert!(
            matches!(err, HearthError::TokenInvalidError { .. }),
            "expected TokenInvalidError for missing kid, got {err:?}"
        );
    }

    // ── verify_token: cryptographic success path ──────────────────────────

    #[tokio::test]
    async fn verify_token_accepts_valid_eddsa_jwt() {
        let (pkcs8_der, pub_key) = make_ed25519_pkcs8();
        let kid = "test-key-1";
        let issuer = "https://auth.example.com";
        let now = now_secs();

        let claims_json = json!({
            "sub": "user_abc",
            "iss": issuer,
            "exp": now + 3600,
            "iat": now,
            "jti": "test-jti",
            "token_type": "access",
        });

        let token = make_test_jwt(&claims_json, &pkcs8_der, kid);
        let jwk = make_jwk(kid, &pub_key);
        let client = client_with_cached_jwk(kid, jwk, None).await;

        let claims = client.verify_token(&token).await
            .expect("verify_token should succeed for a valid JWT");
        assert_eq!(claims.subject(), "user_abc");
        assert_eq!(claims.issuer(), issuer);
    }

    #[tokio::test]
    async fn verify_token_rejects_expired_jwt() {
        let (pkcs8_der, pub_key) = make_ed25519_pkcs8();
        let kid = "test-key-exp";
        let now = now_secs();

        let claims_json = json!({
            "sub": "user_abc",
            "iss": "https://auth.example.com",
            "exp": now - 3600, // expired 1h ago
            "iat": now - 7200,
            "token_type": "access",
        });

        let token = make_test_jwt(&claims_json, &pkcs8_der, kid);
        let jwk = make_jwk(kid, &pub_key);
        let client = client_with_cached_jwk(kid, jwk, None).await;

        let err = client.verify_token(&token).await.unwrap_err();
        assert!(
            matches!(err, HearthError::TokenExpiredError { .. }),
            "expected TokenExpiredError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_token_rejects_wrong_issuer() {
        let (pkcs8_der, pub_key) = make_ed25519_pkcs8();
        let kid = "test-key-iss";
        let now = now_secs();

        let claims_json = json!({
            "sub": "u",
            "iss": "https://evil.example.com", // wrong issuer
            "exp": now + 3600,
            "iat": now,
        });

        let token = make_test_jwt(&claims_json, &pkcs8_der, kid);
        let jwk = make_jwk(kid, &pub_key);
        let client = client_with_cached_jwk(kid, jwk, None).await;

        let err = client.verify_token(&token).await.unwrap_err();
        assert!(
            matches!(err, HearthError::TokenIssuerError { .. }),
            "expected TokenIssuerError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_token_rejects_required_action_token() {
        let (pkcs8_der, pub_key) = make_ed25519_pkcs8();
        let kid = "test-key-ra";
        let now = now_secs();

        let claims_json = json!({
            "sub": "u",
            "iss": "https://auth.example.com",
            "exp": now + 3600,
            "iat": now,
            "token_type": "required_action",
            "required_actions": ["VERIFY_EMAIL"],
        });

        let token = make_test_jwt(&claims_json, &pkcs8_der, kid);
        let jwk = make_jwk(kid, &pub_key);
        let client = client_with_cached_jwk(kid, jwk, None).await;

        let err = client.verify_token(&token).await.unwrap_err();
        match err {
            HearthError::RequiredActionError { required_actions, .. } => {
                assert_eq!(required_actions, vec!["VERIFY_EMAIL"]);
            }
            other => panic!("expected RequiredActionError, got {other:?}"),
        }
    }

    // ── builder ───────────────────────────────────────────────────────────

    #[test]
    fn builder_sets_fields() {
        let client = HearthClientBuilder::new("https://auth.example.com/realms/test")
            .client_id("my-client")
            .client_secret("s3cr3t")
            .jwks_ttl(Duration::from_secs(900))
            .build();
        assert_eq!(client.base_url, "https://auth.example.com/realms/test");
        assert_eq!(client.client_id.as_deref(), Some("my-client"));
        assert_eq!(
            client.issuer_url.as_deref(),
            Some("https://auth.example.com/realms/test")
        );
    }

    #[test]
    fn builder_trims_trailing_slash() {
        let client = HearthClientBuilder::new("https://auth.example.com/").build();
        assert_eq!(client.base_url, "https://auth.example.com");
    }

    // ── new types ─────────────────────────────────────────────────────────

    #[test]
    fn device_authorization_response_deserializes() {
        let json = json!({
            "device_code": "GmRhxyz",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://auth.example.com/activate",
            "verification_uri_complete": "https://auth.example.com/activate?user_code=WDJB-MJHT",
            "expires_in": 600,
            "interval": 5
        });
        let resp: DeviceAuthorizationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.user_code, "WDJB-MJHT");
        assert_eq!(resp.interval, 5);
        assert!(resp.verification_uri_complete.is_some());
    }

    #[test]
    fn sv_delta_response_deserializes() {
        let json = json!({
            "entries": [
                {"session_id": "sess_1", "version": 3, "event": "refreshed"}
            ],
            "cursor": "cur_abc",
            "has_more": false
        });
        let resp: SvDeltaResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].event, "refreshed");
    }

    #[test]
    fn sv_snapshot_response_deserializes() {
        let json = json!({ "sessions": [], "cursor": "snap_cur" });
        let resp: SvSnapshotResponse = serde_json::from_value(json).unwrap();
        assert!(resp.sessions.is_empty());
        assert_eq!(resp.cursor, "snap_cur");
    }

    #[test]
    fn token_response_without_refresh_token_ok() {
        let json = json!({
            "access_token": "eyJ...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:users"
        });
        let resp: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.access_token, "eyJ...");
        assert!(resp.refresh_token.is_none(), "client_credentials response has no refresh_token");
    }

    // ── begin_login / complete_login ──────────────────────────────────────────

    #[tokio::test]
    async fn begin_login_returns_well_formed_url() {
        let client = HearthClientBuilder::new("https://auth.example.com")
            .client_id("my-app")
            .client_secret("s3cr3t")
            .build();

        let result = client
            .begin_login("https://app.example.com/callback", None)
            .await
            .expect("begin_login");

        let url = reqwest::Url::parse(&result.authorization_url).expect("valid URL");
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(params.get("response_type").map(|v| v.as_ref()), Some("code"));
        assert_eq!(params.get("client_id").map(|v| v.as_ref()), Some("my-app"));
        assert_eq!(
            params.get("redirect_uri").map(|v| v.as_ref()),
            Some("https://app.example.com/callback")
        );
        assert_eq!(
            params.get("code_challenge_method").map(|v| v.as_ref()),
            Some("S256")
        );
    }

    #[tokio::test]
    async fn begin_login_code_challenge_matches_verifier() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::{Digest, Sha256};

        let client = HearthClientBuilder::new("https://auth.example.com")
            .client_id("my-app")
            .build();

        let result = client
            .begin_login("https://app.example.com/callback", None)
            .await
            .expect("begin_login");

        let url = reqwest::Url::parse(&result.authorization_url).expect("valid URL");
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        let challenge = params
            .get("code_challenge")
            .expect("code_challenge in URL")
            .to_string();

        let mut hasher = Sha256::new();
        hasher.update(result.code_verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(challenge, expected, "code_challenge must be BASE64URL(SHA256(code_verifier))");
    }

    #[tokio::test]
    async fn begin_login_state_is_non_empty_and_in_url() {
        let client = HearthClientBuilder::new("https://auth.example.com")
            .client_id("my-app")
            .build();

        let result = client
            .begin_login("https://app.example.com/callback", None)
            .await
            .expect("begin_login");

        assert!(!result.state.is_empty(), "state must not be empty");
        let url = reqwest::Url::parse(&result.authorization_url).expect("valid URL");
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(
            params.get("state").map(|v| v.as_ref()),
            Some(result.state.as_str())
        );
    }

    #[tokio::test]
    async fn begin_login_requires_client_id() {
        let client = HearthClientBuilder::new("https://auth.example.com").build();
        let err = client
            .begin_login("https://app.example.com/callback", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, HearthError::ConfigurationError { .. }),
            "expected ConfigurationError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn complete_login_posts_code_verifier_to_token_endpoint() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"access_token":"at","token_type":"Bearer","expires_in":3600}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            req
        });

        let client = HearthClient::new(base, "realm-1");
        let resp = client
            .complete_login("auth-code-xyz", "my-verifier-abc", "https://app.example.com/callback")
            .await
            .expect("complete_login");
        assert_eq!(resp.access_token, "at");

        let req = server.await.unwrap();
        let (_head, body) = req.split_once("\r\n\r\n").unwrap_or((&req, ""));
        assert!(
            body.contains("code_verifier=my-verifier-abc"),
            "code_verifier missing from request body: {body}"
        );
        assert!(body.contains("code=auth-code-xyz"), "code missing: {body}");
    }

    // ── exchange_magic_link (C-12) ────────────────────────────────────────

    #[tokio::test]
    async fn exchange_magic_link_posts_grant_with_token_in_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"access_token":"at","token_type":"Bearer","expires_in":3600}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            req
        });

        let client = HearthClient::new(base, "realm-1");
        let resp = client
            .exchange_magic_link("magic-token-xyz", "cid")
            .await
            .expect("exchange_magic_link");
        assert_eq!(resp.access_token, "at");
        assert_eq!(resp.token_type, "Bearer");

        let req = server.await.unwrap();
        let (head, body) = req.split_once("\r\n\r\n").unwrap_or((&req, ""));
        assert!(head.starts_with("POST /token "), "wrong target: {head}");
        assert!(
            body.contains("grant_type=urn%3Ahearth%3Agrant-type%3Amagic-link"),
            "missing magic-link grant: {body}"
        );
        assert!(body.contains("token=magic-token-xyz"), "missing token: {body}");
        assert!(body.contains("client_id=cid"), "missing client_id: {body}");
    }
}

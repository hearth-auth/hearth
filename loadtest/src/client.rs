//! Thin async HTTP client for the admin/OAuth endpoints the seed step drives
//! (HEA-1789).
//!
//! Self-contained rather than depending on the Hearth Rust SDK: the SDK's
//! `reqwest` is configured with the default (native-TLS) features, which would
//! pull OpenSSL into this rustls-only, no-OpenSSL build. Keeping a small local
//! client lets us stay on `rustls-tls` (matching `goose`).
//!
//! Only the endpoints the seed flow needs are implemented:
//! `POST /admin/bootstrap`, `POST /admin/users`, `POST /clients` (register a
//! password-grant client), `POST /token` (ROPC), and `POST /revoke`.
//!
//! Secrets discipline: this module never logs token or password material. The
//! admin bootstrap token lives only inside the [`SeedClient`] default headers.

use serde::Deserialize;

/// Errors from a seeding HTTP call.
#[derive(Debug)]
pub enum SeedError {
    /// Transport / connection error.
    Http(reqwest::Error),
    /// The server returned a non-2xx status. `body` is truncated and MUST NOT
    /// be constructed from any request that echoes a secret.
    Api {
        /// What we were doing when it failed (e.g. `"create_user"`).
        op: &'static str,
        /// HTTP status code.
        status: u16,
        /// Truncated response body for diagnostics.
        body: String,
    },
    /// Filesystem error writing the seed handle.
    Io(std::io::Error),
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "http error: {e}"),
            Self::Api { op, status, body } => {
                write!(f, "{op} failed: HTTP {status}: {body}")
            }
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

impl From<reqwest::Error> for SeedError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e)
    }
}

impl From<std::io::Error> for SeedError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result of the bootstrap call, holding what the seed flow needs.
#[derive(Debug)]
pub struct Bootstrap {
    /// The dev realm's ID (UUID string).
    pub realm_id: String,
    /// The bootstrap admin bearer token. SECRET — stored in the seed handle
    /// (0600 file) so the load run's `user_lookup` journey can authenticate
    /// admin endpoints. Must not be logged.
    pub admin_token: String,
}

#[derive(Deserialize)]
struct BootstrapResponse {
    realm_id: String,
    access_token: String,
}

#[derive(Deserialize)]
struct CreatedUser {
    id: String,
}

#[derive(Deserialize)]
struct RegisteredClient {
    client_id: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct DevSessionResponse {
    session_id: String,
}

/// A realm-scoped seeding client. All admin calls carry the bootstrap token
/// and `X-Realm-ID`; the anonymous OAuth calls (`/token`, `/revoke`) carry only
/// `X-Realm-ID`.
pub struct SeedClient {
    base_url: String,
    realm_id: String,
    http: reqwest::Client,
}

impl SeedClient {
    /// Bootstraps a dev instance and returns a realm-scoped client plus the
    /// bootstrap result.
    ///
    /// `admin_token` lets the seed attach to an **already-bootstrapped**
    /// instance: `POST /admin/bootstrap` only succeeds anonymously on a fresh
    /// realm; a re-bootstrap requires the bearer token from the first bootstrap
    /// and returns fresh credentials (200) instead of `401`. When `None` the
    /// call is anonymous (the fresh-instance path).
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx bootstrap
    /// response (e.g. when the target is not running in `--dev` mode, or when
    /// the instance is already bootstrapped and no `admin_token` was supplied).
    pub async fn bootstrap(
        base_url: &str,
        admin_token: Option<&str>,
    ) -> Result<(Self, Bootstrap), SeedError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let anon = reqwest::Client::builder().build()?;
        let mut req = anon.post(format!("{base_url}/admin/bootstrap"));
        if let Some(token) = admin_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let boot: BootstrapResponse = json_or_err("bootstrap", resp).await?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-Realm-ID",
            reqwest::header::HeaderValue::from_str(&boot.realm_id)
                .map_err(|_| api_err("bootstrap", 0, "invalid realm id in response"))?,
        );
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", boot.access_token))
                .map_err(|_| api_err("bootstrap", 0, "invalid token in response"))?,
        );
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        let bootstrap = Bootstrap {
            realm_id: boot.realm_id.clone(),
            admin_token: boot.access_token.clone(),
        };
        let client = Self {
            base_url,
            realm_id: boot.realm_id,
            http,
        };
        Ok((client, bootstrap))
    }

    /// The realm this client is scoped to.
    #[must_use]
    pub fn realm_id(&self) -> &str {
        &self.realm_id
    }

    /// Creates a user via `POST /admin/users` and returns its ID.
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx response.
    pub async fn create_user(&self, email: &str, display_name: &str) -> Result<String, SeedError> {
        let resp = self
            .http
            .post(format!("{}/admin/users", self.base_url))
            .json(&serde_json::json!({
                "email": email,
                "display_name": display_name,
            }))
            .send()
            .await?;
        let user: CreatedUser = json_or_err("create_user", resp).await?;
        Ok(user.id)
    }

    /// Registers a public OAuth client (authorization_code grant) via
    /// `POST /clients`, returning its `client_id`.
    ///
    /// The client is used as the authenticating party for introspect and revoke
    /// calls during the load run. ROPC (`grant_type=password`) was removed by
    /// HEA-1862; we no longer need a password-grant client, but the journeys
    /// still require a registered public client for endpoint authentication.
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx response.
    pub async fn register_client(&self, name: &str) -> Result<String, SeedError> {
        let resp = self
            .http
            .post(format!("{}/clients", self.base_url))
            .json(&serde_json::json!({
                "client_name": name,
                "redirect_uris": ["https://loadtest.test/callback"],
                "grant_types": ["authorization_code"],
            }))
            .send()
            .await?;
        let client: RegisteredClient = json_or_err("register_client", resp).await?;
        Ok(client.client_id)
    }

    /// Mints an access token for `user_id` via `POST /dev/seed-token` (dev-only).
    ///
    /// Creates a session and issues a real JWT for the given user. Used both
    /// during seeding (to populate the token corpus) and during load journeys
    /// that need to mint tokens dynamically (issuance + revoke). Replaces ROPC
    /// which was removed by HEA-1862 (HEA-1991).
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx response.
    pub async fn seed_token(&self, user_id: &str) -> Result<String, SeedError> {
        let resp = self
            .http
            .post(format!("{}/dev/seed-token", self.base_url))
            .json(&serde_json::json!({"user_id": user_id}))
            .send()
            .await?;
        let token: TokenResponse = json_or_err("seed_token", resp).await?;
        Ok(token.access_token)
    }

    /// Creates a raw session record for `user_id` via `POST /dev/seed-session`.
    ///
    /// The endpoint is dev-only and bypasses OAuth, writing a session record
    /// directly to storage. Use when `--sessions-frac > 0` to populate the
    /// session corpus without ROPC (removed by HEA-1862; this path added by
    /// HEA-1907).
    ///
    /// Returns the created session's ID (UUID string).
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx response.
    pub async fn create_dev_session(&self, user_id: &str) -> Result<String, SeedError> {
        let resp = self
            .http
            .post(format!("{}/dev/seed-session", self.base_url))
            .json(&serde_json::json!({"user_id": user_id}))
            .send()
            .await?;
        let session: DevSessionResponse = json_or_err("create_dev_session", resp).await?;
        Ok(session.session_id)
    }

    /// Sets a password credential on `user_id` via `POST /dev/seed-password`
    /// (dev-only, HEA-1998).
    ///
    /// `POST /admin/users` cannot set a credential, so this dev endpoint is the
    /// only boot-local way to give a seeded user a login password. Provisioning
    /// a **known** password is what enables the login / KDF saturation plane in
    /// `examples/http_saturation.rs --plane login` (pass the same value to that
    /// harness's `--login-password`).
    ///
    /// This never logs the password material.
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx response.
    pub async fn set_password(&self, user_id: &str, password: &str) -> Result<(), SeedError> {
        let resp = self
            .http
            .post(format!("{}/dev/seed-password", self.base_url))
            .json(&serde_json::json!({"user_id": user_id, "password": password}))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(status_err("set_password", resp).await)
        }
    }

    /// Revokes a token via `POST /revoke` (RFC 7009). The public `client_id`
    /// authenticates the call.
    ///
    /// # Errors
    /// Returns [`SeedError`] on transport failure or a non-2xx response.
    pub async fn revoke(&self, client_id: &str, token: &str) -> Result<(), SeedError> {
        let resp = self
            .http
            .post(format!("{}/revoke", self.base_url))
            .json(&serde_json::json!({
                "token": token,
                "token_type_hint": "access_token",
                "client_id": client_id,
            }))
            .send()
            .await?;
        // RFC 7009: a successful revoke returns 200 with an empty body.
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(status_err("revoke", resp).await)
        }
    }
}

/// Deserializes a JSON body on 2xx, otherwise builds an [`SeedError::Api`].
async fn json_or_err<T: serde::de::DeserializeOwned>(
    op: &'static str,
    resp: reqwest::Response,
) -> Result<T, SeedError> {
    if resp.status().is_success() {
        Ok(resp.json::<T>().await?)
    } else {
        Err(status_err(op, resp).await)
    }
}

/// Builds an [`SeedError::Api`] from a failed response, truncating the body.
async fn status_err(op: &'static str, resp: reqwest::Response) -> SeedError {
    let status = resp.status().as_u16();
    let mut body = resp.text().await.unwrap_or_default();
    body.truncate(500);
    SeedError::Api { op, status, body }
}

/// Constructs an [`SeedError::Api`] directly.
fn api_err(op: &'static str, status: u16, body: &str) -> SeedError {
    SeedError::Api {
        op,
        status,
        body: body.to_string(),
    }
}

use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use hearth::{cluster::router::MemRouter, ClusterNode};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use openraft::BasicNode;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{env, sync::Arc};
use tokio::sync::RwLock;

// ── Config ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    issuer: String,
    audience: Option<String>,
    jwks_cache: Arc<RwLock<Option<Vec<Jwk>>>>,
    http: HttpClient,
    /// Present when this process is a cluster node (absent in single-node mode).
    cluster: Option<Arc<ClusterNode>>,
}

// ── JWKS ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(rename = "n")]
    modulus: Option<String>,
    #[serde(rename = "e")]
    exponent: Option<String>,
    alg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    jwks_uri: String,
}

impl AppState {
    async fn get_jwks(&self) -> Result<Vec<Jwk>, StatusCode> {
        {
            let cache = self.jwks_cache.read().await;
            if let Some(keys) = cache.as_ref() {
                return Ok(keys.clone());
            }
        }

        let discovery_url = format!("{}/.well-known/openid-configuration", self.issuer.trim_end_matches('/'));
        let discovery: Discovery = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .json()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

        let jwks: JwksResponse = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .json()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

        let mut cache = self.jwks_cache.write().await;
        *cache = Some(jwks.keys.clone());
        Ok(jwks.keys)
    }

    async fn verify_token(&self, token: &str) -> Result<Claims, StatusCode> {
        let keys = self.get_jwks().await?;

        // Try each RSA key in the JWKS
        for key in &keys {
            if let (Some(n), Some(e)) = (&key.modulus, &key.exponent) {
                if let Ok(decoding_key) = DecodingKey::from_rsa_components(n, e) {
                    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
                    validation.set_issuer(&[&self.issuer]);
                    if let Some(aud) = &self.audience {
                        validation.set_audience(&[aud]);
                    } else {
                        validation.validate_aud = false;
                    }

                    if let Ok(data) = decode::<Claims>(token, &decoding_key, &validation) {
                        return Ok(data.claims);
                    }
                }
            }
        }

        // Cache may be stale due to key rotation — clear and try once more
        *self.jwks_cache.write().await = None;
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ── Claims extractor ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub exp: usize,
}

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.starts_with("Bearer "))
            .map(|v| &v[7..]);

        let token = auth_header.ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
        })?;

        state.verify_token(token).await.map_err(|status| {
            (status, Json(json!({"error": "invalid_token"}))).into_response()
        })
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn me(claims: Claims) -> Json<Value> {
    Json(json!({"sub": claims.sub, "email": claims.email, "roles": claims.roles}))
}

async fn admin(claims: Claims) -> Response {
    if !claims.roles.iter().any(|r| r == "admin") {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden", "required_role": "admin"}))).into_response();
    }
    Json(json!({"message": "Welcome, admin.", "sub": claims.sub})).into_response()
}

// ── Cluster membership admin endpoint ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MembershipRequest {
    action: String,
    node_id: u64,
    #[serde(default)]
    addr: String,
}

/// POST /admin/cluster/membership
///
/// Requires the `admin` role on the JWT.  Supported actions:
/// - `add_learner`  — add a non-voting replica (addr required)
/// - `add_voter`    — add as learner first, then promote to voter
/// - `remove_voter` — remove from voter set (quorum guard enforced)
async fn cluster_membership(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Json(req): Json<MembershipRequest>,
) -> Response {
    if !claims.roles.iter().any(|r| r == "admin") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "forbidden", "required_role": "admin"})),
        )
            .into_response();
    }

    let node = match &state.cluster {
        Some(n) => n.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "not_a_cluster_node"})),
            )
                .into_response();
        }
    };

    let result = match req.action.as_str() {
        "add_learner" => {
            node.add_learner(req.node_id, BasicNode { addr: req.addr.clone() })
                .await
        }
        "add_voter" => {
            node.add_learner(req.node_id, BasicNode { addr: req.addr.clone() })
                .await
                .and(node.add_voter(req.node_id).await)
        }
        "remove_voter" => node.remove_voter(req.node_id).await,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "unknown_action", "valid": ["add_learner", "add_voter", "remove_voter"]})),
            )
                .into_response();
        }
    };

    match result {
        Ok(view) => Json(json!({
            "action": req.action,
            "node_id": req.node_id,
            "membership": { "voters": view.voters }
        }))
        .into_response(),
        Err(e) => {
            let (status, code) = if e.to_string().contains("quorum") {
                (StatusCode::CONFLICT, "quorum_violation")
            } else {
                (StatusCode::BAD_GATEWAY, "raft_error")
            };
            (status, Json(json!({"error": code, "detail": e.to_string()}))).into_response()
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let issuer = env::var("HEARTH_ISSUER").unwrap_or_else(|_| "http://localhost:4000".to_string());
    let audience = env::var("HEARTH_AUDIENCE").ok();
    let port = env::var("PORT").unwrap_or_else(|_| "3004".to_string());

    // When HEARTH_NODE_ID is set, start in cluster mode.
    let cluster = if let Ok(id_str) = env::var("HEARTH_NODE_ID") {
        let node_id: u64 = id_str.parse().expect("HEARTH_NODE_ID must be a u64");
        let config = Arc::new(
            openraft::Config {
                election_timeout_min: 150,
                election_timeout_max: 450,
                heartbeat_interval: 75,
                ..Default::default()
            }
            .validate()
            .expect("invalid raft config"),
        );
        let router = MemRouter::new();
        let (node, rpc_tx) = ClusterNode::new(node_id, config, router.clone(), 500).await;
        router.add_node(node_id, rpc_tx);
        tracing::info!(node_id, "cluster mode: node started");
        Some(Arc::new(node))
    } else {
        None
    };

    let state = Arc::new(AppState {
        issuer,
        audience,
        jwks_cache: Arc::new(RwLock::new(None)),
        http: HttpClient::new(),
        cluster,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/me", get(me))
        .route("/api/admin", get(admin))
        .route("/admin/cluster/membership", post(cluster_membership))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    println!("Axum server listening on http://localhost:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

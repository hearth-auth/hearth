//! Application state shared across all request handlers.

use std::net::IpAddr;
use std::sync::Arc;

use crate::audit::AuditEngine;
use crate::cluster::ClusterEngine;
use crate::identity::IdentityEngine;
use crate::protocol::admin_auth::{
    AdminRateLimiter, ExportRateLimiter, JwksRateLimiter, TokenRateLimiter,
};
use crate::rbac::RbacEngine;
use crate::webhook::WebhookEngine;

pub struct AppState {
    /// The identity engine for all domain operations.
    pub identity: Arc<dyn IdentityEngine>,
    /// The RBAC engine for role / group / assignment management.
    pub rbac: Arc<dyn RbacEngine>,
    /// The audit engine for mutation logging.
    pub audit: Arc<dyn AuditEngine>,
    /// Webhook subscription and delivery engine (optional; absent in test
    /// harnesses that don't configure outbound delivery).
    pub webhook: Option<Arc<dyn WebhookEngine>>,
    /// Whether the server is running in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint for SDK integration
    /// tests and local development.
    pub dev_mode: bool,
    /// Whether the `/metrics` Prometheus scrape endpoint is enabled.
    ///
    /// Controlled by `metrics.enabled` in `hearth.yaml` (default: `true`).
    pub metrics_enabled: bool,
    /// Optional Bearer token required to access `/metrics` (A-26).
    ///
    /// When `Some`, the handler enforces `Authorization: Bearer <token>`
    /// using constant-time comparison. When `None` the endpoint is
    /// unauthenticated (operators should firewall or bind to loopback).
    pub metrics_bearer_token: Option<String>,
    /// Shared admin API rate limiter. Shared between the HTTP and gRPC
    /// admin surfaces so a caller cannot evade the limit by switching
    /// protocols.
    pub admin_rate_limiter: Arc<AdminRateLimiter>,
    /// Per-`(realm, client_id)` rate limiter for token, introspection, and
    /// device-authorization endpoints. Returns 429 with `Retry-After` when
    /// exceeded.
    pub token_rate_limiter: Arc<TokenRateLimiter>,
    /// Per-user rate limiter for backup/export endpoints (A-30).
    ///
    /// Limits each admin user to [`crate::protocol::admin_auth::EXPORT_RATE_LIMIT`]
    /// export operations per hour to limit blast radius of a compromised token.
    pub export_rate_limiter: Arc<ExportRateLimiter>,
    /// Ed25519 public key (32 raw bytes) used to verify detached signatures
    /// on restore archives (A-30). `None` when signature verification is disabled.
    ///
    /// When `Some`, the restore handler enforces that every uploaded archive
    /// carries a valid `detached_signature_b64` in its manifest. Fail-closed:
    /// archives without a valid signature are rejected.
    pub backup_verify_key_bytes: Option<[u8; 32]>,
    /// Grace period (seconds) during which a retiring signing key remains in
    /// JWKS after rotation. Sourced from `token.signing_key_rotation_grace_period`.
    pub signing_key_rotation_grace_period_secs: u64,
    /// Trusted reverse-proxy IPs for `X-Forwarded-For` extraction.
    ///
    /// When non-empty, the OWASP "rightmost non-trusted" algorithm is applied
    /// to derive the real client IP. When empty (default), the peer socket
    /// IP is used directly.
    pub trusted_proxies: Vec<IpAddr>,
    /// Cluster engine for Raft admin operations. `None` in single-node mode.
    ///
    /// When `None`, all `/admin/cluster/*` endpoints return `503 Service
    /// Unavailable` rather than panicking.
    pub cluster: Option<Arc<ClusterEngine>>,
    /// DPoP state (replay-cache + nonce secret). Lives in the identity layer
    /// and is shared across all request handlers via `Arc`.
    pub dpop: Arc<crate::identity::dpop::DPopProcessor>,
    /// Per-IP rate limiter for JWKS and OIDC discovery endpoints (A-10).
    ///
    /// Shared across all JWKS-family routes (`/jwks`, `/certs`,
    /// `/.well-known/jwks.json`, `/realms/{name}/.well-known/jwks.json`,
    /// `/realms/{name}/.well-known/openid-configuration`) so a caller
    /// cannot evade the limit by rotating between aliases.
    pub jwks_rate_limiter: Arc<JwksRateLimiter>,
    /// Whether Phase-A agent identity routes are active.
    ///
    /// Controlled by `agent_auth.capabilities.identity` in `hearth.yaml`.
    /// When `false`, all `/v1/agents` and `/.well-known/agent.json` routes
    /// are absent from the router (prevents fingerprinting).
    pub agent_identity_enabled: bool,
}

impl AppState {
    /// Creates a new `AppState` with all three engines.
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            webhook: None,
            dev_mode: false,
            metrics_enabled: true,
            metrics_bearer_token: None,
            admin_rate_limiter: Arc::new(AdminRateLimiter::new()),
            token_rate_limiter: Arc::new(TokenRateLimiter::new()),
            export_rate_limiter: Arc::new(ExportRateLimiter::new()),
            backup_verify_key_bytes: None,
            signing_key_rotation_grace_period_secs: 86_400,
            trusted_proxies: Vec::new(),
            cluster: None,
            // zero key is overridden in production via with_dpop_nonce_secret
            dpop: Arc::new(crate::identity::dpop::DPopProcessor::new([0u8; 32])),
            jwks_rate_limiter: Arc::new(JwksRateLimiter::new()),
            agent_identity_enabled: false,
        }
    }

    /// Creates a new `AppState` in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint.
    pub fn new_dev(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            webhook: None,
            dev_mode: true,
            metrics_enabled: true,
            metrics_bearer_token: None,
            admin_rate_limiter: Arc::new(AdminRateLimiter::new()),
            token_rate_limiter: Arc::new(TokenRateLimiter::new()),
            export_rate_limiter: Arc::new(ExportRateLimiter::new()),
            backup_verify_key_bytes: None,
            signing_key_rotation_grace_period_secs: 86_400,
            trusted_proxies: Vec::new(),
            cluster: None,
            dpop: Arc::new(crate::identity::dpop::DPopProcessor::new([0u8; 32])),
            // A-10 dev relaxation: production default (60 rps) would otherwise
            // cause flakes when test harnesses share 127.0.0.1 against a hot
            // limiter. Operators still get the production cap via `serve`'s
            // explicit `with_jwks_rate_limiter` call wired from
            // `config.security.jwks_rps_limit`.
            jwks_rate_limiter: Arc::new(JwksRateLimiter::with_rps_limit(u32::MAX)),
            agent_identity_enabled: false,
        }
    }

    /// Creates an `AppState` that shares an existing rate limiter.
    ///
    /// Used when wiring the gRPC server so its interceptor sees the same
    /// per-user counts as the HTTP handlers.
    pub fn with_shared_rate_limiter(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
        admin_rate_limiter: Arc<AdminRateLimiter>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            webhook: None,
            dev_mode: false,
            metrics_enabled: true,
            metrics_bearer_token: None,
            admin_rate_limiter,
            token_rate_limiter: Arc::new(TokenRateLimiter::new()),
            export_rate_limiter: Arc::new(ExportRateLimiter::new()),
            backup_verify_key_bytes: None,
            signing_key_rotation_grace_period_secs: 86_400,
            trusted_proxies: Vec::new(),
            cluster: None,
            dpop: Arc::new(crate::identity::dpop::DPopProcessor::new([0u8; 32])),
            jwks_rate_limiter: Arc::new(JwksRateLimiter::new()),
            agent_identity_enabled: false,
        }
    }

    /// Enables the Phase-A agent identity routes (`/v1/agents`, `/.well-known/agent.json`).
    ///
    /// Call this during server startup when `agent_auth.capabilities.identity = true`
    /// in the operator config.
    pub fn with_agent_identity(mut self, enabled: bool) -> Self {
        self.agent_identity_enabled = enabled;
        self
    }

    /// Configures trusted reverse-proxy IPs for `X-Forwarded-For` extraction.
    pub fn with_trusted_proxies(mut self, proxies: Vec<IpAddr>) -> Self {
        self.trusted_proxies = proxies;
        self
    }

    /// Attaches a webhook engine, enabling the webhook management endpoints.
    pub fn with_webhook(mut self, webhook: Arc<dyn WebhookEngine>) -> Self {
        self.webhook = Some(webhook);
        self
    }

    /// Sets the Ed25519 public key used to verify detached manifest signatures
    /// on restore archives (A-30).
    ///
    /// `key_bytes` must be 32 raw bytes (the uncompressed Ed25519 public key).
    /// When set, the restore handler enforces that every uploaded archive carries
    /// a valid signature. Pass `None` to disable signature verification.
    pub fn with_backup_verify_key(mut self, key_bytes: Option<[u8; 32]>) -> Self {
        self.backup_verify_key_bytes = key_bytes;
        self
    }

    /// Sets whether the `/metrics` Prometheus scrape endpoint is exposed.
    pub fn with_metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Sets the Bearer token required to access `/metrics` (A-26).
    ///
    /// When `Some`, every `/metrics` request must supply a matching
    /// `Authorization: Bearer <token>` header. Comparison is constant-time.
    pub fn with_metrics_bearer_token(mut self, token: Option<String>) -> Self {
        self.metrics_bearer_token = token;
        self
    }

    /// Sets the signing key rotation grace period.
    pub fn with_signing_key_rotation_grace_period_secs(mut self, secs: u64) -> Self {
        self.signing_key_rotation_grace_period_secs = secs;
        self
    }

    /// Attaches a cluster engine, enabling the `/admin/cluster/*` endpoints.
    pub fn with_cluster(mut self, engine: Arc<ClusterEngine>) -> Self {
        self.cluster = Some(engine);
        self
    }

    /// Sets the 32-byte HMAC secret used for stateless DPoP nonce generation.
    ///
    /// **Must be called before serving any requests.** The zero key `[0u8; 32]`
    /// is rejected at startup by an assertion in `main.rs`.
    pub fn with_dpop_nonce_secret(mut self, secret: [u8; 32]) -> Self {
        self.dpop = Arc::new(crate::identity::dpop::DPopProcessor::new(secret));
        self
    }

    /// Replaces the default JWKS rate limiter with a pre-configured instance (A-10).
    ///
    /// Call this during server startup to apply an operator-configured RPS limit
    /// (from `security.jwks_rps_limit` in `hearth.yaml`) instead of the 60 rps
    /// compiled-in default.
    pub fn with_jwks_rate_limiter(mut self, limiter: Arc<JwksRateLimiter>) -> Self {
        self.jwks_rate_limiter = limiter;
        self
    }
}

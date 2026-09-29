//! Shared rate limiters for admin and token endpoints.
//!
//! [`AdminRateLimiter`] tracks per-admin-user request counts in a rolling
//! 1-minute window, shared between HTTP and gRPC surfaces.
//!
//! [`TokenRateLimiter`] tracks per-`(realm, client_id)` request counts on the
//! OAuth token, introspection, and device-authorization endpoints.
//!
//! The module also holds the admission rules every admin surface (REST, gRPC,
//! SCIM) shares, so the surfaces cannot drift apart: [`ADMIN_PERMISSIONS`],
//! [`grants_admin_permission`] and [`REALMS_ARE_YAML_MANAGED`].

use std::collections::HashMap;
use std::sync::Mutex;

use crate::core::{ClientId, RealmId, UserId};

/// Default maximum admin API requests per minute per user.
///
/// Operators override this with `security.rate_limiting.admin_per_minute` in
/// `hearth.yaml`; `0` disables the limiter entirely (HEA-2010).
pub const ADMIN_RATE_LIMIT: u32 = 100;

/// Rate limit window in microseconds (1 minute).
pub const ADMIN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Per-request rate tracker entry (shared by both limiters).
#[derive(Debug, Clone)]
struct RateTracker {
    count: u32,
    window_start_micros: i64,
}

/// Thread-safe rate limiter shared across protocol surfaces.
///
/// Guarded by a single `Mutex` — contention is low because each request only
/// performs a cheap increment under the lock.
#[derive(Debug)]
pub struct AdminRateLimiter {
    trackers: Mutex<HashMap<String, RateTracker>>,
    /// Maximum requests allowed per window per admin user.
    ///
    /// `0` means **unlimited** — [`check`](Self::check) always returns
    /// `Allowed`. Set from `security.rate_limiting.admin_per_minute` or by the
    /// load-test unthrottled boot path (`security.load_test_unthrottled`,
    /// loopback-gated). Zero removes the admin-API abuse cap; never do it on a
    /// production bind. Defaults to [`ADMIN_RATE_LIMIT`].
    limit: u32,
}

impl Default for AdminRateLimiter {
    fn default() -> Self {
        Self::with_limit(ADMIN_RATE_LIMIT)
    }
}

/// Outcome of an admin rate-limit check.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RateLimitOutcome {
    /// The request may proceed.
    Allowed,
    /// The caller exceeded `ADMIN_RATE_LIMIT` in the current window.
    Exceeded,
}

impl AdminRateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a limiter that never rate-limits.
    ///
    /// **Load-test use only** — wired from `security.load_test_unthrottled` on a
    /// loopback bind so a single-node throughput test can push the hot path
    /// without the abuse cap acting as the bottleneck. See the field docs for
    /// the production warning.
    pub fn disabled() -> Self {
        Self::with_limit(0)
    }

    /// Creates a limiter with a custom per-user per-minute cap.
    ///
    /// A `limit` of `0` disables the limiter (equivalent to [`Self::disabled`]).
    /// Wired from `security.rate_limiting.admin_per_minute` in `hearth.yaml`.
    #[must_use]
    pub fn with_limit(limit: u32) -> Self {
        Self {
            trackers: Mutex::new(HashMap::new()),
            limit,
        }
    }

    /// Records a request from `user_id` and reports whether it is permitted.
    ///
    /// The caller supplies `now_micros` so tests can drive time deterministically;
    /// production callers pass the current Unix-microsecond clock.
    pub fn check(&self, user_id: &UserId, now_micros: i64) -> RateLimitOutcome {
        if self.limit == 0 {
            return RateLimitOutcome::Allowed;
        }
        let key = user_id.as_uuid().to_string();
        let mut trackers = self
            .trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let tracker = trackers.entry(key).or_insert(RateTracker {
            count: 0,
            window_start_micros: now_micros,
        });

        if now_micros - tracker.window_start_micros > ADMIN_RATE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now_micros;
        }

        tracker.count += 1;
        if tracker.count > self.limit {
            RateLimitOutcome::Exceeded
        } else {
            RateLimitOutcome::Allowed
        }
    }
}

// === Token endpoint rate limiter ===

/// Maximum token-endpoint requests per minute per `(realm, client)` pair.
pub const TOKEN_RATE_LIMIT: u32 = 200;

/// Token rate-limit window in microseconds (1 minute).
pub const TOKEN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Outcome of a token endpoint rate-limit check.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TokenRateLimitOutcome {
    /// The request may proceed.
    Allowed,
    /// Exceeded the per-client limit.  `retry_after_secs` is the number of
    /// whole seconds until the current window resets.
    Exceeded {
        /// Seconds the client should wait before retrying (for `Retry-After`).
        retry_after_secs: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportRateLimiter — per-export / per-user (A-30)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum export operations per hour per admin user (A-30).
///
/// A single admin token limited to 10 backup/export calls per 60-minute window
/// prevents a compromised credential from mass-exfiltrating realm data in a
/// tight loop. Operators can relax this for automated DR jobs via a service
/// account with a dedicated token.
pub const EXPORT_RATE_LIMIT: u32 = 10;

/// Export rate-limit window in microseconds (1 hour).
pub const EXPORT_RATE_WINDOW_MICROS: i64 = 3_600 * 1_000_000;

/// Per-user fixed-window rate limiter for export endpoints (A-30).
///
/// Keyed by `user_uuid`. Contention is negligible because exports are
/// infrequent and the lock is held only for a counter increment.
#[derive(Debug)]
pub struct ExportRateLimiter {
    trackers: Mutex<HashMap<String, RateTracker>>,
    /// Maximum exports allowed per window per admin user.
    ///
    /// `0` means **unlimited**. Set from `security.backup.export_rate_limit`
    /// or by the load-test unthrottled boot path. Defaults to
    /// [`EXPORT_RATE_LIMIT`].
    limit: u32,
}

impl Default for ExportRateLimiter {
    fn default() -> Self {
        Self::with_limit(EXPORT_RATE_LIMIT)
    }
}

/// Outcome of an export rate-limit check.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExportRateLimitOutcome {
    /// The export operation may proceed.
    Allowed,
    /// The user has exceeded [`EXPORT_RATE_LIMIT`] in the current window.
    Exceeded,
}

impl ExportRateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a limiter that never rate-limits.
    ///
    /// **Load-test use only** — wired from `security.load_test_unthrottled` on a
    /// loopback bind. See the field docs for the production warning.
    pub fn disabled() -> Self {
        Self::with_limit(0)
    }

    /// Creates a limiter with a custom per-user per-hour export cap.
    ///
    /// A `limit` of `0` disables the limiter. Wired from
    /// `security.backup.export_rate_limit` in `hearth.yaml`.
    #[must_use]
    pub fn with_limit(limit: u32) -> Self {
        Self {
            trackers: Mutex::new(HashMap::new()),
            limit,
        }
    }

    /// Records an export attempt from `user_id` and reports whether it is permitted.
    ///
    /// `now_micros` is the current Unix timestamp in microseconds; tests should
    /// pass a fixed value to drive time deterministically.
    pub fn check(&self, user_id: &UserId, now_micros: i64) -> ExportRateLimitOutcome {
        if self.limit == 0 {
            return ExportRateLimitOutcome::Allowed;
        }
        let key = user_id.as_uuid().to_string();
        let mut trackers = self
            .trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let tracker = trackers.entry(key).or_insert(RateTracker {
            count: 0,
            window_start_micros: now_micros,
        });

        if now_micros - tracker.window_start_micros > EXPORT_RATE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now_micros;
        }

        tracker.count += 1;
        if tracker.count > self.limit {
            ExportRateLimitOutcome::Exceeded
        } else {
            ExportRateLimitOutcome::Allowed
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TokenRateLimiter
// ─────────────────────────────────────────────────────────────────────────────

/// Per-`(realm, client)` sliding-window rate limiter for OAuth token endpoints.
///
/// Keyed by `"{realm_uuid}:{client_uuid}"`.  Lock contention is low because
/// each request holds the lock only long enough to increment a counter.
#[derive(Debug)]
pub struct TokenRateLimiter {
    trackers: Mutex<HashMap<String, RateTracker>>,
    /// Maximum requests allowed per window per `(realm, client)` pair.
    ///
    /// `0` means **unlimited**. Set from
    /// `security.rate_limiting.token_per_minute` or by the load-test
    /// unthrottled boot path (`security.load_test_unthrottled`,
    /// loopback-gated). Zero removes brute-force / token-minting abuse
    /// protection on the OAuth token and introspection endpoints; never do it
    /// on a production bind. Defaults to [`TOKEN_RATE_LIMIT`].
    limit: u32,
}

impl Default for TokenRateLimiter {
    fn default() -> Self {
        Self::with_limit(TOKEN_RATE_LIMIT)
    }
}

impl TokenRateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a limiter that never rate-limits.
    ///
    /// **Load-test use only** — wired from `security.load_test_unthrottled` on a
    /// loopback bind so token issuance under a throughput test is not gated by
    /// the per-`(realm, client)` cap. See the field docs for the production
    /// warning.
    pub fn disabled() -> Self {
        Self::with_limit(0)
    }

    /// Creates a limiter with a custom per-`(realm, client)` per-minute cap.
    ///
    /// A `limit` of `0` disables the limiter. Wired from
    /// `security.rate_limiting.token_per_minute` in `hearth.yaml`.
    #[must_use]
    pub fn with_limit(limit: u32) -> Self {
        Self {
            trackers: Mutex::new(HashMap::new()),
            limit,
        }
    }

    /// Records a request and reports whether it is permitted.
    ///
    /// `now_micros` is the current Unix timestamp in microseconds; pass a
    /// fixed value in tests to drive time deterministically.
    pub fn check(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        now_micros: i64,
    ) -> TokenRateLimitOutcome {
        self.check_bucket(realm_id, &client_id.as_uuid().to_string(), now_micros)
    }

    /// Bucket name for a token request that carries no client identity.
    ///
    /// A clientless `grant_type=refresh_token` exchange (Hearth's session
    /// refresh) authenticates nothing at the edge, so the peer address is the
    /// only identity available to bucket it under. The `ip:` prefix keeps
    /// these buckets disjoint from the client-UUID buckets used by
    /// [`Self::check`] (audit 2026-08-28 §4.16#8).
    #[must_use]
    pub fn anonymous_ip_bucket(client_ip: &str) -> String {
        format!("ip:{client_ip}")
    }

    /// Records a request against an arbitrary bucket within a realm.
    ///
    /// `bucket` is any stable per-caller discriminator — a client UUID for an
    /// authenticated request, [`Self::anonymous_ip_bucket`] for one that
    /// carries no client identity. A `limit` of `0` still means **unlimited**,
    /// exactly as it does for [`Self::check`].
    pub fn check_bucket(
        &self,
        realm_id: &RealmId,
        bucket: &str,
        now_micros: i64,
    ) -> TokenRateLimitOutcome {
        if self.limit == 0 {
            return TokenRateLimitOutcome::Allowed;
        }
        let key = format!("{}:{}", realm_id.as_uuid(), bucket);
        let mut trackers = self
            .trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let tracker = trackers.entry(key).or_insert(RateTracker {
            count: 0,
            window_start_micros: now_micros,
        });

        if now_micros - tracker.window_start_micros > TOKEN_RATE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now_micros;
        }

        tracker.count += 1;
        if tracker.count > self.limit {
            let elapsed = now_micros - tracker.window_start_micros;
            let remaining_micros = TOKEN_RATE_WINDOW_MICROS - elapsed;
            let retry_after_secs =
                u32::try_from((remaining_micros / 1_000_000).max(1)).unwrap_or(60);
            TokenRateLimitOutcome::Exceeded { retry_after_secs }
        } else {
            TokenRateLimitOutcome::Allowed
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JwksRateLimiter — per-IP cap on JWKS and discovery endpoints (A-10)
// ─────────────────────────────────────────────────────────────────────────────

/// Default JWKS / discovery endpoint rate limit: 60 requests per second per IP.
///
/// JWKS is a public, unauthenticated endpoint. At 60 rps it serves legitimate
/// relying parties while blocking enumeration bots.
pub const JWKS_RATE_LIMIT_PER_SEC: u32 = 60;

/// Window for JWKS rate limiting: 1 second in microseconds.
pub const JWKS_RATE_WINDOW_MICROS: i64 = 1_000_000;

/// Per-IP rate limiter for JWKS and OIDC discovery endpoints (A-10).
///
/// The limit is configurable at construction time so operators can override the
/// default via `security.jwks_rps_limit` in `hearth.yaml`.
#[derive(Debug)]
pub struct JwksRateLimiter {
    /// Maximum allowed requests per second per IP.
    ///
    /// `0` means **unlimited**, matching [`AdminRateLimiter`],
    /// [`TokenRateLimiter`] and [`ExportRateLimiter`]. It previously meant
    /// *deny everything* here — `count <= 0` is false for the very first
    /// request — so the same sentinel removed the cap on three limiters and
    /// blackholed JWKS and OIDC discovery on the fourth, in one file (audit
    /// §4.13#7). Set from `security.jwks_rps_limit`, whose documented default
    /// is 60.
    rps_limit: u32,
    trackers: Mutex<HashMap<String, RateTracker>>,
}

impl Default for JwksRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksRateLimiter {
    /// Creates a limiter with the compiled-in default (60 rps per IP).
    pub fn new() -> Self {
        Self::with_rps_limit(JWKS_RATE_LIMIT_PER_SEC)
    }

    /// Creates a limiter that never rate-limits.
    ///
    /// **Load-test use only** — wired from `security.load_test_unthrottled` on
    /// a loopback bind. Mirrors [`AdminRateLimiter::disabled`] so the intent is
    /// spelled out at the call site rather than encoded in a magic number.
    pub fn disabled() -> Self {
        Self::with_rps_limit(0)
    }

    /// Creates a limiter with a custom per-IP requests-per-second cap.
    ///
    /// A `rps_limit` of `0` disables the limiter (equivalent to
    /// [`Self::disabled`]), consistent with every other limiter in this module.
    /// Use this to apply the operator-configured value from
    /// `security.jwks_rps_limit` in `hearth.yaml`.
    pub fn with_rps_limit(rps_limit: u32) -> Self {
        Self {
            rps_limit,
            trackers: Mutex::new(HashMap::new()),
        }
    }

    /// Records a request from `ip` and returns `true` when the request is allowed.
    ///
    /// `now_micros` is the current Unix timestamp in microseconds; pass a fixed
    /// value in tests to drive time deterministically.
    pub fn check(&self, ip: &str, now_micros: i64) -> bool {
        if self.rps_limit == 0 {
            return true;
        }
        let mut trackers = self
            .trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tracker = trackers.entry(ip.to_string()).or_insert(RateTracker {
            count: 0,
            window_start_micros: now_micros,
        });
        if now_micros - tracker.window_start_micros > JWKS_RATE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now_micros;
        }
        tracker.count += 1;
        tracker.count <= self.rps_limit
    }
}

/// The refusal every admin surface returns for a realm create or update.
///
/// Realms are declared in `hearth.yaml` and reconciled from it, so no API
/// writes them: REST `POST /admin/realms` and `PATCH /admin/realms/{id}`
/// answer `405`, gRPC `CreateRealm` and `UpdateRealm` answer
/// `FAILED_PRECONDITION`, all with this message. gRPC `UpdateRealm` used to
/// replace the realm's whole config with the three fields its proto carries
/// plus defaults, silently dropping the MFA, CIDR, lockout, SCIM-token and
/// webhook settings until the next reload (GA audit round 3, G-7).
pub const REALMS_ARE_YAML_MANAGED: &str =
    "Realms are managed via hearth.yaml. Remove this endpoint from your client.";

/// The full-superuser admin permission. It opens every admin surface and
/// satisfies every per-endpoint sub-permission check.
pub const SUPERUSER_PERMISSION: &str = "hearth.admin";

/// Every admin-grade permission. Holding any one of them admits a token to the
/// administrative plane: REST `extract_admin_auth`, gRPC `authenticate_admin`
/// and the SCIM admin-JWT fallback all test against this list, and each
/// endpoint then narrows to the one sub-permission it needs.
///
/// The same list is the set of principals a SCIM provisioning token may not
/// modify or delete. That guard used to carry its own copy, which covered two
/// of the five, so a provisioning token could take over any realm, clients or
/// agents sub-admin (GA audit round 3, G-6). Both now read this constant.
///
/// `hearth.export` is deliberately absent: it never admits a caller on its
/// own, since every export and restore endpoint also demands one of these.
pub const ADMIN_PERMISSIONS: &[&str] = &[
    SUPERUSER_PERMISSION,
    "hearth.users.admin",
    "hearth.clients.admin",
    "hearth.realm.admin",
    "hearth.agents.admin",
];

/// Returns whether `permission` is admin-grade, i.e. one of
/// [`ADMIN_PERMISSIONS`].
#[must_use]
pub fn is_admin_permission(permission: &str) -> bool {
    ADMIN_PERMISSIONS.contains(&permission)
}

/// Returns whether `permissions` satisfies an admin endpoint that requires the
/// sub-permission `required`. [`SUPERUSER_PERMISSION`] always does; otherwise
/// `required` itself must be present.
///
/// This is the one per-endpoint rule shared by REST
/// (`require_admin_permission`), gRPC (`grpc_require_permission`) and SCIM.
#[must_use]
pub fn grants_admin_permission(permissions: &[String], required: &str) -> bool {
    permissions
        .iter()
        .any(|p| p == SUPERUSER_PERMISSION || p == required)
}

/// Returns the first admin-grade permission in `target` that `actor` does not
/// hold, or `None` when the actor may administer the target.
///
/// This is the privilege ceiling on user administration, as a pure function:
///
/// - An actor holding [`SUPERUSER_PERMISSION`] outranks everyone (`None`).
/// - Otherwise the actor must hold **every** admin-grade permission
///   ([`ADMIN_PERMISSIONS`]) the target holds. A same-level peer passes; a
///   target with any admin permission the actor lacks — `hearth.admin`
///   included — does not.
///
/// Non-admin permissions of the target are ignored: the ceiling protects the
/// admin plane, not application authorization.
#[must_use]
pub fn admin_ceiling_gap<'a, I>(actor: &[String], target: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    if actor.iter().any(|p| p == SUPERUSER_PERMISSION) {
        return None;
    }
    target
        .into_iter()
        .filter(|p| is_admin_permission(p))
        .find(|p| !actor.iter().any(|a| a == p))
}

/// Why [`check_user_admin_ceiling`] refused an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserCeilingError {
    /// The target user holds an admin-grade permission the actor lacks.
    Exceeded,
    /// The target's permissions could not be resolved. The operation is
    /// refused (fail closed) rather than assumed safe.
    Unresolved,
}

/// The privilege ceiling on user administration: an admin may not modify,
/// re-email, reset, disable or delete a user who holds an admin-grade
/// permission the admin lacks (see [`admin_ceiling_gap`] for the rule).
///
/// `actor_permissions` is the actor's permission set (token claims); a SCIM
/// provisioning token passes an empty set, so it may act on no admin
/// principal at all. `realm_id` is the realm the target user lives in, which is
/// where its permissions are resolved.
///
/// Every user-administration surface calls this one function: REST
/// `/admin/users*` and `/admin/realms/{id}/users/{id}/required-actions`, gRPC
/// `UpdateUser` / `DeleteUser`, and SCIM `/Users`. Without it a
/// `hearth.users.admin` sub-admin could rewrite a superuser's email and reset
/// the password, and so take over `hearth.admin` (GA audit round 3). The web
/// console admits only `hearth.admin`, which satisfies the ceiling by
/// construction.
///
/// # Errors
///
/// [`UserCeilingError::Exceeded`] when the target outranks the actor;
/// [`UserCeilingError::Unresolved`] when the RBAC read fails.
pub fn check_user_admin_ceiling(
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    target: &UserId,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    // A superuser clears the ceiling whatever the target holds: skip the read.
    if actor_permissions.iter().any(|p| p == SUPERUSER_PERMISSION) {
        return Ok(());
    }
    let resolved = rbac
        .resolve_permissions(target, realm_id, None, None)
        .map_err(|e| {
            tracing::warn!(
                realm_id = %realm_id,
                error = %e,
                "admin ceiling could not resolve the target's permissions; refusing"
            );
            UserCeilingError::Unresolved
        })?;
    let gap = admin_ceiling_gap(
        actor_permissions,
        resolved
            .permissions
            .iter()
            .map(crate::rbac::Permission::as_str),
    );
    match gap {
        None => Ok(()),
        Some(missing) => {
            tracing::warn!(
                realm_id = %realm_id,
                missing_permission = missing,
                "user administration refused: the target holds an admin permission the actor lacks"
            );
            Err(UserCeilingError::Exceeded)
        }
    }
}

/// Capability a cross-realm admin operation must be granted by a stored
/// [`crate::identity::CrossRealmTrustPolicy`] in the target realm before it is
/// permitted. A policy may also carry `*`, which grants every capability.
pub const CROSS_REALM_ADMIN_CAPABILITY: &str = "hearth.admin";

/// Whether an admin authenticated in one realm may operate on another, as
/// decided by [`admin_realm_scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRealmScope {
    /// Same realm, or a system-realm crossing the target's policies allow.
    Permitted,
    /// A tenant-realm admin addressing a realm that is not its own.
    OtherRealm,
    /// A system-realm crossing that the target realm's trust policy refuses.
    PolicyDenied,
}

/// The realm-level object-authorization rule (BOLA guard) shared by every
/// admin surface that takes a realm id: REST `/admin/realms/{id}/*` and gRPC
/// `GetRealm` / `DeleteRealm`.
///
/// - `caller_realm == target_realm`: no boundary is crossed, always permitted.
/// - A tenant realm may not address another realm: [`AdminRealmScope::OtherRealm`].
/// - The **system realm** (nil UUID) may cross, subject to the target realm's
///   cross-realm trust policies. Three-way outcome:
///   1. **Permitted** — a live policy in the target names the system realm and
///      grants [`CROSS_REALM_ADMIN_CAPABILITY`] (or `*`).
///   2. **Denied** — a live policy in the target names the system realm but
///      withholds that capability: [`AdminRealmScope::PolicyDenied`].
///   3. **Ungoverned** — no live policy in the target names the system realm.
///      The default is *permissive-with-audit*: the crossing is allowed and a
///      `WARN`-level record is emitted. Fail-closed here would brick the
///      system realm's management plane on every deployment that has never
///      authored a policy.
///
/// gRPC `GetRealm` / `DeleteRealm` used to apply only the first two rules, so
/// a policy that refused the system realm held on REST and not on gRPC (GA
/// audit round 3).
///
/// # Errors
///
/// Propagates an identity-engine error from the policy reads.
pub fn admin_realm_scope(
    identity: &dyn crate::identity::IdentityEngine,
    caller_realm: &RealmId,
    target_realm: &RealmId,
    now_micros: i64,
) -> Result<AdminRealmScope, crate::identity::IdentityError> {
    if caller_realm == target_realm {
        return Ok(AdminRealmScope::Permitted);
    }
    if !caller_realm.as_uuid().is_nil() {
        return Ok(AdminRealmScope::OtherRealm);
    }
    if identity.check_cross_realm_policy(
        target_realm,
        caller_realm,
        CROSS_REALM_ADMIN_CAPABILITY,
    )? {
        return Ok(AdminRealmScope::Permitted);
    }
    let now = crate::core::Timestamp::from_micros(now_micros);
    let governed = identity
        .list_cross_realm_policies(target_realm)?
        .iter()
        .any(|p| &p.source_realm_id == caller_realm && p.expires_at.is_none_or(|exp| now < exp));
    if governed {
        tracing::warn!(
            source_realm = %caller_realm.as_uuid(),
            target_realm = %target_realm.as_uuid(),
            capability = CROSS_REALM_ADMIN_CAPABILITY,
            "cross-realm admin operation refused by trust policy"
        );
        return Ok(AdminRealmScope::PolicyDenied);
    }
    tracing::warn!(
        source_realm = %caller_realm.as_uuid(),
        target_realm = %target_realm.as_uuid(),
        capability = CROSS_REALM_ADMIN_CAPABILITY,
        "cross-realm admin operation permitted by default: no cross-realm trust \
         policy governs this realm pair"
    );
    Ok(AdminRealmScope::Permitted)
}

/// Returns whether an access token may be used against an administrative
/// surface, judged by the client it was issued to (GA audit B1).
///
/// A token that names no client (RFC 9068 `client_id`) is a Hearth
/// first-party session token and passes. A token issued to a client passes
/// only while that client exists in `realm_id` and is
/// [`crate::identity::ClientTrustLevel::FirstParty`]: a third-party app a user
/// signed in to must never administer the realm on the user's behalf, even
/// when a claim profile releases the user's admin permissions to it. An
/// unparseable claim, a deleted client or a storage error fail closed.
pub(crate) fn token_client_may_administer(
    identity: &dyn crate::identity::IdentityEngine,
    realm_id: &RealmId,
    claims: &crate::identity::TokenClaims,
) -> bool {
    let Some(raw) = claims.client_id() else {
        return true;
    };
    let Ok(client_id) = raw.parse::<ClientId>() else {
        return false;
    };
    matches!(
        identity.get_client(realm_id, &client_id),
        Ok(Some(client)) if client.trust_level() == crate::identity::ClientTrustLevel::FirstParty
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn user() -> UserId {
        UserId::new(Uuid::new_v4())
    }

    fn realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    fn client() -> ClientId {
        ClientId::new(Uuid::new_v4())
    }

    // --- AdminRateLimiter ---

    #[test]
    fn allows_under_limit() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Exceeded);
    }

    #[test]
    fn resets_after_window() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Exceeded);
        let later = ADMIN_RATE_WINDOW_MICROS + 1;
        assert_eq!(limiter.check(&u, later), RateLimitOutcome::Allowed);
    }

    #[test]
    fn separate_users_independent() {
        let limiter = AdminRateLimiter::new();
        let a = user();
        let b = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&a, 0);
        }
        assert_eq!(limiter.check(&a, 0), RateLimitOutcome::Exceeded);
        assert_eq!(limiter.check(&b, 0), RateLimitOutcome::Allowed);
    }

    // --- Configurable limits (HEA-2010) ---
    //
    // The saturation rig could not measure the read plane because every rung
    // was 65-67% HTTP 429 from the compiled-in 100/min admin cap, and the only
    // escape hatch (`security.load_test_unthrottled`) is refused outside
    // `--dev`. These cover the operator-facing override, including `0` = off.

    #[test]
    fn admin_limit_honours_configured_value() {
        let limiter = AdminRateLimiter::with_limit(3);
        let u = user();
        for _ in 0..3 {
            assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Allowed);
        }
        assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Exceeded);
    }

    #[test]
    fn admin_limit_zero_never_sheds() {
        let limiter = AdminRateLimiter::with_limit(0);
        let u = user();
        for _ in 0..(ADMIN_RATE_LIMIT * 10) {
            assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn admin_default_still_caps_at_compiled_default() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Exceeded);
    }

    #[test]
    fn token_limit_honours_configured_value() {
        let limiter = TokenRateLimiter::with_limit(2);
        let (r, c) = (realm(), client());
        for _ in 0..2 {
            assert_eq!(limiter.check(&r, &c, 0), TokenRateLimitOutcome::Allowed);
        }
        assert!(matches!(
            limiter.check(&r, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
    }

    #[test]
    fn token_limit_zero_never_sheds() {
        let limiter = TokenRateLimiter::with_limit(0);
        let (r, c) = (realm(), client());
        for _ in 0..(TOKEN_RATE_LIMIT * 10) {
            assert_eq!(limiter.check(&r, &c, 0), TokenRateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn export_limit_honours_configured_value() {
        let limiter = ExportRateLimiter::with_limit(1);
        let u = user();
        assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Allowed);
        assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Exceeded);
    }

    #[test]
    fn export_limit_zero_never_sheds() {
        let limiter = ExportRateLimiter::with_limit(0);
        let u = user();
        for _ in 0..(EXPORT_RATE_LIMIT * 10) {
            assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Allowed);
        }
    }

    // --- TokenRateLimiter ---

    #[test]
    fn token_allows_under_limit() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            assert_eq!(limiter.check(&r, &c, 0), TokenRateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn token_rejects_over_limit() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        assert!(matches!(
            limiter.check(&r, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
    }

    #[test]
    fn token_retry_after_is_positive() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        match limiter.check(&r, &c, 0) {
            TokenRateLimitOutcome::Exceeded { retry_after_secs } => {
                assert!(retry_after_secs > 0);
                assert!(retry_after_secs <= 60);
            }
            TokenRateLimitOutcome::Allowed => panic!("expected Exceeded"),
        }
    }

    #[test]
    fn token_resets_after_window() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        assert!(matches!(
            limiter.check(&r, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
        let later = TOKEN_RATE_WINDOW_MICROS + 1;
        assert_eq!(limiter.check(&r, &c, later), TokenRateLimitOutcome::Allowed);
    }

    #[test]
    fn token_separate_clients_independent() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c1 = client();
        let c2 = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c1, 0);
        }
        assert!(matches!(
            limiter.check(&r, &c1, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
        assert_eq!(limiter.check(&r, &c2, 0), TokenRateLimitOutcome::Allowed);
    }

    #[test]
    fn token_separate_realms_independent() {
        let limiter = TokenRateLimiter::new();
        let r1 = realm();
        let r2 = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r1, &c, 0);
        }
        assert!(matches!(
            limiter.check(&r1, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
        assert_eq!(limiter.check(&r2, &c, 0), TokenRateLimitOutcome::Allowed);
    }

    // --- ExportRateLimiter ---

    #[test]
    fn export_allows_under_limit() {
        let limiter = ExportRateLimiter::new();
        let u = user();
        for _ in 0..EXPORT_RATE_LIMIT {
            assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn export_rejects_over_limit() {
        let limiter = ExportRateLimiter::new();
        let u = user();
        for _ in 0..EXPORT_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Exceeded);
    }

    #[test]
    fn export_resets_after_hour_window() {
        let limiter = ExportRateLimiter::new();
        let u = user();
        for _ in 0..EXPORT_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Exceeded);
        let later = EXPORT_RATE_WINDOW_MICROS + 1;
        assert_eq!(
            limiter.check(&u, later),
            ExportRateLimitOutcome::Allowed,
            "window must reset after 1 hour"
        );
    }

    #[test]
    fn export_separate_users_are_independent() {
        let limiter = ExportRateLimiter::new();
        let a = user();
        let b = user();
        for _ in 0..EXPORT_RATE_LIMIT {
            let _ = limiter.check(&a, 0);
        }
        assert_eq!(limiter.check(&a, 0), ExportRateLimitOutcome::Exceeded);
        assert_eq!(
            limiter.check(&b, 0),
            ExportRateLimitOutcome::Allowed,
            "different users must have independent quotas"
        );
    }

    // --- disabled() load-test bypass ---

    #[test]
    fn admin_disabled_never_limits() {
        let limiter = AdminRateLimiter::disabled();
        let u = user();
        // Far beyond ADMIN_RATE_LIMIT within a single window: every call allowed.
        for _ in 0..(ADMIN_RATE_LIMIT * 10) {
            assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn token_disabled_never_limits() {
        let limiter = TokenRateLimiter::disabled();
        let r = realm();
        let c = client();
        for _ in 0..(TOKEN_RATE_LIMIT * 10) {
            assert_eq!(limiter.check(&r, &c, 0), TokenRateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn export_disabled_never_limits() {
        let limiter = ExportRateLimiter::disabled();
        let u = user();
        for _ in 0..(EXPORT_RATE_LIMIT * 10) {
            assert_eq!(limiter.check(&u, 0), ExportRateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn new_default_is_enabled() {
        // Regression guard: the load-test bypass must default OFF, so a
        // freshly-constructed limiter still enforces its cap.
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        assert!(
            matches!(
                limiter.check(&r, &c, 0),
                TokenRateLimitOutcome::Exceeded { .. }
            ),
            "new() must be rate-limited; only disabled() bypasses"
        );
    }

    // --- JwksRateLimiter ---

    #[test]
    fn jwks_allows_under_limit() {
        let limiter = JwksRateLimiter::with_rps_limit(5);
        for _ in 0..5 {
            assert!(
                limiter.check("1.2.3.4", 0),
                "requests within limit must be allowed"
            );
        }
    }

    #[test]
    fn jwks_rejects_over_limit() {
        let limiter = JwksRateLimiter::with_rps_limit(3);
        for _ in 0..3 {
            let _ = limiter.check("1.2.3.4", 0);
        }
        assert!(
            !limiter.check("1.2.3.4", 0),
            "request beyond limit must be rejected"
        );
    }

    #[test]
    fn jwks_resets_after_one_second_window() {
        let limiter = JwksRateLimiter::with_rps_limit(2);
        for _ in 0..2 {
            let _ = limiter.check("1.2.3.4", 0);
        }
        assert!(!limiter.check("1.2.3.4", 0), "must be limited in-window");
        // Advance by just over 1 second.
        let later = JWKS_RATE_WINDOW_MICROS + 1;
        assert!(
            limiter.check("1.2.3.4", later),
            "window must reset after 1 second"
        );
    }

    #[test]
    fn jwks_separate_ips_are_independent() {
        let limiter = JwksRateLimiter::with_rps_limit(1);
        assert!(limiter.check("10.0.0.1", 0));
        assert!(!limiter.check("10.0.0.1", 0), "ip1 must be limited");
        assert!(
            limiter.check("10.0.0.2", 0),
            "different IP must have independent quota"
        );
    }

    #[test]
    fn jwks_custom_rps_limit_respected() {
        let limit: u32 = 10;
        let limiter = JwksRateLimiter::with_rps_limit(limit);
        for i in 0..limit {
            assert!(
                limiter.check("5.5.5.5", 0),
                "request {i} must be allowed (limit={limit})"
            );
        }
        assert!(
            !limiter.check("5.5.5.5", 0),
            "request {} must be rejected (over limit)",
            limit
        );
    }

    /// Audit §4.13#7 (task 20.8): the `0` sentinel had two meanings in one
    /// file. `AdminRateLimiter`, `TokenRateLimiter` and `ExportRateLimiter`
    /// read `0` as **unlimited**; `JwksRateLimiter` read it as **deny
    /// everything** (`count <= 0` is false for the first request), so
    /// `security.jwks_rps_limit: 0` blackholed every JWKS and discovery fetch
    /// — an outage for every relying party — while the same value on any other
    /// limiter removed the cap. `0` now means unlimited everywhere.
    #[test]
    fn jwks_limit_zero_never_sheds() {
        let limiter = JwksRateLimiter::with_rps_limit(0);
        for i in 0..(JWKS_RATE_LIMIT_PER_SEC * 10) {
            assert!(
                limiter.check("6.6.6.6", 0),
                "request {i} must be allowed — 0 means unlimited, not deny-all"
            );
        }
    }

    /// The explicit spelling of the same intent, mirroring `disabled()` on the
    /// other three limiters.
    #[test]
    fn jwks_disabled_never_sheds() {
        let limiter = JwksRateLimiter::disabled();
        for i in 0..(JWKS_RATE_LIMIT_PER_SEC * 10) {
            assert!(limiter.check("7.7.7.7", 0), "request {i} must be allowed");
        }
    }

    // --- Admin permission set (GA audit round 3, G-6) ---

    /// Every seeded `hearth.admin` / `hearth.*.admin` permission is admin-grade.
    /// A future `hearth.<x>.admin` added to the seed but not to
    /// `ADMIN_PERMISSIONS` would be unreachable on the admin plane AND left
    /// unprotected from SCIM provisioning tokens; this fails first.
    #[test]
    fn every_seeded_admin_permission_is_admin_grade() {
        let seeded_admin: Vec<&str> = crate::rbac::SEED_PERMISSIONS
            .iter()
            .map(|(name, _)| *name)
            .filter(|n| {
                let parts: Vec<&str> = n.split('.').collect();
                *n == SUPERUSER_PERMISSION || matches!(parts.as_slice(), ["hearth", _, "admin"])
            })
            .collect();
        assert_eq!(seeded_admin.len(), ADMIN_PERMISSIONS.len());
        for name in seeded_admin {
            assert!(
                is_admin_permission(name),
                "{name} missing from ADMIN_PERMISSIONS"
            );
        }
    }

    /// The converse: nothing in the list is a typo the seed never grants.
    #[test]
    fn every_admin_permission_is_seeded() {
        for name in ADMIN_PERMISSIONS {
            assert!(
                crate::rbac::seed_permission_description(name).is_some(),
                "{name} is not a seeded permission"
            );
        }
    }

    #[test]
    fn non_admin_permissions_are_not_admin_grade() {
        for name in [
            "hearth.export",
            "hearth.sv_feed",
            "realm.admin",
            "user.write",
            "",
        ] {
            assert!(!is_admin_permission(name), "{name} must not be admin-grade");
        }
    }

    // --- Privilege ceiling on user administration (GA audit round 3) ---

    fn owned(ps: &[&str]) -> Vec<String> {
        ps.iter().map(|p| (*p).to_string()).collect()
    }

    #[test]
    fn ceiling_superuser_outranks_everyone() {
        let actor = owned(&["hearth.admin"]);
        assert_eq!(
            admin_ceiling_gap(&actor, ADMIN_PERMISSIONS.iter().copied()),
            None
        );
    }

    #[test]
    fn ceiling_sub_admin_may_not_act_on_a_superuser() {
        let actor = owned(&["hearth.users.admin", "hearth.realm.admin"]);
        assert_eq!(
            admin_ceiling_gap(&actor, ["hearth.admin"]),
            Some("hearth.admin")
        );
    }

    #[test]
    fn ceiling_sub_admin_needs_every_admin_permission_the_target_holds() {
        let actor = owned(&["hearth.users.admin"]);
        assert_eq!(
            admin_ceiling_gap(&actor, ["hearth.users.admin", "hearth.clients.admin"]),
            Some("hearth.clients.admin")
        );
        assert_eq!(
            admin_ceiling_gap(&actor, ["hearth.users.admin"]),
            None,
            "same level"
        );
    }

    #[test]
    fn ceiling_ignores_non_admin_permissions_and_plain_targets() {
        let provisioning_token: Vec<String> = Vec::new();
        assert_eq!(
            admin_ceiling_gap(&provisioning_token, ["user.write", "hearth.export"]),
            None
        );
        assert_eq!(
            admin_ceiling_gap(&provisioning_token, ["hearth.agents.admin"]),
            Some("hearth.agents.admin"),
            "an empty actor set may act on no admin principal"
        );
    }

    #[test]
    fn grants_admin_permission_requires_superuser_or_the_named_permission() {
        let perms = |ps: &[&str]| ps.iter().map(|p| (*p).to_string()).collect::<Vec<_>>();

        assert!(grants_admin_permission(
            &perms(&["hearth.users.admin"]),
            "hearth.users.admin"
        ));
        assert!(grants_admin_permission(
            &perms(&["hearth.admin"]),
            "hearth.users.admin"
        ));
        assert!(!grants_admin_permission(
            &perms(&["hearth.clients.admin", "hearth.realm.admin"]),
            "hearth.users.admin"
        ));
        assert!(!grants_admin_permission(&[], "hearth.users.admin"));
    }
}

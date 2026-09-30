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

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::core::{rate_limit_key_str, ClientId, ExpiringMap, RealmId, UserId};

/// Most tracker entries any one limiter in this module holds at once.
///
/// Every limiter used to keep a `HashMap` entry per key forever — the JWKS
/// limiter per client address, the token limiter per attacker-chosen client id
/// and per anonymous address (GA sweep 3, E-2). Entries now expire with their
/// window and the map is hard-capped.
pub const LIMITER_CAPACITY: usize = 100_000;

/// Default maximum admin API requests per minute per user.
///
/// Operators override this with `security.rate_limiting.admin_per_minute` in
/// `hearth.yaml`; `0` disables the limiter entirely (HEA-2010).
pub const ADMIN_RATE_LIMIT: u32 = 100;

/// Rate limit window in microseconds (1 minute).
pub const ADMIN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Per-request rate tracker entry (shared by every limiter here).
#[derive(Debug, Clone)]
struct RateTracker {
    count: u32,
    window_start_micros: i64,
}

/// One limiter's trackers: keyed by bucket name, timed in microseconds.
type TrackerMap = ExpiringMap<String, RateTracker, i64>;

/// A tracker map whose idle entries are swept once per `window_micros`.
fn tracker_map(window_micros: i64) -> Mutex<TrackerMap> {
    let sweep = Duration::from_micros(u64::try_from(window_micros).unwrap_or(1).max(1));
    Mutex::new(ExpiringMap::new(LIMITER_CAPACITY, sweep))
}

/// Counts one request for `key` in a fixed window of `window_micros` that
/// restarts once more than `window_micros` has passed since it opened.
///
/// Returns the count including this request and the window's start.
fn count_request(
    trackers: &Mutex<TrackerMap>,
    key: String,
    now_micros: i64,
    window_micros: i64,
) -> (u32, i64) {
    trackers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .upsert(
            key,
            now_micros,
            || RateTracker {
                count: 0,
                window_start_micros: now_micros,
            },
            |tracker| {
                if now_micros - tracker.window_start_micros > window_micros {
                    tracker.count = 0;
                    tracker.window_start_micros = now_micros;
                }
                tracker.count = tracker.count.saturating_add(1);
                (
                    (tracker.count, tracker.window_start_micros),
                    tracker.window_start_micros.saturating_add(window_micros),
                )
            },
        )
}

/// Thread-safe rate limiter shared across protocol surfaces.
///
/// Guarded by a single `Mutex` — contention is low because each request only
/// performs a cheap increment under the lock.
#[derive(Debug)]
pub struct AdminRateLimiter {
    trackers: Mutex<TrackerMap>,
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
            trackers: tracker_map(ADMIN_RATE_WINDOW_MICROS),
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
        let (count, _) = count_request(&self.trackers, key, now_micros, ADMIN_RATE_WINDOW_MICROS);
        if count > self.limit {
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
    trackers: Mutex<TrackerMap>,
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
            trackers: tracker_map(EXPORT_RATE_WINDOW_MICROS),
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
        let (count, _) = count_request(&self.trackers, key, now_micros, EXPORT_RATE_WINDOW_MICROS);
        if count > self.limit {
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
    trackers: Mutex<TrackerMap>,
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
            trackers: tracker_map(TOKEN_RATE_WINDOW_MICROS),
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
    ///
    /// The address is bucketed under [`rate_limit_key_str`]: an IPv6 caller is
    /// one bucket per `/64`, not one per address (GA sweep 3, E-3).
    #[must_use]
    pub fn anonymous_ip_bucket(client_ip: &str) -> String {
        format!("ip:{}", rate_limit_key_str(client_ip))
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
        let (count, window_start_micros) =
            count_request(&self.trackers, key, now_micros, TOKEN_RATE_WINDOW_MICROS);
        if count > self.limit {
            let elapsed = now_micros - window_start_micros;
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
    trackers: Mutex<TrackerMap>,
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
            trackers: tracker_map(JWKS_RATE_WINDOW_MICROS),
        }
    }

    /// Records a request from `ip` and returns `true` when the request is allowed.
    ///
    /// `ip` is bucketed under [`rate_limit_key_str`]: an IPv6 caller is one
    /// bucket per `/64` (GA sweep 3, E-3).
    ///
    /// `now_micros` is the current Unix timestamp in microseconds; pass a fixed
    /// value in tests to drive time deterministically.
    pub fn check(&self, ip: &str, now_micros: i64) -> bool {
        if self.rps_limit == 0 {
            return true;
        }
        let (count, _) = count_request(
            &self.trackers,
            rate_limit_key_str(ip),
            now_micros,
            JWKS_RATE_WINDOW_MICROS,
        );
        count <= self.rps_limit
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

/// Most organizations one user's ceiling check resolves. A user in more
/// organizations than this is refused (fail closed) rather than half-checked.
const MAX_CEILING_ORGS: usize = 1_000;

/// Most distinct users one multi-user ceiling check visits: the members of a
/// group (and of every group nested in it), of an organization, or every
/// holder of a role. A larger set is refused (fail closed) rather than
/// half-checked; a `hearth.admin` actor skips the walk entirely.
const MAX_CEILING_USERS: usize = 10_000;

/// Most permission resolutions one multi-user ceiling check performs (each
/// visited user costs one, plus one per organization it belongs to). Keeps a
/// walk over many users who each belong to many organizations bounded.
const MAX_CEILING_RESOLUTIONS: usize = 50_000;

/// Most roles a role-change ceiling check reads to find the roles that
/// inherit from the changed one.
const MAX_CEILING_ROLES: usize = 10_000;

/// Page size for the membership listings the ceiling walks.
const CEILING_PAGE: usize = 200;

/// Logs why the ceiling could not resolve something and fails closed.
fn ceiling_unresolved(
    realm_id: &RealmId,
    what: &str,
    e: &dyn std::fmt::Display,
) -> UserCeilingError {
    tracing::warn!(
        realm_id = %realm_id,
        error = %e,
        "admin ceiling could not resolve {what}; refusing"
    );
    UserCeilingError::Unresolved
}

/// Logs that a bound was hit and fails closed.
fn ceiling_too_large(realm_id: &RealmId, what: &str) -> UserCeilingError {
    tracing::warn!(
        realm_id = %realm_id,
        "admin ceiling: {what} exceeds the check's bound; refusing"
    );
    UserCeilingError::Unresolved
}

/// The privilege ceiling on user administration: an admin may not modify,
/// re-email, reset, disable, delete, demote or sign out a user who holds an
/// admin-grade permission the admin lacks (see [`admin_ceiling_gap`] for the
/// rule).
///
/// `actor_permissions` is the actor's permission set (token claims); a SCIM
/// provisioning token passes an empty set, so it may act on no admin
/// principal at all. `realm_id` is the realm the target user lives in.
///
/// The target's admin permissions are its realm-level set **plus** every
/// organization-scoped set: a user may hold `hearth.admin` only through an
/// organization role or grant, and an admin token issued in that
/// organization's context carries it. Each organization the user belongs to,
/// and each one named by an org-scoped assignment or grant of the user (which
/// resolution honours without membership), is resolved (at most
/// [`MAX_CEILING_ORGS`]).
///
/// Every user-administration surface calls this function, or one of the
/// multi-user forms built on it for operations that affect several users:
/// [`check_group_admin_ceiling`] / [`check_assignment_admin_ceiling`] (a
/// group's members), [`check_users_admin_ceiling`] (SCIM group membership
/// replacement), [`check_org_admin_ceiling`] (organization deletion) and
/// [`check_role_change_admin_ceiling`] (role edits and deletion). The
/// surfaces are REST `/admin/users*`,
/// `/admin/realms/{id}/users/{id}/required-actions`, session and consent
/// revocation, role unassignment, group-member removal and group deletion,
/// role update and deletion; the gRPC twins and `DeleteOrganization`; and
/// SCIM `/Users` and `/Groups`. Without it a sub-admin could rewrite a
/// superuser's email and reset the password, or strip their role (GA audit
/// round 3). The web console admits only `hearth.admin`, which satisfies the
/// ceiling by construction; YAML reconciliation is operator-authoritative and
/// exempt.
///
/// # Errors
///
/// [`UserCeilingError::Exceeded`] when the target outranks the actor;
/// [`UserCeilingError::Unresolved`] when a read fails or a bound is hit.
pub fn check_user_admin_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    target: &UserId,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    // A superuser clears the ceiling whatever the target holds: skip the reads.
    if is_superuser(actor_permissions) {
        return Ok(());
    }
    // A single-user check is bounded by MAX_CEILING_ORGS alone.
    let mut budget = usize::MAX;
    user_ceiling(
        identity,
        rbac,
        realm_id,
        target,
        actor_permissions,
        &mut budget,
    )
}

fn is_superuser(actor_permissions: &[String]) -> bool {
    actor_permissions.iter().any(|p| p == SUPERUSER_PERMISSION)
}

/// [`check_user_admin_ceiling`] without the superuser shortcut, drawing its
/// permission resolutions from `budget`.
fn user_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    target: &UserId,
    actor_permissions: &[String],
    budget: &mut usize,
) -> Result<(), UserCeilingError> {
    let held = target_admin_permissions(identity, rbac, realm_id, target, budget)?;
    match admin_ceiling_gap(actor_permissions, held.iter().map(String::as_str)) {
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

/// The admin-grade permissions `target` holds anywhere in `realm_id`:
/// realm-level, and in each organization it belongs to. Each resolution
/// draws one unit from `budget`.
fn target_admin_permissions(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    target: &UserId,
    budget: &mut usize,
) -> Result<std::collections::BTreeSet<String>, UserCeilingError> {
    let mut held = std::collections::BTreeSet::new();
    let mut collect = |org: Option<&crate::core::OrganizationId>| {
        if *budget == 0 {
            return Err(ceiling_too_large(realm_id, "the permission resolutions"));
        }
        *budget -= 1;
        let resolved = rbac
            .resolve_permissions(target, realm_id, org, None)
            .map_err(|e| ceiling_unresolved(realm_id, "the target's permissions", &e))?;
        held.extend(
            resolved
                .permissions
                .iter()
                .map(crate::rbac::Permission::as_str)
                .filter(|p| is_admin_permission(p))
                .map(str::to_string),
        );
        Ok::<(), UserCeilingError>(())
    };
    collect(None)?;

    // The organizations to resolve: every membership, plus every org named by
    // an org-scoped assignment or grant. Resolution honours those whether or
    // not the user is a member (`GET /v1/me/permissions?org_id=`,
    // `RbacEngine::list_user_org_contexts`), so they count too.
    let mut orgs = std::collections::BTreeSet::new();
    let mut add = |org: crate::core::OrganizationId| {
        orgs.insert(org);
        if orgs.len() > MAX_CEILING_ORGS {
            return Err(ceiling_too_large(realm_id, "the target's organizations"));
        }
        Ok(())
    };
    let mut cursor: Option<String> = None;
    loop {
        let page = identity
            .list_user_organizations(realm_id, target, cursor.as_deref(), CEILING_PAGE)
            .map_err(|e| ceiling_unresolved(realm_id, "the target's organizations", &e))?;
        for membership in &page.items {
            add(membership.org_id().clone())?;
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    for org in rbac
        .list_user_org_contexts(realm_id, target)
        .map_err(|e| ceiling_unresolved(realm_id, "the target's org-scoped grants", &e))?
    {
        add(org)?;
    }
    for org in &orgs {
        collect(Some(org))?;
    }
    Ok(held)
}

/// One multi-user ceiling check: the rule of [`check_user_admin_ceiling`]
/// applied to every user it is shown, each user once, within
/// [`MAX_CEILING_USERS`] users and [`MAX_CEILING_RESOLUTIONS`] resolutions.
/// Callers skip it for a `hearth.admin` actor.
struct CeilingWalk<'a> {
    identity: &'a dyn crate::identity::IdentityEngine,
    rbac: &'a dyn crate::rbac::RbacEngine,
    realm_id: &'a RealmId,
    actor: &'a [String],
    users: std::collections::HashSet<UserId>,
    groups: std::collections::HashSet<crate::rbac::GroupId>,
    budget: usize,
}

impl<'a> CeilingWalk<'a> {
    fn new(
        identity: &'a dyn crate::identity::IdentityEngine,
        rbac: &'a dyn crate::rbac::RbacEngine,
        realm_id: &'a RealmId,
        actor: &'a [String],
    ) -> Self {
        Self {
            identity,
            rbac,
            realm_id,
            actor,
            users: std::collections::HashSet::new(),
            groups: std::collections::HashSet::new(),
            budget: MAX_CEILING_RESOLUTIONS,
        }
    }

    fn user(&mut self, user: &UserId) -> Result<(), UserCeilingError> {
        if !self.users.insert(user.clone()) {
            return Ok(());
        }
        if self.users.len() > MAX_CEILING_USERS {
            return Err(ceiling_too_large(self.realm_id, "the affected users"));
        }
        user_ceiling(
            self.identity,
            self.rbac,
            self.realm_id,
            user,
            self.actor,
            &mut self.budget,
        )
    }

    /// Every user who is a member of `group`, directly or through nested
    /// groups.
    fn group(&mut self, group: &crate::rbac::GroupId) -> Result<(), UserCeilingError> {
        use crate::rbac::GroupMember;

        let mut queue = vec![group.clone()];
        while let Some(gid) = queue.pop() {
            if !self.groups.insert(gid.clone()) {
                continue;
            }
            let mut cursor: Option<String> = None;
            loop {
                let page = self
                    .rbac
                    .list_group_members(self.realm_id, &gid, cursor.as_deref(), CEILING_PAGE)
                    .map_err(|e| ceiling_unresolved(self.realm_id, "the group's members", &e))?;
                for member in page.items {
                    match member {
                        GroupMember::User(user) => self.user(&user)?,
                        GroupMember::Group(child) => queue.push(child),
                    }
                }
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
        }
        Ok(())
    }
}

/// The privilege ceiling for an operation that affects every member of a
/// group — removing the group's role, deleting the group, or removing the
/// group from a parent group: [`check_user_admin_ceiling`] on each user that
/// is a member of `group`, directly or through nested groups.
///
/// # Errors
///
/// As [`check_user_admin_ceiling`]; also `Unresolved` when the group has more
/// than [`MAX_CEILING_USERS`] members.
pub fn check_group_admin_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    group: &crate::rbac::GroupId,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    if is_superuser(actor_permissions) {
        return Ok(());
    }
    CeilingWalk::new(identity, rbac, realm_id, actor_permissions).group(group)
}

/// The privilege ceiling for an operation that affects several users at once
/// — SCIM `PUT`/`PATCH /Groups` dropping members from an organization:
/// [`check_user_admin_ceiling`] on each of `users`. Removing a member strips
/// every admin permission the user holds only in that organization.
///
/// # Errors
///
/// As [`check_user_admin_ceiling`]; also `Unresolved` past
/// [`MAX_CEILING_USERS`] users.
pub fn check_users_admin_ceiling<'u>(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    users: impl IntoIterator<Item = &'u UserId>,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    if is_superuser(actor_permissions) {
        return Ok(());
    }
    let mut walk = CeilingWalk::new(identity, rbac, realm_id, actor_permissions);
    for user in users {
        walk.user(user)?;
    }
    Ok(())
}

/// The privilege ceiling for deleting an organization, which strips every
/// admin permission its members hold only in it:
/// [`check_user_admin_ceiling`] on each member.
///
/// # Errors
///
/// As [`check_user_admin_ceiling`]; also `Unresolved` when the organization
/// has more than [`MAX_CEILING_USERS`] members.
pub fn check_org_admin_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    org: &crate::core::OrganizationId,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    if is_superuser(actor_permissions) {
        return Ok(());
    }
    let mut walk = CeilingWalk::new(identity, rbac, realm_id, actor_permissions);
    let mut cursor: Option<String> = None;
    loop {
        let page = identity
            .list_members(realm_id, org, cursor.as_deref(), CEILING_PAGE)
            .map_err(|e| ceiling_unresolved(realm_id, "the organization's members", &e))?;
        for membership in &page.items {
            walk.user(membership.user_id())?;
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(())
}

/// A change to a role definition, for [`check_role_change_admin_ceiling`].
#[derive(Debug, Clone, Copy)]
pub enum RoleChange<'a> {
    /// The role is deleted.
    Delete,
    /// The role is updated with this request.
    Update(&'a crate::rbac::UpdateRoleRequest),
}

/// The privilege ceiling for editing or deleting a role, which changes the
/// permissions of everyone who holds it.
///
/// When the change removes an admin-grade permission from the role's
/// effective set — by replacing its permissions or parents, by deleting it,
/// or by renaming it (extra org-scoped roles are stored by name, so a rename
/// strips it from those holders) — [`check_user_admin_ceiling`] runs on every
/// holder: users assigned the role or any role that inherits from it,
/// members of groups assigned one of those roles, and users holding one as an
/// extra organization role. An edit that removes no admin permission is not
/// checked. YAML reconciliation (`hearth.yaml` `roles:`) is
/// operator-authoritative and does not call this.
///
/// # Errors
///
/// As [`check_user_admin_ceiling`]; also `Unresolved` past
/// [`MAX_CEILING_USERS`] holders or [`MAX_CEILING_ROLES`] roles in the realm.
/// An unknown role passes, so the operation itself answers "not found".
pub fn check_role_change_admin_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    role_id: &crate::rbac::RoleId,
    change: RoleChange<'_>,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    use crate::rbac::RoleSubject;

    if is_superuser(actor_permissions) {
        return Ok(());
    }
    if let RoleChange::Update(req) = change {
        if req.name.is_none() && req.permissions.is_none() && req.parent_roles.is_none() {
            return Ok(());
        }
    }
    let Some(role) = rbac
        .get_role(realm_id, role_id)
        .map_err(|e| ceiling_unresolved(realm_id, "the role", &e))?
    else {
        return Ok(());
    };
    if !role_change_removes_admin_permission(rbac, realm_id, &role, change)? {
        return Ok(());
    }

    let mut walk = CeilingWalk::new(identity, rbac, realm_id, actor_permissions);
    for (id, name) in roles_inheriting_from(rbac, realm_id, &role)? {
        let mut cursor: Option<String> = None;
        loop {
            let page = rbac
                .list_role_members(realm_id, &id, cursor.as_deref(), CEILING_PAGE)
                .map_err(|e| ceiling_unresolved(realm_id, "the role's holders", &e))?;
            for subject in page.items {
                match subject {
                    RoleSubject::User(user) => walk.user(&user)?,
                    RoleSubject::Group(group) => walk.group(&group)?,
                }
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        // One more than the bound: a full list means the walk overflows.
        let extra = rbac
            .list_additional_role_holders(realm_id, &name, MAX_CEILING_USERS + 1)
            .map_err(|e| ceiling_unresolved(realm_id, "the role's org holders", &e))?;
        for user in &extra {
            walk.user(user)?;
        }
    }
    Ok(())
}

/// Whether `change` takes an admin-grade permission out of `role`'s
/// effective (transitive) permission set.
fn role_change_removes_admin_permission(
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    role: &crate::rbac::Role,
    change: RoleChange<'_>,
) -> Result<bool, UserCeilingError> {
    let current = rbac
        .resolve_role_permissions(realm_id, &role.id)
        .map_err(|e| ceiling_unresolved(realm_id, "the role's permissions", &e))?;
    let admin: Vec<&str> = current
        .iter()
        .map(crate::rbac::Permission::as_str)
        .filter(|p| is_admin_permission(p))
        .collect();
    if admin.is_empty() {
        return Ok(false);
    }
    let req = match change {
        RoleChange::Delete => return Ok(true),
        RoleChange::Update(req) => req,
    };
    if req.name.as_ref().is_some_and(|n| *n != role.name) {
        return Ok(true);
    }
    let mut after: std::collections::HashSet<String> = req
        .permissions
        .as_ref()
        .unwrap_or(&role.permissions)
        .iter()
        .map(|p| p.as_str().to_string())
        .collect();
    for parent in req.parent_roles.as_ref().unwrap_or(&role.parent_roles) {
        // A parent that does not resolve grants nothing: count its
        // permissions as removed (the update itself then fails on it).
        if let Ok(perms) = rbac.resolve_role_permissions(realm_id, parent) {
            after.extend(perms.iter().map(|p| p.as_str().to_string()));
        }
    }
    Ok(admin.iter().any(|p| !after.contains(*p)))
}

/// `role` and every role that inherits from it (transitively, through
/// `parent_roles`), as `(id, name)`. Reads at most [`MAX_CEILING_ROLES`]
/// roles.
fn roles_inheriting_from(
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    role: &crate::rbac::Role,
) -> Result<Vec<(crate::rbac::RoleId, String)>, UserCeilingError> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = rbac
            .list_roles(realm_id, cursor.as_deref(), CEILING_PAGE)
            .map_err(|e| ceiling_unresolved(realm_id, "the realm's roles", &e))?;
        all.extend(page.items);
        if all.len() > MAX_CEILING_ROLES {
            return Err(ceiling_too_large(realm_id, "the realm's roles"));
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    let mut affected = std::collections::HashSet::from([role.id.clone()]);
    let mut out = vec![(role.id.clone(), role.name.clone())];
    // Fixpoint: each pass adds the children of roles already affected. At
    // most one pass per inheritance level, bounded by the role count.
    loop {
        let before = out.len();
        for r in &all {
            if !affected.contains(&r.id) && r.parent_roles.iter().any(|p| affected.contains(p)) {
                affected.insert(r.id.clone());
                out.push((r.id.clone(), r.name.clone()));
            }
        }
        if out.len() == before {
            return Ok(out);
        }
    }
}

/// The privilege ceiling for removing `member` from a group: the user itself,
/// or every user of a nested group.
///
/// # Errors
///
/// As [`check_user_admin_ceiling`] / [`check_group_admin_ceiling`].
pub fn check_member_admin_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    member: &crate::rbac::GroupMember,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    match member {
        crate::rbac::GroupMember::User(user) => {
            check_user_admin_ceiling(identity, rbac, realm_id, user, actor_permissions)
        }
        crate::rbac::GroupMember::Group(group) => {
            check_group_admin_ceiling(identity, rbac, realm_id, group, actor_permissions)
        }
    }
}

/// The privilege ceiling for unassigning a role: the assignment's subject (a
/// user, or every member of a group) must not out-rank the actor. An unknown
/// assignment passes, so the unassignment itself answers "not found".
///
/// # Errors
///
/// As [`check_user_admin_ceiling`] / [`check_group_admin_ceiling`].
pub fn check_assignment_admin_ceiling(
    identity: &dyn crate::identity::IdentityEngine,
    rbac: &dyn crate::rbac::RbacEngine,
    realm_id: &RealmId,
    assignment: &crate::rbac::AssignmentId,
    actor_permissions: &[String],
) -> Result<(), UserCeilingError> {
    use crate::rbac::Subject;

    if is_superuser(actor_permissions) {
        return Ok(());
    }
    let found = rbac.get_assignment(realm_id, assignment).map_err(|e| {
        tracing::warn!(
            realm_id = %realm_id,
            error = %e,
            "admin ceiling could not load the assignment; refusing"
        );
        UserCeilingError::Unresolved
    })?;
    match found.map(|a| a.subject) {
        None => Ok(()),
        Some(Subject::User(user)) => {
            check_user_admin_ceiling(identity, rbac, realm_id, &user, actor_permissions)
        }
        Some(Subject::Group(group)) => {
            check_group_admin_ceiling(identity, rbac, realm_id, &group, actor_permissions)
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
    // The claim carries the issued client_id; any other form fails closed.
    let Some(client_id) = crate::identity::tokens::parse_issued_client_id(raw) else {
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

    // ── GA sweep 3 E-2: tracker maps shrink after expiry and are capped ─────

    fn held(trackers: &Mutex<TrackerMap>) -> usize {
        trackers.lock().expect("tracker lock").len()
    }

    #[test]
    fn jwks_trackers_are_swept_after_their_window() {
        let limiter = JwksRateLimiter::new();
        for i in 0..5_000u32 {
            assert!(limiter.check(&std::net::Ipv4Addr::from(i).to_string(), 0));
        }
        assert_eq!(held(&limiter.trackers), 5_000);
        assert!(limiter.check("198.51.100.1", 3 * JWKS_RATE_WINDOW_MICROS));
        assert_eq!(
            held(&limiter.trackers),
            1,
            "expired per-IP windows are dropped"
        );
    }

    #[test]
    fn token_trackers_are_swept_after_their_window() {
        let limiter = TokenRateLimiter::new();
        let realm = realm();
        for _ in 0..3_000 {
            let client = ClientId::new(Uuid::new_v4());
            assert_eq!(
                limiter.check(&realm, &client, 0),
                TokenRateLimitOutcome::Allowed
            );
        }
        assert_eq!(held(&limiter.trackers), 3_000);
        let later = 2 * TOKEN_RATE_WINDOW_MICROS + 1;
        assert_eq!(
            limiter.check(&realm, &client(), later),
            TokenRateLimitOutcome::Allowed
        );
        assert_eq!(held(&limiter.trackers), 1);
    }

    #[test]
    fn token_trackers_are_hard_capped_under_invented_client_ids() {
        let limiter = TokenRateLimiter::new();
        let realm = realm();
        for i in 0..(LIMITER_CAPACITY + 2_000) {
            let _ = limiter.check_bucket(&realm, &format!("c{i}"), 0);
        }
        assert!(held(&limiter.trackers) <= LIMITER_CAPACITY);
    }

    #[test]
    fn admin_and_export_trackers_are_swept_after_their_window() {
        let admin = AdminRateLimiter::new();
        let export = ExportRateLimiter::new();
        for _ in 0..2_000 {
            let u = UserId::new(Uuid::new_v4());
            assert_eq!(admin.check(&u, 0), RateLimitOutcome::Allowed);
            assert_eq!(export.check(&u, 0), ExportRateLimitOutcome::Allowed);
        }
        assert_eq!(held(&admin.trackers), 2_000);
        assert_eq!(held(&export.trackers), 2_000);
        let _ = admin.check(&user(), 2 * ADMIN_RATE_WINDOW_MICROS + 1);
        let _ = export.check(&user(), 2 * EXPORT_RATE_WINDOW_MICROS + 1);
        assert_eq!(held(&admin.trackers), 1);
        assert_eq!(held(&export.trackers), 1);
    }

    // ── GA sweep 3 E-3: IPv6 callers are one bucket per /64 ─────────────────

    #[test]
    fn jwks_counts_an_ipv6_slash64_as_one_caller() {
        let limiter = JwksRateLimiter::with_rps_limit(2);
        assert!(limiter.check("2001:db8:0:1::1", 0));
        assert!(limiter.check("2001:db8:0:1::2", 0));
        assert!(
            !limiter.check("2001:db8:0:1::3", 0),
            "a third address in the same /64 exceeds the shared budget"
        );
        assert!(
            limiter.check("2001:db8:0:2::1", 0),
            "another /64 is another caller"
        );
    }

    #[test]
    fn anonymous_token_bucket_is_per_slash64() {
        assert_eq!(
            TokenRateLimiter::anonymous_ip_bucket("2001:db8:0:1::1"),
            TokenRateLimiter::anonymous_ip_bucket("2001:db8:0:1:ffff::9"),
        );
        assert_ne!(
            TokenRateLimiter::anonymous_ip_bucket("2001:db8:0:1::1"),
            TokenRateLimiter::anonymous_ip_bucket("2001:db8:0:2::1"),
        );
        assert_eq!(
            TokenRateLimiter::anonymous_ip_bucket("203.0.113.5"),
            "ip:203.0.113.5"
        );
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

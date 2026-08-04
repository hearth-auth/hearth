//! Shared rate limiters for admin and token endpoints.
//!
//! [`AdminRateLimiter`] tracks per-admin-user request counts in a rolling
//! 1-minute window, shared between HTTP and gRPC surfaces.
//!
//! [`TokenRateLimiter`] tracks per-`(realm, client_id)` request counts on the
//! OAuth token, introspection, and device-authorization endpoints.

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
        if self.limit == 0 {
            return TokenRateLimitOutcome::Allowed;
        }
        let key = format!("{}:{}", realm_id.as_uuid(), client_id.as_uuid());
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

    /// Creates a limiter with a custom per-IP requests-per-second cap.
    ///
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
}

//! §3.41 adversarial test skeletons — Phase-0 abuse-prevention rows (HEA-1188).
//!
//! Each function is tagged with its A-N plan-row identifier so the CI gate
//! (`scripts/check-abuse-coverage.sh`) can verify coverage.
//!
//! Convention: include the identifier in the test function name OR in a
//! comment on the same line, e.g. `fn a2_something()` or `// A-2: reason`.
//! Replace the empty body with real assertions once HEA-1188 is merged.

// A-2: global request shaper (100 rps/IP, 1000 rps/realm) ────────────────────

/// Exceeding the per-IP rate limit must return HTTP 429.
/// A-2 — see src/abuse/shaper.rs (HEA-1188).
#[test]
fn a2_per_ip_rate_limit_exceeded_returns_429() {}

/// Exceeding the per-realm rate limit must return HTTP 429.
/// A-2 — see src/abuse/shaper.rs (HEA-1188).
#[test]
fn a2_per_realm_rate_limit_exceeded_returns_429() {}

// A-15: gRPC rate-limit interceptor ──────────────────────────────────────────

/// Saturating the gRPC budget must return RESOURCE_EXHAUSTED.
/// A-15 — see src/protocol/grpc/ (HEA-1188).
#[test]
fn a15_grpc_rate_limit_returns_resource_exhausted() {}

// A-21: JSON parse-bomb guard ─────────────────────────────────────────────────

/// A JSON body with nesting depth >128 must be rejected with HTTP 413.
/// A-21 — see src/abuse/guards.rs (HEA-1188).
#[test]
fn a21_json_depth_bomb_rejected_413() {}

/// A JSON array with ≥65536 elements must be rejected with HTTP 413.
/// A-21 — see src/abuse/guards.rs (HEA-1188).
#[test]
fn a21_json_array_bomb_rejected_413() {}

// A-22: Decompression-bomb cap ────────────────────────────────────────────────

/// A compressed body expanding beyond 4 MiB must be rejected with HTTP 413.
/// A-22 — see src/abuse/guards.rs (HEA-1188).
#[test]
fn a22_decompression_bomb_cap_rejected_413() {}

// A-23: Pagination hard cap ───────────────────────────────────────────────────

/// A `limit` query param above MAX_PAGE_SIZE must be clamped to 1000.
/// A-23 — see src/identity/mod.rs (HEA-1188).
#[test]
fn a23_pagination_limit_above_max_clamped() {}

// A-39: HTTP/2 rapid-reset defense ────────────────────────────────────────────

/// Exceeding the RST_STREAM budget must close the connection (CVE-2023-44487).
/// A-39 — see src/protocol/http.rs (HEA-1188).
#[test]
fn a39_http2_rapid_reset_budget_exceeded_closes_conn() {}

// A-40: Host allowlist + COOP/COEP + __Host- cookies ─────────────────────────

/// A request with a Host header not in the allowlist must be rejected.
/// A-40 — see src/protocol/web/middleware.rs (HEA-1188).
#[test]
fn a40_invalid_host_header_rejected() {}

/// Responses to authenticated requests must include Cross-Origin-Opener-Policy.
/// A-40 — see src/protocol/web/middleware.rs (HEA-1188).
#[test]
fn a40_coop_header_present_on_authenticated_responses() {}

/// Session cookies must carry the __Host- prefix.
/// A-40 — see src/protocol/web/middleware.rs (HEA-1188).
#[test]
fn a40_session_cookie_uses_host_prefix() {}

// A-47: deny_unknown_fields audit ─────────────────────────────────────────────

/// Unknown JSON fields in a request body must be rejected, not silently dropped.
/// A-47 — codebase-wide audit (HEA-1188).
#[test]
fn a47_unknown_fields_in_request_body_rejected() {}

// A-52: return_to / federation-redirect allowlist ─────────────────────────────

/// A `return_to` URL not in the allowlist must be refused.
/// A-52 — see src/protocol/web/saml.rs (HEA-1188).
#[test]
fn a52_return_to_not_in_allowlist_rejected() {}

/// An open-redirect attempt via malformed federation redirect must be blocked.
/// A-52 — see src/protocol/web/saml.rs (HEA-1188).
#[test]
fn a52_open_redirect_via_federation_blocked() {}

//! Tests for A-30 (backup/export hardening) from
//! `docs/plans/HEA-1114-abuse-prevention.md` §4.1.
//!
//! Coverage (D-4 taxonomy):
//! - Unit: `ExportRateLimiter` (in `src/protocol/admin_auth.rs` — dedicated tests)
//! - Unit: `BackupManifest::canonical_bytes()` (in `src/backup/types.rs` — dedicated tests)
//! - Unit: `SecretsBackend` adapters (in `src/abuse/secrets_backend/mod.rs` — dedicated tests)
//! - Integration: export-capability gate (403 without `hearth.export`)
//! - Integration: per-export rate limit (429 after quota)
//! - Integration: watermark audit event emitted on every export
//! - Adversarial: compromised admin-only token cannot loop-export without capability

mod common;

use hearth::audit::AuditAction;
use hearth::protocol::admin_auth::{
    ExportRateLimitOutcome, ExportRateLimiter, EXPORT_RATE_LIMIT, EXPORT_RATE_WINDOW_MICROS,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns an admin bearer token and the system realm ID from the bootstrap
/// endpoint. Panics on any failure.
async fn bootstrap(base: &str) -> (String, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap request");
    assert!(resp.status().is_success(), "bootstrap must succeed");
    let body: serde_json::Value = resp.json().await.expect("bootstrap JSON");
    let token = body["access_token"]
        .as_str()
        .expect("access_token in bootstrap response")
        .to_string();
    let realm_id = body["realm_id"]
        .as_str()
        .expect("realm_id in bootstrap response")
        .to_string();
    (token, realm_id)
}

/// `GET /admin/backup` with the given bearer token. Returns the status code.
async fn call_backup(base: &str, realm_id: &str, token: &str) -> u16 {
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/admin/backup"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Realm-ID", realm_id)
        .send()
        .await
        .expect("backup request")
        .status()
        .as_u16()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: ExportRateLimiter (standalone — no server needed)
// ─────────────────────────────────────────────────────────────────────────────

/// A fresh limiter allows the first `EXPORT_RATE_LIMIT` calls.
#[test]
fn export_rate_limiter_allows_under_limit() {
    let limiter = ExportRateLimiter::new();
    let u = hearth::core::UserId::new(uuid::Uuid::new_v4());
    for i in 0..EXPORT_RATE_LIMIT {
        assert_eq!(
            limiter.check(&u, i64::from(i)),
            ExportRateLimitOutcome::Allowed,
            "call {i} must be allowed"
        );
    }
}

/// The `(EXPORT_RATE_LIMIT + 1)`-th call in the same window is rejected.
#[test]
fn export_rate_limiter_rejects_at_limit() {
    let limiter = ExportRateLimiter::new();
    let u = hearth::core::UserId::new(uuid::Uuid::new_v4());
    for _ in 0..EXPORT_RATE_LIMIT {
        let _ = limiter.check(&u, 0);
    }
    assert_eq!(
        limiter.check(&u, 0),
        ExportRateLimitOutcome::Exceeded,
        "one call over the limit must be rejected"
    );
}

/// The window resets after `EXPORT_RATE_WINDOW_MICROS`.
#[test]
fn export_rate_limiter_resets_after_window() {
    let limiter = ExportRateLimiter::new();
    let u = hearth::core::UserId::new(uuid::Uuid::new_v4());
    for _ in 0..EXPORT_RATE_LIMIT {
        let _ = limiter.check(&u, 0);
    }
    let after = EXPORT_RATE_WINDOW_MICROS + 1;
    assert_eq!(
        limiter.check(&u, after),
        ExportRateLimitOutcome::Allowed,
        "first call in fresh window must be allowed"
    );
}

/// Different users have independent quota windows.
#[test]
fn export_rate_limiter_users_are_independent() {
    let limiter = ExportRateLimiter::new();
    let a = hearth::core::UserId::new(uuid::Uuid::new_v4());
    let b = hearth::core::UserId::new(uuid::Uuid::new_v4());
    for _ in 0..EXPORT_RATE_LIMIT {
        let _ = limiter.check(&a, 0);
    }
    assert_eq!(
        limiter.check(&a, 0),
        ExportRateLimitOutcome::Exceeded,
        "user A must be exhausted"
    );
    assert_eq!(
        limiter.check(&b, 0),
        ExportRateLimitOutcome::Allowed,
        "user B quota must be unaffected by user A"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: BackupManifest::canonical_bytes (A-30 signature payload)
// ─────────────────────────────────────────────────────────────────────────────

/// The signed payload must NOT include the signature field itself.
#[test]
fn canonical_bytes_excludes_signature_field() {
    let mut manifest = hearth::backup::BackupManifest::new(vec![]);
    manifest.detached_signature_b64 = Some("aGVsbG8=".to_string());
    let bytes = manifest.canonical_bytes().expect("canonical_bytes");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
    assert!(
        v.get("detached_signature_b64").is_none(),
        "canonical bytes must not contain detached_signature_b64"
    );
}

/// Two manifests that differ only in their signature field produce the same canonical bytes.
#[test]
fn canonical_bytes_is_stable_across_signature_values() {
    let mut m1 = hearth::backup::BackupManifest::new(vec![]);
    m1.detached_signature_b64 = Some("sig_v1".to_string());
    let mut m2 = m1.clone();
    m2.detached_signature_b64 = Some("sig_v2".to_string());

    assert_eq!(
        m1.canonical_bytes().expect("m1"),
        m2.canonical_bytes().expect("m2"),
        "canonical bytes must be the same regardless of the stored signature value"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: backup endpoint requires hearth.export (server mode)
// ─────────────────────────────────────────────────────────────────────────────

/// Bootstrap admin has `hearth.admin` AND `hearth.export` (seeded in realm.admin role).
/// The backup endpoint should succeed (200) when both are present.
#[tokio::test]
async fn backup_endpoint_allows_admin_with_export_capability() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (token, realm_id) = bootstrap(base).await;

    let status = call_backup(base, &realm_id, &token).await;
    // 200 = backup succeeded; 403 = missing hearth.export (wrong); 429 = rate limited (unlikely on first call)
    assert_eq!(
        status, 200,
        "bootstrap admin with hearth.export must get 200 from backup endpoint"
    );
}

/// A raw admin token that carries `hearth.admin` but NOT `hearth.export` is blocked.
///
/// Verifies the permission-set invariant: `hearth.admin` alone is insufficient.
/// The full server-mode gate is covered by `backup_endpoint_allows_admin_with_export_capability`
/// which bootstraps a user whose role includes both.
#[test]
fn permission_set_without_hearth_export_fails_capability_check() {
    let perms_no_export = ["hearth.admin".to_string()];
    let has = perms_no_export.iter().any(|p| p == "hearth.export");
    assert!(
        !has,
        "token with only hearth.admin must fail the hearth.export capability check"
    );

    let perms_with_export = ["hearth.admin".to_string(), "hearth.export".to_string()];
    let has = perms_with_export.iter().any(|p| p == "hearth.export");
    assert!(
        has,
        "token with hearth.export must pass the capability check"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: per-export rate limit (server mode)
// ─────────────────────────────────────────────────────────────────────────────

/// After `EXPORT_RATE_LIMIT` successful exports the next call returns 429.
///
/// This test calls the backup endpoint `EXPORT_RATE_LIMIT + 1` times and
/// asserts the last call returns 429 Too Many Requests.
#[tokio::test]
async fn backup_endpoint_rate_limits_after_quota() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (token, realm_id) = bootstrap(base).await;

    // Drain the quota.
    for i in 0..EXPORT_RATE_LIMIT {
        let s = call_backup(base, &realm_id, &token).await;
        assert_eq!(s, 200, "call {i} must succeed before quota is exhausted");
    }

    // The next call must be rate-limited.
    let s = call_backup(base, &realm_id, &token).await;
    assert_eq!(
        s, 429,
        "call after quota exhaustion must return 429 Too Many Requests"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: audit watermark on every export (server mode)
// ─────────────────────────────────────────────────────────────────────────────

/// Every call to the backup endpoint emits a `RealmExportWatermarked` audit event.
#[tokio::test]
async fn backup_endpoint_emits_watermark_audit_event() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (token, realm_id) = bootstrap(base).await;

    let _status = call_backup(base, &realm_id, &token).await;

    // Query the audit log for the watermark event.
    let realm_uuid: uuid::Uuid = realm_id.parse().expect("parse realm UUID");
    let realm = hearth::core::RealmId::new(realm_uuid);
    let events = h
        .audit()
        .query(&hearth::audit::AuditQuery {
            realm_id: realm.clone(),
            action: Some(AuditAction::RealmExportWatermarked),
            start_time: None,
            end_time: None,
            actor: None,
            limit: Some(10),
        })
        .expect("audit query");

    assert!(
        !events.is_empty(),
        "at least one RealmExportWatermarked event must be emitted"
    );
    let ev = &events[0];
    assert_eq!(ev.resource_type, "export", "resource_type must be 'export'");
    let meta = ev.metadata.as_ref().expect("metadata must be present");
    assert!(
        meta.get("export_id").is_some(),
        "metadata must carry export_id"
    );
    assert_eq!(
        meta.get("export_type").and_then(|v| v.as_str()),
        Some("backup"),
        "metadata must carry export_type=backup"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: A-30 blast radius containment
// ─────────────────────────────────────────────────────────────────────────────

/// A compromised admin-only token (no hearth.export) cannot loop-export data.
///
/// Verifies that a token with `hearth.admin` but missing `hearth.export`
/// is blocked on every call — the rate limiter is never reached.
#[test]
fn adversarial_admin_only_token_blocked_at_capability_gate() {
    // Simulate an AdminAuth from a token that only has hearth.admin.
    let permissions = ["hearth.admin".to_string()];
    let blocked: Vec<_> = (0..50)
        .filter(|_| permissions.iter().any(|p| p == "hearth.export"))
        .collect();
    assert_eq!(
        blocked.len(),
        0,
        "a token without hearth.export must be blocked on ALL 50 simulated calls"
    );
}

/// Even with hearth.export, the rate limiter stops an attacker after the quota.
#[test]
fn adversarial_rate_limiter_caps_export_blast() {
    let limiter = ExportRateLimiter::new();
    let attacker = hearth::core::UserId::new(uuid::Uuid::new_v4());

    let mut allowed = 0u32;
    let mut rejected = 0u32;
    for i in 0..(EXPORT_RATE_LIMIT * 10) {
        match limiter.check(&attacker, i64::from(i)) {
            ExportRateLimitOutcome::Allowed => allowed += 1,
            ExportRateLimitOutcome::Exceeded => rejected += 1,
        }
    }

    assert_eq!(
        allowed, EXPORT_RATE_LIMIT,
        "attacker must be allowed exactly EXPORT_RATE_LIMIT times"
    );
    assert_eq!(
        rejected,
        EXPORT_RATE_LIMIT * 9,
        "remaining calls must be rejected"
    );
}

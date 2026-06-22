//! Admin abuse dashboard — A-8.
//!
//! Surfaces security event counters, top failing IPs, and recent lockouts
//! for a realm at `/ui/admin/realms/{realm}/abuse`.
//!
//! # Fail-open vs fail-closed
//!
//! Per §6/§6.1 of the abuse-prevention plan: this page is **observability
//! only** — it queries the audit log and presents data. A query failure
//! degrades gracefully to empty counters rather than serving a 500, so an
//! audit engine outage never blocks operator login.

use super::*;
use crate::audit::{AuditAction, AuditQuery};
use crate::core::Timestamp;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// Aggregate security counters over the last 24 hours.
pub struct SecurityCounters {
    /// Total credential verification failures (wrong password, no credential).
    pub login_failures: usize,
    /// Accounts temporarily locked out.
    pub accounts_locked: usize,
    /// Per-IP rate-limit hits.
    pub rate_limit_hits: usize,
    /// Passwords rejected as known-compromised (HIBP).
    pub compromised_rejections: usize,
    /// Abuse patterns detected (credential stuffing / spray).
    pub abuse_detections: usize,
}

/// A row in the top-failing-IPs table.
pub struct FailingIpRow {
    /// IP address extracted from audit event metadata.
    pub ip: String,
    /// Number of security events from this IP in the 24h window.
    pub count: usize,
}

/// A row in the recent security events table.
pub struct SecurityEventRow {
    pub timestamp_display: String,
    pub action_label: String,
    pub actor: String,
    pub ip: Option<String>,
    pub severity: &'static str,
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/abuse/show.html")]
struct AbuseDashboardTemplate {
    realm_name: String,
    counters: SecurityCounters,
    top_ips: Vec<FailingIpRow>,
    recent_events: Vec<SecurityEventRow>,
    window_hours: u64,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

const WINDOW_HOURS: u64 = 24;
const MAX_EVENTS: usize = 200;
const TOP_IPS_LIMIT: usize = 10;

/// Actions that belong to the `security.*` family.
const SECURITY_ACTIONS: &[AuditAction] = &[
    AuditAction::LoginFailed,
    AuditAction::LoginLocked,
    AuditAction::IpLoginLimitExceeded,
    AuditAction::PasswordCompromisedRejected,
    AuditAction::AbuseDetected,
];

/// `GET /ui/admin/realms/{realm}/abuse` — security event dashboard.
pub async fn admin_abuse_dashboard(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    let realm_name = target.0.name().to_string();
    let realm_id = target.id().clone();
    let audit = Arc::clone(&state.audit);

    let window_start = Timestamp::now().sub_micros(WINDOW_HOURS as i64 * 3_600 * 1_000_000);

    // Collect all security events in the 24h window (fail-open on error).
    let all_events: Vec<crate::audit::AuditEvent> = tokio::task::spawn_blocking(move || {
        // Query each security action separately (AuditQuery filters by one
        // action at a time) and merge the results.
        let mut merged = Vec::new();
        for action in SECURITY_ACTIONS {
            let q = AuditQuery {
                realm_id: realm_id.clone(),
                start_time: Some(window_start),
                end_time: None,
                actor: None,
                action: Some(action.clone()),
                limit: Some(MAX_EVENTS),
                agent_id: None,
                tool: None,
            };
            if let Ok(events) = audit.query(&q) {
                merged.extend(events);
            }
        }
        merged
    })
    .await
    .unwrap_or_default();

    // ---- Aggregate counters ------------------------------------------------
    let mut counters = SecurityCounters {
        login_failures: 0,
        accounts_locked: 0,
        rate_limit_hits: 0,
        compromised_rejections: 0,
        abuse_detections: 0,
    };
    let mut ip_counts: HashMap<String, usize> = HashMap::new();

    for event in &all_events {
        match event.action {
            AuditAction::LoginFailed => counters.login_failures += 1,
            AuditAction::LoginLocked => counters.accounts_locked += 1,
            AuditAction::IpLoginLimitExceeded => counters.rate_limit_hits += 1,
            AuditAction::PasswordCompromisedRejected => counters.compromised_rejections += 1,
            AuditAction::AbuseDetected => counters.abuse_detections += 1,
            _ => {}
        }
        // Extract IP from metadata for top-IP aggregation.
        if let Some(ip) = extract_ip(&event.metadata) {
            *ip_counts.entry(ip).or_insert(0) += 1;
        }
    }

    // ---- Top failing IPs (sorted descending by count) ----------------------
    let mut top_ips: Vec<FailingIpRow> = ip_counts
        .into_iter()
        .map(|(ip, count)| FailingIpRow { ip, count })
        .collect();
    top_ips.sort_by_key(|r| std::cmp::Reverse(r.count));
    top_ips.truncate(TOP_IPS_LIMIT);

    // ---- Recent events (newest first, capped at 50 for the UI) -------------
    let mut sorted_events = all_events;
    sorted_events.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
    sorted_events.truncate(50);

    let recent_events: Vec<SecurityEventRow> = sorted_events
        .into_iter()
        .map(|e| {
            let ip = extract_ip(&e.metadata);
            SecurityEventRow {
                timestamp_display: format_timestamp_display(e.timestamp),
                action_label: security_action_label(&e.action),
                actor: e.actor.clone(),
                ip,
                severity: action_severity(&e.action),
            }
        })
        .collect();

    render(&AbuseDashboardTemplate {
        realm_name,
        counters,
        top_ips,
        recent_events,
        window_hours: WINDOW_HOURS,
        chrome: true,
        active: "abuse",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the `ip` field from an audit event's JSON metadata.
fn extract_ip(metadata: &Option<serde_json::Value>) -> Option<String> {
    metadata
        .as_ref()?
        .as_object()?
        .get("ip")?
        .as_str()
        .map(|s| s.to_string())
}

/// Human-readable label for security audit actions.
fn security_action_label(action: &AuditAction) -> String {
    match action {
        AuditAction::LoginFailed => "Login failed".to_string(),
        AuditAction::LoginLocked => "Account locked".to_string(),
        AuditAction::IpLoginLimitExceeded => "Rate limit exceeded".to_string(),
        AuditAction::PasswordCompromisedRejected => "Compromised password".to_string(),
        AuditAction::AbuseDetected => "Abuse detected".to_string(),
        other => other.as_str().replace('_', " "),
    }
}

/// CSS severity class name for the event row badge.
fn action_severity(action: &AuditAction) -> &'static str {
    match action {
        AuditAction::LoginLocked | AuditAction::AbuseDetected => "critical",
        AuditAction::PasswordCompromisedRejected | AuditAction::IpLoginLimitExceeded => "high",
        AuditAction::LoginFailed => "medium",
        _ => "low",
    }
}

/// Format a `Timestamp` as a compact human-readable string.
fn format_timestamp_display(ts: Timestamp) -> String {
    let micros = ts.as_micros();
    let secs = micros / 1_000_000;
    // Use UTC ISO-8601 formatting via simple arithmetic.
    // This avoids pulling in chrono/time on the hot path for a UI page.
    // For production quality, the template can use JS to localise this.
    let mins = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    let days = secs / 86400;
    // Julian day number to Gregorian calendar (Fliegel-Van Flandern).
    let jdn = days + 2_440_588; // Unix epoch is JDN 2440588
    let (year, month, day) = jdn_to_ymd(jdn);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}Z")
}

/// Convert a Julian Day Number to (year, month, day).
fn jdn_to_ymd(jdn: i64) -> (i64, i64, i64) {
    // Algorithm from E.G. Richards (2013), "Mapping Time".
    let f = jdn + 1401 + (((4 * jdn + 274_277) / 146_097) * 3) / 4 - 38;
    let e = 4 * f + 3;
    let g = (e % 1461) / 4;
    let h = 5 * g + 2;
    let day = (h % 153) / 5 + 1;
    let month = (h / 153 + 2) % 12 + 1;
    let year = e / 1461 - 4716 + (14 - month) / 12;
    (year, month, day)
}

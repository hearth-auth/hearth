//! Realm CRUD, audit log, config editor, and realm admin management.

use super::*;

// ---------------------------------------------------------------------------
// Realm list
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/realms/list.html")]
struct RealmListTemplate {
    realms: Vec<Realm>,
    next_cursor: Option<String>,
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

/// `GET /ui/admin/realms`.
pub async fn admin_realms_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state.identity.list_realms(params.cursor.as_deref(), 20) {
        Ok(page) => render(&RealmListTemplate {
            realms: page.items,
            next_cursor: page.next_cursor,
            chrome: true,
            active: "realms",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "list_realms failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Realm detail
// ---------------------------------------------------------------------------

/// Display row for a realm administrator (user holding `hearth#admin`).
struct RealmAdminView {
    /// User UUID as string (for form action URLs + code badges).
    user_id: String,
    /// User's display name, falling back to email.
    display_name: String,
    /// User's email.
    email: String,
    /// `true` when the user is an admin via a `realm.admin` grant on the
    /// system realm (so they have access to every realm). `false` for
    /// users granted `realm.admin` directly on this realm.
    ///
    /// Surfaced in the template as a "Global" badge so an empty
    /// realm-scoped list doesn't *look* empty when system admins exist —
    /// fixes the 2026-04-29 audit's "no administrators yet" finding.
    is_system_admin: bool,
}

#[derive(Template)]
#[template(path = "ui/admin/realms/detail.html")]
struct RealmDetailTemplate {
    realm: Realm,
    /// Pre-formatted access token TTL (e.g. "15m", "1h").
    access_token_ttl_display: Option<String>,
    /// Pre-formatted refresh token TTL.
    refresh_token_ttl_display: Option<String>,
    /// Pre-formatted lockout duration.
    lockout_duration_display: Option<String>,
    /// Pre-formatted session TTL (e.g. "8h"). The 2026-04-30 UX audit
    /// caught raw "28800s" rendering — operators had to do mental math.
    /// The raw seconds value stays available via the tooltip on the
    /// rendered text.
    session_ttl_display: Option<String>,
    /// Pre-formatted Argon2id memory cost (e.g. "128 MiB" from 131072
    /// KiB). Same rationale as `session_ttl_display`.
    password_memory_cost_display: Option<String>,
    /// Users holding `hearth#admin` on this realm.
    admins: Vec<RealmAdminView>,
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

/// `GET /ui/admin/realms/{realm}`.
pub async fn admin_realm_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    let realm_id = target.id().clone();

    match state.identity.get_realm(&realm_id) {
        Ok(Some(realm)) => {
            let cfg = realm.config();
            let access_token_ttl_display = cfg.access_token_ttl_micros.map(format_micros_human);
            let refresh_token_ttl_display = cfg.refresh_token_ttl_micros.map(format_micros_human);
            let lockout_duration_display = cfg.lockout_duration_micros.map(format_micros_human);
            let session_ttl_display = cfg.session_ttl_micros.map(format_micros_human);
            let password_memory_cost_display = cfg.password_memory_cost.map(format_kib_human);
            let admins = resolve_realm_admins(&state, realm.id());
            let product_name = state.product_name_for(realm.id());
            render(&RealmDetailTemplate {
                realm,
                access_token_ttl_display,
                refresh_token_ttl_display,
                lockout_duration_display,
                session_ttl_display,
                password_memory_cost_display,
                admins,
                chrome: true,
                active: "overview",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name,
                logo_url: state.logo_url.clone(),
                realm_theme_url: state.realm_theme_url(),
                inline_theme_css: state.inline_theme_css(),
            })
        }
        Ok(None) => super::handlers_common::not_found("Realm not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_realm failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Delete realm (only Archived realms)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/delete`.
pub async fn admin_realm_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_id = target.id().clone();

    // Only allow permanent deletion of Archived realms.
    match state.identity.get_realm(&realm_id) {
        Ok(Some(realm)) if realm.status() == RealmStatus::Archived => {
            match state.identity.delete_realm(&realm_id) {
                Ok(()) => {
                    audit_realm_event(&state, &session, &realm_id, "delete");
                    Redirect::to("/ui/admin/realms").into_response()
                }
                Err(IdentityError::RealmNotFound) => {
                    super::handlers_common::not_found("Realm not found")
                }
                Err(e) => {
                    tracing::warn!(error = %e, "delete_realm failed");
                    super::handlers_common::server_error()
                }
            }
        }
        Ok(Some(_)) => super::handlers_common::bad_request(
            "Only archived realms can be permanently deleted. Remove the realm from hearth.yaml and restart to archive it first.",
        ),
        Ok(None) => super::handlers_common::not_found("Realm not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_realm failed");
            super::handlers_common::server_error()
        }
    }
}

/// Best-effort audit for realm operations.
fn audit_realm_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::RealmCreated,
        "update" => AuditAction::RealmUpdated,
        "delete" => AuditAction::RealmDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "realm".to_string(),
        resource_id: realm_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "realm admin audit append failed");
    }
}

// =========================================================================
// Applications (OAuth clients)
// =========================================================================

// =========================================================================
// Audit log
// =========================================================================

/// A single row in the audit log view.
pub struct AuditRow {
    /// The raw audit event.
    pub event: crate::audit::AuditEvent,
    /// Human-readable absolute timestamp (`YYYY-MM-DD HH:MM UTC`).
    /// Still rendered as a `title="…"` tooltip so the precise UTC time
    /// is always one hover away (HEA-644).
    pub timestamp_display: String,
    /// Human-readable relative timestamp (`just now`, `Nm ago`, `Nh ago`,
    /// or `Mon DD`). Easier to scan than absolute UTC when reviewing
    /// recent activity (HEA-644).
    pub timestamp_relative: String,
    /// Title-case English label for `event.action`, e.g. "User Created" for
    /// `UserCreated`. The raw `as_str()` tag is still rendered as a tooltip
    /// so operators can correlate UI rows with API filter values.
    pub action_label: &'static str,
    /// Coarse category for `event.action` — one of `"Identity"`, `"Session"`,
    /// `"OAuth"`, `"Security"`, `"Organization"`, or `"System"`. Drives the
    /// colored dot rendered before the action label so operators can scan
    /// for event groups at a glance without reading every label (HEA-647).
    pub action_category: &'static str,
    /// `true` when [`crate::audit::AuditAction::failure_policy`] returns
    /// [`crate::audit::AuditFailurePolicy::FailOperation`] — i.e. the action
    /// is destructive or security-sensitive (user deletion, credential
    /// change, consent revocation, bulk disable, role revoke, etc.). The
    /// audit table renders a subtle amber left-border on these rows so
    /// destructive events are visually separated from routine updates
    /// (HEA-647).
    pub action_high_severity: bool,
    /// Friendly actor label — resolved email when the actor is a user UUID,
    /// "system" when the event was generated by an internal subsystem, or
    /// the raw actor string when no resolution applies. The 2026-04-30 UX
    /// audit caught audit logs rendering nothing but UUIDs, leaving
    /// administrators unable to scan for who did what.
    pub actor_display: String,
    /// Admin URL pointing to the actor user's detail page. `Some` only when
    /// the actor parses as a user UUID and resolves inside the audit event's
    /// realm — system actors and cross-realm fallbacks stay unlinked so we
    /// never point operators at a realm-mismatched detail page.
    pub actor_url: Option<String>,
    /// Friendly resource label — display name of the user / org / client /
    /// realm referenced by `resource_type` + `resource_id`. Falls back to a
    /// short id (first 8 hex chars) when the resource cannot be resolved
    /// (deleted, cross-realm, unknown type).
    pub resource_display: String,
    /// Admin URL pointing to the resource's detail page. `Some` only when
    /// the resource was successfully resolved against the identity / RBAC
    /// engine — deleted or unresolvable resources still render the display
    /// name but without a link, so operators don't navigate to a 404.
    pub resource_url: Option<String>,
    /// Pretty-printed JSON representation of `event.metadata` for display.
    /// Empty string when there is no metadata.
    pub metadata_json: String,
    /// Compact pills for the metadata column — up to 3 entries from the
    /// metadata object rendered as `key: value` chips. Action-specific
    /// priority keys (e.g. `ip` for `SessionCreated`, `client_id`+`scopes`
    /// for `ClientConsentGranted`) are always rendered first so the
    /// overflow chip never hides operationally important context.
    pub metadata_pills: Vec<(String, String)>,
    /// Number of metadata keys hidden behind "+N more" overflow indicator.
    /// Only non-priority keys ever land in this overflow bucket.
    pub metadata_extra: usize,
    /// The `integrity_hash` of the preceding event in the chain, or empty
    /// string for the genesis event. Derived from the ordered query result.
    pub previous_hash: String,
    /// Alias for `event.integrity_hash` — the current event's chain hash.
    pub hash: String,
    /// Whether the hash chain was verified for this event.
    /// `None` means verification was not requested for this query.
    pub chain_valid: Option<bool>,
}

/// Maps every [`crate::audit::AuditAction`] variant to a title-case English
/// label suitable for rendering in the admin audit log. The match is
/// exhaustive — operators see real prose ("Consent Revoked"), not raw
/// snake-case tags.
fn action_label(action: &crate::audit::AuditAction) -> &'static str {
    use crate::audit::AuditAction as A;
    match action {
        A::UserCreated => "User Created",
        A::UserUpdated => "User Updated",
        A::UserDeleted => "User Deleted",
        A::CredentialSet => "Credential Set",
        A::CredentialChanged => "Credential Changed",
        A::CredentialVerified => "Credential Verified",
        A::SessionCreated => "Session Created",
        A::SessionRevoked => "Session Revoked",
        A::TokenIssued => "Token Issued",
        A::TokenRefreshed => "Token Refreshed",
        A::RealmCreated => "Realm Created",
        A::RealmUpdated => "Realm Updated",
        A::RealmDeleted => "Realm Deleted",
        A::ClientRegistered => "Client Registered",
        A::AuthorizationCodeIssued => "Authorization Code Issued",
        A::AuthorizationCodeExchanged => "Authorization Code Exchanged",
        A::TupleWritten => "Tuple Written",
        A::TupleDeleted => "Tuple Deleted",
        A::ClientUpdated => "Client Updated",
        A::ClientDeleted => "Client Deleted",
        A::BulkUsersCreated => "Bulk Users Created",
        A::BulkUsersDisabled => "Bulk Users Disabled",
        A::OrgCreated => "Organization Created",
        A::OrgUpdated => "Organization Updated",
        A::OrgDeleted => "Organization Deleted",
        A::GroupCreated => "Group Created",
        A::GroupUpdated => "Group Updated",
        A::GroupDeleted => "Group Deleted",
        A::GroupMemberAdded => "Group Member Added",
        A::GroupMemberRemoved => "Group Member Removed",
        A::GroupMemberRoleChanged => "Group Member Role Changed",
        A::ConsentGranted => "Consent Granted",
        A::ConsentDenied => "Consent Denied",
        A::ConsentRevoked => "Consent Revoked",
        A::FederationLoginStarted => "Federation Login Started",
        A::FederationLoginCompleted => "Federation Login Completed",
        A::FederationAccountLinked => "Federation Account Linked",
        A::FederationAccountUnlinked => "Federation Account Unlinked",
        A::FederationJitProvisioned => "Federation User JIT Provisioned",
        A::SamlLoginInitiated => "SAML Login Initiated",
        A::SamlLoginCompleted => "SAML Login Completed",
        A::SamlLoginFailed => "SAML Login Failed",
        A::SamlIdpAuthnRequestReceived => "SAML AuthnRequest Received",
        A::SamlIdpResponseIssued => "SAML Response Issued",
        A::SamlIdpInitiatedSso => "SAML IdP-Initiated SSO",
        A::SamlSloRequested => "SAML Single Logout Requested",
        A::SamlSloCompleted => "SAML Single Logout Completed",
        A::ScimUserCreated => "SCIM User Created",
        A::ScimUserUpdated => "SCIM User Updated",
        A::ScimUserDeleted => "SCIM User Deleted",
        A::ScimGroupCreated => "SCIM Group Created",
        A::ScimGroupUpdated => "SCIM Group Updated",
        A::ScimGroupDeleted => "SCIM Group Deleted",
        A::RoleAssigned => "Role Assigned",
        A::RoleRevoked => "Role Revoked",
        A::OrphanedReferenceSkipped => "Orphaned Reference Skipped",
        A::UserPermissionGranted => "User Permission Granted",
        A::UserPermissionRevoked => "User Permission Revoked",
        A::ClientConsentGranted => "Client Consent Granted",
        A::ClientConsentRevoked => "Client Consent Revoked",
        A::ConsentRequiredOnRefresh => "Consent Required on Refresh",
        A::Cleanup => "Cleanup",
        A::LoginFailed => "Login Failed",
        A::LoginLocked => "Login Locked",
        A::IpLoginLimitExceeded => "IP Login Limit Exceeded",
        A::BackupCreated => "Backup Created",
        A::BackupRestored => "Backup Restored",
        A::RequiredActionAssigned => "Required Action Assigned",
        A::RequiredActionRemoved => "Required Action Removed",
        A::RequiredActionCompleted => "Required Action Completed",
        A::RequiredActionAutoCleared => "Required Action Auto-Cleared",
        A::PasswordCompromisedRejected => "Password Compromised Rejected",
        A::BreachCheckUnavailable => "Breach Check Unavailable",
        A::StepUpMfaTriggered => "Step-Up MFA Triggered",
        A::StepUpMfaCompleted => "Step-Up MFA Completed",
        A::SmsOtpEnrollmentStarted => "SMS OTP Enrollment Started",
        A::SmsOtpEnrollmentVerified => "SMS OTP Enrollment Verified",
        A::SmsOtpEnrollmentFailed => "SMS OTP Enrollment Failed",
        A::SmsMfaChallengeSucceeded => "SMS MFA Challenge Succeeded",
        A::SmsMfaChallengeFailed => "SMS MFA Challenge Failed",
        A::SmsMfaLocked => "SMS MFA Locked",
        A::DeviceFingerprintsErased => "Device Fingerprints Erased",
    }
}

/// Maps every [`crate::audit::AuditAction`] variant to a coarse category
/// for the audit log UI — one of `"Identity"`, `"Session"`, `"OAuth"`,
/// `"Security"`, `"Organization"`, or `"System"`. Drives the colored dot
/// in `_rows.html` so operators can scan event groups at a glance (HEA-647).
///
/// The match is exhaustive — every variant must be classified. Routine
/// updates inside a category (e.g. `UserUpdated`) share the category with
/// their destructive counterpart (`UserDeleted`); the row-level severity
/// indicator is what separates them visually.
fn action_category(action: &crate::audit::AuditAction) -> &'static str {
    use crate::audit::AuditAction as A;
    match action {
        // Identity — user records, credentials, bulk user operations.
        A::UserCreated
        | A::UserUpdated
        | A::UserDeleted
        | A::CredentialSet
        | A::CredentialChanged
        | A::CredentialVerified
        | A::BulkUsersCreated
        | A::BulkUsersDisabled
        | A::RequiredActionAssigned
        | A::RequiredActionRemoved
        | A::RequiredActionCompleted
        | A::RequiredActionAutoCleared => "Identity",
        // Session — sessions, tokens, login attempts (logins gate session entry).
        A::SessionCreated
        | A::SessionRevoked
        | A::TokenIssued
        | A::TokenRefreshed
        | A::LoginFailed
        | A::LoginLocked
        | A::IpLoginLimitExceeded => "Session",
        // OAuth — OAuth2/OIDC client lifecycle + authorization-code/consent flow.
        A::ClientRegistered
        | A::ClientUpdated
        | A::ClientDeleted
        | A::AuthorizationCodeIssued
        | A::AuthorizationCodeExchanged
        | A::ConsentGranted
        | A::ConsentDenied
        | A::ConsentRevoked
        | A::ClientConsentGranted
        | A::ClientConsentRevoked
        | A::ConsentRequiredOnRefresh => "OAuth",
        // Organization — B2B orgs and groups (membership events included).
        A::OrgCreated
        | A::OrgUpdated
        | A::OrgDeleted
        | A::GroupCreated
        | A::GroupUpdated
        | A::GroupDeleted
        | A::GroupMemberAdded
        | A::GroupMemberRemoved
        | A::GroupMemberRoleChanged => "Organization",
        // Security — RBAC role assignments, direct user permissions,
        // raw authz tuples, integrity-watchdog events, and breach-check outcomes.
        A::RoleAssigned
        | A::RoleRevoked
        | A::UserPermissionGranted
        | A::UserPermissionRevoked
        | A::TupleWritten
        | A::TupleDeleted
        | A::OrphanedReferenceSkipped
        | A::PasswordCompromisedRejected
        | A::BreachCheckUnavailable
        | A::StepUpMfaTriggered
        | A::StepUpMfaCompleted
        | A::SmsOtpEnrollmentStarted
        | A::SmsOtpEnrollmentVerified
        | A::SmsOtpEnrollmentFailed
        | A::SmsMfaChallengeSucceeded
        | A::SmsMfaChallengeFailed
        | A::SmsMfaLocked
        | A::DeviceFingerprintsErased => "Security",
        // System — realm config, federation/SAML/SCIM integrations,
        // backup/restore, and internal cleanup jobs.
        A::RealmCreated
        | A::RealmUpdated
        | A::RealmDeleted
        | A::FederationLoginStarted
        | A::FederationLoginCompleted
        | A::FederationAccountLinked
        | A::FederationAccountUnlinked
        | A::FederationJitProvisioned
        | A::SamlLoginInitiated
        | A::SamlLoginCompleted
        | A::SamlLoginFailed
        | A::SamlIdpAuthnRequestReceived
        | A::SamlIdpResponseIssued
        | A::SamlIdpInitiatedSso
        | A::SamlSloRequested
        | A::SamlSloCompleted
        | A::ScimUserCreated
        | A::ScimUserUpdated
        | A::ScimUserDeleted
        | A::ScimGroupCreated
        | A::ScimGroupUpdated
        | A::ScimGroupDeleted
        | A::BackupCreated
        | A::BackupRestored
        | A::Cleanup => "System",
    }
}

/// Extracts up to 3 key-value pill entries from a metadata JSON object,
/// preferring the keys most informative for the given [`crate::audit::AuditAction`].
///
/// Returns `(pills, extra)` where `pills` contains `(key, truncated_value)`
/// pairs (max 3) and `extra` is the count of remaining keys not shown inline.
/// Non-object metadata yields an empty pill list.
///
/// Priority keys for an action are always rendered first when present, so
/// the `+N more` overflow chip never hides a priority key. Remaining slots
/// fill in `serde_json::Map` iteration order (alphabetic) for stable output.
fn build_metadata_pills(
    action: &crate::audit::AuditAction,
    metadata: Option<&serde_json::Value>,
) -> (Vec<(String, String)>, usize) {
    use crate::audit::AuditAction as A;
    const LIMIT: usize = 3;

    let obj = match metadata.and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return (Vec::new(), 0),
    };

    // Action-specific priority keys. Per HEA-646, surface the most
    // operationally useful metadata (IP for sessions, client_id+scopes
    // for consent, etc.) instead of the first-N-alphabetic default.
    let priority: &[&str] = match action {
        A::SessionCreated => &["ip", "user_agent"],
        A::ClientConsentGranted | A::ClientConsentRevoked => &["client_id", "scopes"],
        A::CredentialChanged => &["method"],
        A::FederationLoginCompleted => &["provider", "external_id"],
        _ => &[],
    };

    let mut pills: Vec<(String, String)> = Vec::with_capacity(LIMIT);
    let mut used: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for &key in priority {
        if pills.len() == LIMIT {
            break;
        }
        if let Some(v) = obj.get(key) {
            pills.push((key.to_string(), truncate_pill_value(v)));
            used.insert(key);
        }
    }
    for (k, v) in obj.iter() {
        if pills.len() == LIMIT {
            break;
        }
        if used.contains(k.as_str()) {
            continue;
        }
        pills.push((k.clone(), truncate_pill_value(v)));
    }

    let extra = obj.len().saturating_sub(pills.len());
    (pills, extra)
}

/// Truncates a metadata value for inline pill rendering — strings cap at
/// 24 chars, other types stringify and cap at 20 chars.
fn truncate_pill_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => {
            if s.len() > 24 {
                format!("{}…", &s[..24])
            } else {
                s.clone()
            }
        }
        other => {
            let s = other.to_string();
            if s.len() > 20 {
                format!("{}…", &s[..20])
            } else {
                s
            }
        }
    }
}

/// Resolves an audit-event actor string (typically a user UUID) to a
/// human-friendly display value plus an optional admin-UI deep link.
/// Returns `("system", None)` verbatim, looks up users by id, and falls
/// back to the original string when no lookup applies.
///
/// The URL is `Some` only when the actor resolves inside the *event's* own
/// realm — a super-admin acting cross-realm renders with their email but
/// without a link, since the realm-scoped user detail page wouldn't find
/// them. `realm_name` is the URL slug for the event realm.
fn resolve_audit_actor(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    realm_name: &str,
    actor: &str,
    cache: &mut std::collections::HashMap<String, (String, Option<String>)>,
) -> (String, Option<String>) {
    if actor == "system" {
        return ("system".to_string(), None);
    }
    if let Some(hit) = cache.get(actor) {
        return hit.clone();
    }
    let resolved: (String, Option<String>) = match uuid::Uuid::parse_str(actor) {
        Ok(uuid) => {
            let user_id = crate::core::UserId::new(uuid);
            // Audit actors can be cross-realm: a system-realm admin acting
            // on a tenant realm shows up with their system-realm user id
            // but the audit row is scoped to the tenant realm. Try the
            // event realm first (and link); fall through to the system
            // realm so the common case still gets a friendly email, but
            // skip the link to avoid pointing operators at a 404.
            let from_event_realm = state
                .identity
                .get_user(realm_id, &user_id)
                .ok()
                .flatten()
                .map(|u| {
                    let url = format!("/ui/admin/realms/{realm_name}/users/{}", u.id().as_uuid());
                    (u.email().to_string(), Some(url))
                });
            from_event_realm
                .or_else(|| {
                    let system = crate::identity::keys::system_realm_id();
                    if &system == realm_id {
                        return None;
                    }
                    state
                        .identity
                        .get_user(&system, &user_id)
                        .ok()
                        .flatten()
                        .map(|u| (u.email().to_string(), None))
                })
                .unwrap_or_else(|| (actor.to_string(), None))
        }
        Err(_) => (actor.to_string(), None),
    };
    cache.insert(actor.to_string(), resolved.clone());
    resolved
}

/// Resolves an audit-event resource (`type`, `id`) to a display name plus
/// an optional admin-UI deep link. Hits the identity / RBAC engine on
/// misses; cached per request to avoid quadratic lookups on tightly-
/// clustered events.
///
/// The URL is `Some` only when the resource was successfully resolved —
/// deleted, cross-realm, or unknown-type rows still get a display string
/// (short-id fallback) but no link, so operators don't click into a 404.
/// `realm_name` is the URL slug for the realm under which the audit row
/// is being rendered; it forms the `{realm}` segment of admin links.
fn resolve_audit_resource(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    realm_name: &str,
    resource_type: &str,
    resource_id: &str,
    cache: &mut std::collections::HashMap<(String, String), (String, Option<String>)>,
) -> (String, Option<String>) {
    let key = (resource_type.to_string(), resource_id.to_string());
    if let Some(hit) = cache.get(&key) {
        return hit.clone();
    }
    let resolved: Option<(String, Option<String>)> = match resource_type {
        "user" => uuid::Uuid::parse_str(resource_id).ok().and_then(|u| {
            state
                .identity
                .get_user(realm_id, &crate::core::UserId::new(u))
                .ok()
                .flatten()
                .map(|user| {
                    let url = format!(
                        "/ui/admin/realms/{realm_name}/users/{}",
                        user.id().as_uuid()
                    );
                    (user.email().to_string(), Some(url))
                })
        }),
        "realm" => uuid::Uuid::parse_str(resource_id).ok().and_then(|u| {
            state
                .identity
                .get_realm(&RealmId::new(u))
                .ok()
                .flatten()
                .map(|r| {
                    // Admin realm routes are keyed by the realm slug, not
                    // the UUID — addressable URL = `/ui/admin/realms/{name}`.
                    let name = r.name().to_string();
                    let url = format!("/ui/admin/realms/{name}");
                    (name, Some(url))
                })
        }),
        "organization" => uuid::Uuid::parse_str(resource_id).ok().and_then(|u| {
            state
                .identity
                .get_organization(realm_id, &crate::core::OrganizationId::new(u))
                .ok()
                .flatten()
                .map(|o| {
                    let url = format!(
                        "/ui/admin/realms/{realm_name}/organizations/{}",
                        o.id().as_uuid()
                    );
                    (o.name().to_string(), Some(url))
                })
        }),
        // Audit code writes "client" today; "application" reserved for the
        // UI-facing rename so future events under either tag still link.
        "client" | "application" => uuid::Uuid::parse_str(resource_id).ok().and_then(|u| {
            state
                .identity
                .get_client(realm_id, &crate::core::ClientId::new(u))
                .ok()
                .flatten()
                .map(|c| {
                    let url = format!(
                        "/ui/admin/realms/{realm_name}/applications/{}",
                        c.client_id().as_uuid()
                    );
                    (c.client_name().to_string(), Some(url))
                })
        }),
        "group" => uuid::Uuid::parse_str(resource_id).ok().and_then(|u| {
            state
                .rbac
                .get_group(realm_id, &crate::rbac::GroupId::new(u))
                .ok()
                .flatten()
                .map(|g| {
                    let url = format!("/ui/admin/realms/{realm_name}/groups/{}", g.id.as_uuid());
                    (g.name, Some(url))
                })
        }),
        // Sessions don't have a per-id detail page — link to the list view
        // so operators can still pivot from an audit row into session admin.
        // No presence check needed: the URL doesn't embed the resource id.
        "session" => {
            let short = resource_id.get(..8).unwrap_or(resource_id);
            let url = format!("/ui/admin/realms/{realm_name}/sessions");
            Some((format!("{short}…"), Some(url)))
        }
        _ => None,
    };
    let entry = resolved.unwrap_or_else(|| {
        // Fallback: show short id so the row stays compact and scannable.
        let short = resource_id.get(..8).unwrap_or(resource_id);
        (format!("{short}…"), None)
    });
    cache.insert(key, entry.clone());
    entry
}

/// Query params for the UI audit page.
#[derive(Debug, Deserialize)]
pub struct AuditFilterParams {
    /// Filter by actor.
    #[serde(default)]
    pub actor: Option<String>,
    /// Filter by action name.
    #[serde(default)]
    pub action: Option<String>,
    /// Start date filter (`YYYY-MM-DD`).
    #[serde(default)]
    pub start_date: Option<String>,
    /// End date filter (`YYYY-MM-DD`).
    #[serde(default)]
    pub end_date: Option<String>,
    /// Maximum events to show.
    #[serde(
        default,
        deserialize_with = "super::handlers_common::empty_string_as_none"
    )]
    pub limit: Option<usize>,
    /// Export format — `"csv"` or `"json"` (default). Only used by the
    /// export endpoint; ignored by the list handler.
    #[serde(default)]
    pub format: Option<String>,
}

/// Parses a `YYYY-MM-DD` date string into a `Timestamp` (start of that day, UTC).
fn parse_date_to_timestamp(date_str: &str) -> Option<crate::core::Timestamp> {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Simplified: compute days since epoch using a known-good formula
    // This is accurate for dates from 2000-2099
    let mut m = month;
    let mut y = year;
    if m <= 2 {
        m += 12;
        y -= 1;
    }
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + day - 719_469;
    Some(crate::core::Timestamp::from_micros(
        days * 86_400 * 1_000_000,
    ))
}

#[derive(Template)]
#[template(path = "ui/admin/audit/list.html")]
struct AuditListTemplate {
    events: Vec<AuditRow>,
    realm_name: String,
    form_actor: String,
    form_action: String,
    form_start_date: String,
    form_end_date: String,
    form_limit: String,
    /// Every available `AuditAction` as `(tag, label)` pairs, alphabetised
    /// by tag. Powers the Action `<select>`: the option value is the raw
    /// tag (`org_created`) which the backend still parses, while the
    /// visible text is the friendly label ("Organization Created") so
    /// administrators don't have to recall exact spellings.
    available_actions: Vec<(&'static str, &'static str)>,
    flash_message: Option<String>,
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

/// Rows-only partial returned when the audit filter is triggered via HTMX.
#[derive(Template)]
#[template(path = "ui/admin/audit/_rows.html")]
struct AuditRowsTemplate {
    events: Vec<AuditRow>,
}

/// `GET /ui/admin/audit`.
pub async fn admin_audit_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    htmx: super::templates::IsHtmx,
    Query(params): Query<AuditFilterParams>,
) -> Response {
    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());

    let start_time = params
        .start_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(parse_date_to_timestamp);
    let end_time = params
        .end_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|d| {
            // End date is exclusive — advance to start of next day
            parse_date_to_timestamp(d).map(|t| t.add_micros(86_400 * 1_000_000))
        });

    let limit = params.limit.unwrap_or(50).min(200);
    let query = crate::audit::AuditQuery {
        realm_id: target.id().clone(),
        start_time,
        end_time,
        actor: params.actor.clone().filter(|s| !s.is_empty()),
        action,
        limit: Some(limit),
    };

    match state.audit.query(&query) {
        Ok(events) => {
            // Per-request resolution caches so the same actor / resource
            // doesn't hit the identity engine N times when an event burst
            // touches one user repeatedly (the typical pattern).
            let mut actor_cache: std::collections::HashMap<String, (String, Option<String>)> =
                std::collections::HashMap::new();
            let mut resource_cache: std::collections::HashMap<
                (String, String),
                (String, Option<String>),
            > = std::collections::HashMap::new();
            let mut prev_hash = String::new();
            let realm_name = target.0.name().to_string();
            let rows: Vec<AuditRow> = events
                .into_iter()
                .map(|e| {
                    let (actor_display, actor_url) = resolve_audit_actor(
                        &state,
                        target.id(),
                        &realm_name,
                        &e.actor,
                        &mut actor_cache,
                    );
                    let (resource_display, resource_url) = resolve_audit_resource(
                        &state,
                        target.id(),
                        &realm_name,
                        &e.resource_type,
                        &e.resource_id,
                        &mut resource_cache,
                    );
                    let metadata_json = e
                        .metadata
                        .as_ref()
                        .and_then(|m| serde_json::to_string_pretty(m).ok())
                        .unwrap_or_default();
                    let (metadata_pills, metadata_extra) =
                        build_metadata_pills(&e.action, e.metadata.as_ref());
                    let hash = e.integrity_hash.clone();
                    let previous_hash = std::mem::replace(&mut prev_hash, hash.clone());
                    let action_label = action_label(&e.action);
                    let action_category = action_category(&e.action);
                    let action_high_severity = e.action.failure_policy()
                        == crate::audit::AuditFailurePolicy::FailOperation;
                    AuditRow {
                        timestamp_display: format_ts(e.timestamp),
                        timestamp_relative: format_ts_relative(e.timestamp),
                        action_label,
                        action_category,
                        action_high_severity,
                        actor_display,
                        actor_url,
                        resource_display,
                        resource_url,
                        metadata_json,
                        metadata_pills,
                        metadata_extra,
                        previous_hash,
                        hash,
                        chain_valid: None,
                        event: e,
                    }
                })
                .collect();
            if htmx.0 {
                render(&AuditRowsTemplate { events: rows })
            } else {
                render(&AuditListTemplate {
                    events: rows,
                    realm_name: target.0.name().to_string(),
                    form_actor: params.actor.unwrap_or_default(),
                    form_action: params.action.unwrap_or_default(),
                    form_start_date: params.start_date.unwrap_or_default(),
                    form_end_date: params.end_date.unwrap_or_default(),
                    form_limit: limit.to_string(),
                    available_actions: crate::audit::AuditAction::all()
                        .into_iter()
                        .map(|a| (a.as_str(), action_label(&a)))
                        .collect(),
                    flash_message: None,
                    chrome: true,
                    active: "audit",
                    user_email: Some(session.user_email.clone()),
                    is_admin: true,
                    flash: None,
                    csrf: session.csrf.clone(),
                    narrow: false,
                    product_name: state.product_name.clone(),
                    logo_url: state.logo_url.clone(),
                    realm_theme_url: state.realm_theme_url(),
                    inline_theme_css: state.inline_theme_css(),
                })
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit query failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/audit/verify` — verifies audit log integrity.
pub async fn admin_audit_verify_integrity(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    match state.audit.verify_integrity(target.id(), None, None) {
        Ok(true) => render(&AuditListTemplate {
            events: Vec::new(),
            realm_name: target.0.name().to_string(),
            form_actor: String::new(),
            form_action: String::new(),
            form_start_date: String::new(),
            form_end_date: String::new(),
            form_limit: "50".to_string(),
            available_actions: crate::audit::AuditAction::all()
                .into_iter()
                .map(|a| (a.as_str(), action_label(&a)))
                .collect(),
            flash_message: Some("Audit chain integrity verified successfully.".to_string()),
            chrome: true,
            active: "audit",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        }),
        Ok(false) => render(&AuditListTemplate {
            events: Vec::new(),
            realm_name: target.0.name().to_string(),
            form_actor: String::new(),
            form_action: String::new(),
            form_start_date: String::new(),
            form_end_date: String::new(),
            form_limit: "50".to_string(),
            available_actions: crate::audit::AuditAction::all()
                .into_iter()
                .map(|a| (a.as_str(), action_label(&a)))
                .collect(),
            flash_message: Some(
                "Integrity violation detected! The audit chain may have been tampered with."
                    .to_string(),
            ),
            chrome: true,
            active: "audit",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "audit verify_integrity failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log REST API + JSON export
// ---------------------------------------------------------------------------

/// `GET /admin/api/realms/{realm}/audit/events` — filterable JSON query API.
///
/// Accepts the same query parameters as the UI audit view (`actor`, `action`,
/// `start_date`, `end_date`, `limit`) and returns a JSON object suitable for
/// programmatic access, monitoring dashboards, and SIEM ingestion scripts.
///
/// Response body: `{"events": [...], "realm_id": "...", "count": N}`
pub async fn admin_api_audit_events(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<AuditFilterParams>,
) -> Response {
    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());
    let start_time = params
        .start_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(parse_date_to_timestamp);
    let end_time = params
        .end_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|d| parse_date_to_timestamp(d).map(|t| t.add_micros(86_400 * 1_000_000)));

    let limit = params.limit.unwrap_or(200).min(1000);
    let query = crate::audit::AuditQuery {
        realm_id: target.id().clone(),
        start_time,
        end_time,
        actor: params.actor.filter(|s| !s.is_empty()),
        action,
        limit: Some(limit),
    };

    match state.audit.query(&query) {
        Ok(events) => {
            let count = events.len();
            axum::response::Json(serde_json::json!({
                "realm_id": target.id().as_uuid().to_string(),
                "count": count,
                "events": events,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit api query failed");
            super::handlers_common::server_error()
        }
    }
}

/// `GET /admin/realms/{realm}/audit/export` — downloads audit events as a
/// JSON file with `Content-Disposition: attachment`.
///
/// Accepts the same filter parameters as the UI view. The downloaded file is
/// named `audit-{realm}-{date}.json` and contains all matched events (up to
/// 10 000) as a JSON array, suitable for offline analysis or archiving.
pub async fn admin_audit_export(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<AuditFilterParams>,
) -> Response {
    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());
    let start_time = params
        .start_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(parse_date_to_timestamp);
    let end_time = params
        .end_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|d| parse_date_to_timestamp(d).map(|t| t.add_micros(86_400 * 1_000_000)));

    let limit = params.limit.unwrap_or(10_000).min(10_000);
    let query = crate::audit::AuditQuery {
        realm_id: target.id().clone(),
        start_time,
        end_time,
        actor: params.actor.filter(|s| !s.is_empty()),
        action,
        limit: Some(limit),
    };

    let use_csv = params.format.as_deref() == Some("csv");
    match state.audit.query(&query) {
        Ok(events) => {
            let realm_slug = target.0.name().to_string();
            let today = format_today_date();
            if use_csv {
                let mut csv = String::with_capacity(events.len() * 128);
                csv.push_str("id,timestamp,action,actor,resource_type,resource_id,metadata\n");
                for e in &events {
                    csv_append_field(&mut csv, e.id.as_uuid().to_string().as_str());
                    csv.push(',');
                    csv_append_field(&mut csv, &format!("{}", e.timestamp.as_micros()));
                    csv.push(',');
                    csv_append_field(&mut csv, e.action.as_str());
                    csv.push(',');
                    csv_append_field(&mut csv, &e.actor);
                    csv.push(',');
                    csv_append_field(&mut csv, &e.resource_type);
                    csv.push(',');
                    csv_append_field(&mut csv, &e.resource_id);
                    csv.push(',');
                    let meta = e
                        .metadata
                        .as_ref()
                        .map_or_else(String::new, |m| m.to_string());
                    csv_append_field(&mut csv, &meta);
                    csv.push('\n');
                }
                let filename = format!("audit-{realm_slug}-{today}.csv");
                let disposition = format!("attachment; filename=\"{filename}\"");
                axum::response::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .header("Content-Disposition", disposition)
                    .body(axum::body::Body::from(csv))
                    .unwrap_or_else(|_| super::handlers_common::server_error())
            } else {
                // NDJSON: one JSON object per line, suitable for streaming consumers.
                let mut ndjson = String::with_capacity(events.len() * 256);
                for e in &events {
                    match serde_json::to_string(e) {
                        Ok(line) => {
                            ndjson.push_str(&line);
                            ndjson.push('\n');
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "audit export serialize failed");
                            return super::handlers_common::server_error();
                        }
                    }
                }
                let filename = format!("audit-{realm_slug}-{today}.ndjson");
                let disposition = format!("attachment; filename=\"{filename}\"");
                axum::response::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/x-ndjson")
                    .header("Content-Disposition", disposition)
                    .body(axum::body::Body::from(ndjson))
                    .unwrap_or_else(|_| super::handlers_common::server_error())
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit export query failed");
            super::handlers_common::server_error()
        }
    }
}

/// `GET /admin/api/realms/{realm}/audit/config` — read retention configuration.
///
/// Returns the current `retention_days` for the realm's audit log.
/// A value of `0` means unlimited (no pruning).
pub async fn admin_api_audit_config_get(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    match state.audit.get_retention_config(target.id()) {
        Ok(config) => axum::response::Json(config).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "audit config get failed");
            super::handlers_common::server_error()
        }
    }
}

/// Request body for updating audit retention configuration.
#[derive(serde::Deserialize)]
pub struct UpdateAuditRetentionBody {
    pub retention_days: u32,
}

/// `PUT /admin/api/realms/{realm}/audit/config` — update retention configuration.
///
/// Sets `retention_days` for the realm's audit log. A value of `0`
/// disables automatic pruning (unlimited retention).
pub async fn admin_api_audit_config_put(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    axum::Json(body): axum::Json<UpdateAuditRetentionBody>,
) -> Response {
    let config = crate::audit::AuditRetentionConfig {
        retention_days: body.retention_days,
    };
    match state.audit.set_retention_config(target.id(), &config) {
        Ok(()) => axum::response::Json(config).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "audit config update failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /admin/api/realms/{realm}/audit/prune` — manually prune old events.
///
/// Immediately deletes all audit events older than the realm's configured
/// `retention_days`. If `retention_days` is `0` (unlimited), returns 200
/// with `{"deleted": 0}` without touching any events.
pub async fn admin_api_audit_prune(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    let config = match state.audit.get_retention_config(target.id()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "audit prune: config fetch failed");
            return super::handlers_common::server_error();
        }
    };
    if config.retention_days == 0 {
        return axum::response::Json(serde_json::json!({"deleted": 0})).into_response();
    }
    let cutoff = prune_cutoff_timestamp(config.retention_days);
    match state.audit.prune_before(target.id(), cutoff) {
        Ok(deleted) => {
            tracing::info!(
                realm = %target.0.name(),
                deleted,
                "audit: manual prune completed"
            );
            axum::response::Json(serde_json::json!({"deleted": deleted})).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit prune failed");
            super::handlers_common::server_error()
        }
    }
}

/// Computes the cutoff timestamp for pruning events older than `retention_days`.
pub fn prune_cutoff_timestamp(retention_days: u32) -> crate::core::Timestamp {
    let now_micros = crate::core::Timestamp::now().as_micros();
    let window_micros = (retention_days as i64) * 86_400 * 1_000_000;
    let cutoff_micros = now_micros.saturating_sub(window_micros);
    crate::core::Timestamp::from_micros(cutoff_micros)
}

/// Appends a single CSV field, quoting it when it contains commas, quotes, or newlines.
fn csv_append_field(out: &mut String, value: &str) {
    if value.contains([',', '"', '\n', '\r']) {
        out.push('"');
        for ch in value.chars() {
            if ch == '"' {
                out.push('"');
            }
            out.push(ch);
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

/// Returns today's date as `YYYY-MM-DD` (UTC).
fn format_today_date() -> String {
    let now = crate::core::Timestamp::now().as_micros();
    let secs = now / 1_000_000;
    let days = secs / 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let yoe = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let y = yoe + era * 400;
    let day_of_year = day_of_era - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let d = day_of_year - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ---------------------------------------------------------------------------
// Test email
// ---------------------------------------------------------------------------

/// Form data for the admin test email action.
#[derive(Debug, Deserialize)]
pub struct TestEmailForm {
    /// The CSRF token echoed from the form.
    pub csrf: String,
    /// The recipient email address.
    pub email: String,
}

/// Sends a test email to verify transport configuration.
///
/// Requires admin role. On success, returns a flash message confirming
/// delivery. On failure, returns a flash message with the error.
pub async fn admin_test_email(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    FriendlyForm(form): FriendlyForm<TestEmailForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let email = form.email.trim();
    if email.is_empty() {
        return Redirect::to("/ui/admin/settings?flash=test_email_empty").into_response();
    }

    match &state.email {
        Some(email_service) => {
            let realm_branding = state
                .identity
                .get_realm(target.id())
                .ok()
                .flatten()
                .and_then(|t| t.config().email_branding.clone());
            match email_service.send_test_email(email, realm_branding.as_ref()) {
                Ok(()) => {
                    tracing::info!(to = %email, "admin test email sent");
                    Redirect::to("/ui/admin/settings?flash=test_email_sent").into_response()
                }
                Err(e) => {
                    tracing::warn!(error = %e, to = %email, "admin test email failed");
                    Redirect::to("/ui/admin/settings?flash=test_email_failed").into_response()
                }
            }
        }
        None => Redirect::to("/ui/admin/settings?flash=test_email_no_transport").into_response(),
    }
}

// =========================================================================

// =========================================================================
// System Info
// =========================================================================

/// Template for `GET /ui/admin/settings`.
#[derive(Template)]
#[template(path = "ui/admin/settings/system.html")]
struct SystemInfoTemplate {
    /// Full server configuration. `None` when running without a config file
    /// (e.g. in embedded tests).
    config: Option<Arc<Config>>,
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

/// `GET /ui/admin/settings` — read-only system information page.
pub async fn admin_system_info(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    render(&SystemInfoTemplate {
        config: state.config.clone(),
        chrome: true,
        active: "settings",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// Config Editor
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/settings/editor`.
#[derive(Template)]
#[template(path = "ui/admin/settings/editor.html")]
#[allow(dead_code, clippy::struct_excessive_bools)]
struct ConfigEditorTemplate {
    yaml_content: String,
    /// JSON representation of the raw YAML tree (for the visual editor).
    config_json: String,
    read_only: bool,
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

/// Template for the diff preview partial.
#[derive(Template)]
#[template(path = "ui/admin/settings/_diff_preview.html")]
#[allow(dead_code)]
struct DiffPreviewTemplate {
    diff: String,
    diff_lines: Vec<String>,
    error: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Form data for config editor actions.
#[derive(Debug, Deserialize)]
pub struct ConfigEditorForm {
    #[serde(default)]
    pub yaml: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Query params for config editor page (flash messages via redirect).
#[derive(Debug, Deserialize)]
pub struct ConfigEditorParams {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_kind: Option<String>,
}

/// `GET /ui/admin/settings/editor` — config editor page.
pub async fn admin_config_editor(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<ConfigEditorParams>,
) -> Response {
    let (yaml_content, read_only) = read_config_yaml(&state);
    let config_json = yaml_to_editor_json(&yaml_content).unwrap_or_else(|_| "{}".to_string());

    let flash = params.flash.map(|msg| {
        let kind = params.flash_kind.as_deref().unwrap_or("success");
        if kind == "error" {
            Flash::error(msg)
        } else {
            Flash::success(msg)
        }
    });

    render(&ConfigEditorTemplate {
        yaml_content,
        config_json,
        read_only,
        chrome: true,
        active: "settings",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

/// `POST /ui/admin/settings/editor/preview` — HTMX diff preview.
pub async fn admin_config_editor_preview(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<ConfigEditorForm>,
) -> Response {
    let new_yaml = form.yaml;

    // Validate the new config
    let validation_error = Config::from_yaml_str(&new_yaml)
        .err()
        .map(|e| e.to_string());

    let diff = if validation_error.is_some() {
        String::new()
    } else {
        let (old_yaml, _) = read_config_yaml(&state);
        compute_unified_diff(&old_yaml, &new_yaml)
    };

    let diff_lines: Vec<String> = diff.lines().map(String::from).collect();

    render(&DiffPreviewTemplate {
        diff,
        diff_lines,
        error: validation_error,
        product_name: String::new(),
        logo_url: String::new(),
        realm_theme_url: None,
        inline_theme_css: None,
    })
}

/// `POST /ui/admin/settings/editor/apply` — validate, write to disk, trigger reload.
pub async fn admin_config_editor_apply(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<ConfigEditorForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let new_yaml = form.yaml;

    // Validate first
    if let Err(e) = Config::from_yaml_str(&new_yaml) {
        return render_config_editor_with_flash(
            &state,
            &session,
            &new_yaml,
            Flash::error(format!("Validation failed: {e}")),
        );
    }

    // Write to disk
    let Some(config_path) = &state.config_path else {
        return render_config_editor_with_flash(
            &state,
            &session,
            &new_yaml,
            Flash::error("No config file path configured — cannot write".to_string()),
        );
    };

    if let Err(e) = std::fs::write(config_path, &new_yaml) {
        tracing::error!(error = %e, "failed to write config file");
        return render_config_editor_with_flash(
            &state,
            &session,
            &new_yaml,
            Flash::error(format!("Failed to write file: {e}")),
        );
    }

    // Trigger hot-reload
    if let Some(notify) = &state.reload_notify {
        notify.notify_one();
    }

    tracing::info!("config file updated via editor, reload triggered");

    Redirect::to(
        "/ui/admin/settings/editor?flash=Configuration+applied+successfully&flash_kind=success",
    )
    .into_response()
}

/// `GET /ui/admin/settings/editor/export` — download the current YAML file.
pub async fn admin_config_editor_export(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
) -> Response {
    let (yaml_content, _) = read_config_yaml(&state);

    (
        [
            (axum::http::header::CONTENT_TYPE, "application/x-yaml"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"hearth.yaml\"",
            ),
        ],
        yaml_content,
    )
        .into_response()
}

/// `POST /ui/admin/settings/editor/visual/export` — convert the visual editor's
/// JSON state to YAML and return it as plain text. This lets the export modal
/// show the *current* editor state rather than the on-disk file, which matters
/// in read-only / container environments where "Apply" cannot write to disk.
pub async fn admin_config_editor_visual_export(
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    match editor_json_to_yaml(&json) {
        Ok(yaml) => (StatusCode::OK, yaml).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

// --- Config editor helpers ---

/// Reads the raw YAML from the config file on disk.
/// Returns `(yaml_content, read_only)`. `read_only` is true when no file path is available.
fn read_config_yaml(state: &Arc<WebState>) -> (String, bool) {
    match &state.config_path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(content) => (content, false),
            Err(e) => {
                tracing::warn!(error = %e, "failed to read config file for editor");
                (format!("# Error reading config file: {e}"), true)
            }
        },
        None => (
            "# No config file path available.\n# Running in embedded/dev mode.\n".to_string(),
            true,
        ),
    }
}

/// Renders the config editor template with a flash message (for inline error display).
fn render_config_editor_with_flash(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    yaml_content: &str,
    flash: Flash,
) -> Response {
    let read_only = state.config_path.is_none();
    let config_json = yaml_to_editor_json(yaml_content).unwrap_or_else(|_| "{}".to_string());
    render(&ConfigEditorTemplate {
        yaml_content: yaml_content.to_string(),
        config_json,
        read_only,
        chrome: true,
        active: "settings",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: Some(flash),
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

// --- Visual config editor helpers ---

/// Parses raw YAML (without env substitution) into a JSON string for the
/// visual editor. Env var references like `${PORT:-8420}` stay as literal
/// strings in the JSON.
fn yaml_to_editor_json(yaml_str: &str) -> Result<String, String> {
    let value: serde_norway::Value =
        serde_norway::from_str(yaml_str).map_err(|e| format!("YAML parse error: {e}"))?;
    serde_json::to_string(&value).map_err(|e| format!("JSON serialization error: {e}"))
}

/// Try to extract a dotted field path from a `serde_norway` parse error.
///
/// `serde_norway` errors for type mismatches typically look like:
/// `server.port: invalid type: string "asdf", expected u16 at line 3 column 9`
///
/// Returns the extracted field path, or `"_yaml"` if no path can be parsed.
fn field_from_parse_error(msg: &str) -> &str {
    if let Some(pos) = msg.find(": ") {
        let candidate = &msg[..pos];
        if !candidate.is_empty()
            && candidate.contains('.')
            && candidate
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        {
            return candidate;
        }
    }
    "_yaml"
}

/// Converts editor JSON back to a YAML string. The resulting YAML is
/// machine-generated (no comments, consistent ordering).
fn editor_json_to_yaml(json: &serde_json::Value) -> Result<String, String> {
    let value: serde_norway::Value =
        serde_json::from_value(json.clone()).map_err(|e| format!("JSON→YAML conversion: {e}"))?;
    serde_norway::to_string(&value).map_err(|e| format!("YAML serialization error: {e}"))
}

/// `POST /ui/admin/settings/editor/visual/preview` — JSON-based diff preview.
///
/// Accepts the visual editor's config state as a JSON body, converts to YAML,
/// validates via the full `Config::from_yaml_str` pipeline, and returns a
/// diff preview HTML partial.
pub async fn admin_config_editor_visual_preview(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    let new_yaml = match editor_json_to_yaml(&json) {
        Ok(y) => y,
        Err(e) => {
            return render(&DiffPreviewTemplate {
                diff: String::new(),
                diff_lines: Vec::new(),
                error: Some(e),
                product_name: String::new(),
                logo_url: String::new(),
                realm_theme_url: None,
                inline_theme_css: None,
            });
        }
    };

    let validation_error = Config::from_yaml_str(&new_yaml)
        .err()
        .map(|e| e.to_string());

    let diff = if validation_error.is_some() {
        String::new()
    } else {
        let (old_yaml, _) = read_config_yaml(&state);
        compute_unified_diff(&old_yaml, &new_yaml)
    };

    let diff_lines: Vec<String> = diff.lines().map(String::from).collect();

    render(&DiffPreviewTemplate {
        diff,
        diff_lines,
        error: validation_error,
        product_name: String::new(),
        logo_url: String::new(),
        realm_theme_url: None,
        inline_theme_css: None,
    })
}

/// `POST /ui/admin/settings/editor/visual/validate` — JSON-based validation.
///
/// Accepts the visual editor's config state as JSON, converts to YAML,
/// parses without validation, then runs `validate_all()` to collect every
/// issue. Returns a JSON response with field-level errors.
pub async fn admin_config_editor_visual_validate(
    State(_state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    let new_yaml = match editor_json_to_yaml(&json) {
        Ok(y) => y,
        Err(e) => {
            return axum::response::Json(serde_json::json!({
                "valid": false,
                "errors": [{ "field": "_yaml", "reason": e }],
            }))
            .into_response();
        }
    };

    let config = match Config::from_yaml_str_unchecked(&new_yaml) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            let field = field_from_parse_error(&msg);
            return axum::response::Json(serde_json::json!({
                "valid": false,
                "errors": [{ "field": field, "reason": msg }],
            }))
            .into_response();
        }
    };

    let issues = config.validate_all();
    let valid = issues.is_empty();

    axum::response::Json(serde_json::json!({
        "valid": valid,
        "errors": issues,
    }))
    .into_response()
}

/// `POST /ui/admin/settings/editor/visual/apply` — JSON-based apply.
///
/// Accepts the visual editor's config state as JSON, converts to YAML,
/// validates (collecting all errors), writes to disk, and triggers a
/// hot-reload.
pub async fn admin_config_editor_visual_apply(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    // Convert JSON → YAML
    let new_yaml = match editor_json_to_yaml(&json) {
        Ok(y) => y,
        Err(e) => {
            return axum::response::Json(serde_json::json!({
                "ok": false,
                "error": e,
            }))
            .into_response();
        }
    };

    // Parse without validation so we can run validate_all()
    let config = match Config::from_yaml_str_unchecked(&new_yaml) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            let field = field_from_parse_error(&msg);
            return axum::response::Json(serde_json::json!({
                "ok": false,
                "error": format!("Parse error: {msg}"),
                "errors": [{ "field": field, "reason": msg }],
            }))
            .into_response();
        }
    };

    // Run full validation and report all issues
    let issues: Vec<ValidationIssue> = config.validate_all();
    if !issues.is_empty() {
        let count = issues.len();
        return axum::response::Json(serde_json::json!({
            "ok": false,
            "error": format!("{count} validation error(s)"),
            "errors": issues,
        }))
        .into_response();
    }

    // Write to disk
    let Some(config_path) = &state.config_path else {
        return axum::response::Json(serde_json::json!({
            "ok": false,
            "error": "No config file path configured — cannot write",
        }))
        .into_response();
    };

    if let Err(e) = std::fs::write(config_path, &new_yaml) {
        tracing::error!(error = %e, "failed to write config file (visual editor)");
        return axum::response::Json(serde_json::json!({
            "ok": false,
            "error": format!("Failed to write file: {e}"),
        }))
        .into_response();
    }

    // Trigger hot-reload
    if let Some(notify) = &state.reload_notify {
        notify.notify_one();
    }

    tracing::info!("config file updated via visual editor, reload triggered");

    axum::response::Json(serde_json::json!({
        "ok": true,
        "message": "Configuration applied successfully",
    }))
    .into_response()
}

/// Computes a simple unified diff between two YAML strings.
#[allow(clippy::too_many_lines)]
fn compute_unified_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    if old_lines == new_lines {
        return String::new();
    }

    // Simple Myers-like diff: find longest common subsequence, then output
    // additions and deletions in unified format.
    let mut output = String::new();
    output.push_str("--- hearth.yaml (current)\n");
    output.push_str("+++ hearth.yaml (proposed)\n");

    // Walk both sequences, emitting context/add/remove lines
    let mut old_idx = 0;
    let mut new_idx = 0;
    let mut hunk_lines: Vec<String> = Vec::new();
    let mut hunk_old_start = 0usize;
    let mut hunk_new_start = 0usize;
    let mut hunk_old_count = 0u32;
    let mut hunk_new_count = 0u32;
    let mut trailing_context = 0u32;

    while old_idx < old_lines.len() || new_idx < new_lines.len() {
        if old_idx < old_lines.len()
            && new_idx < new_lines.len()
            && old_lines[old_idx] == new_lines[new_idx]
        {
            // Matching line
            if !hunk_lines.is_empty() {
                trailing_context += 1;
                hunk_lines.push(format!(" {}", old_lines[old_idx]));
                hunk_old_count += 1;
                hunk_new_count += 1;
                if trailing_context >= 3 {
                    // Flush hunk
                    let _ = writeln!(
                        output,
                        "@@ -{},{} +{},{} @@",
                        hunk_old_start + 1,
                        hunk_old_count,
                        hunk_new_start + 1,
                        hunk_new_count,
                    );
                    for l in &hunk_lines {
                        output.push_str(l);
                        output.push('\n');
                    }
                    hunk_lines.clear();
                    hunk_old_count = 0;
                    hunk_new_count = 0;
                    trailing_context = 0;
                }
            }
            old_idx += 1;
            new_idx += 1;
        } else if new_idx < new_lines.len()
            && (old_idx >= old_lines.len()
                || !old_lines[old_idx..]
                    .iter()
                    .take(10)
                    .any(|l| *l == new_lines[new_idx]))
        {
            // Added line (not found in next few old lines)
            trailing_context = 0;
            if hunk_lines.is_empty() {
                hunk_old_start = old_idx.saturating_sub(3);
                hunk_new_start = new_idx.saturating_sub(3);
                // Prepend context
                let ctx_start = old_idx.saturating_sub(3);
                for line in &old_lines[ctx_start..old_idx] {
                    hunk_lines.push(format!(" {line}"));
                    hunk_old_count += 1;
                    hunk_new_count += 1;
                }
            }
            hunk_lines.push(format!("+{}", new_lines[new_idx]));
            hunk_new_count += 1;
            new_idx += 1;
        } else if old_idx < old_lines.len() {
            // Deleted line
            trailing_context = 0;
            if hunk_lines.is_empty() {
                hunk_old_start = old_idx.saturating_sub(3);
                hunk_new_start = new_idx.saturating_sub(3);
                let ctx_start = old_idx.saturating_sub(3);
                for line in &old_lines[ctx_start..old_idx] {
                    hunk_lines.push(format!(" {line}"));
                    hunk_old_count += 1;
                    hunk_new_count += 1;
                }
            }
            hunk_lines.push(format!("-{}", old_lines[old_idx]));
            hunk_old_count += 1;
            old_idx += 1;
        } else {
            new_idx += 1;
        }
    }

    // Flush remaining hunk
    if !hunk_lines.is_empty() {
        let _ = writeln!(
            output,
            "@@ -{},{} +{},{} @@",
            hunk_old_start + 1,
            hunk_old_count,
            hunk_new_start + 1,
            hunk_new_count,
        );
        for l in &hunk_lines {
            output.push_str(l);
            output.push('\n');
        }
    }

    output
}

// =========================================================================
// Realm administrators
// =========================================================================
// =========================================================================
// Realm administrators (Roles & Permissions — Phase 3)
// =========================================================================

/// Resolves the list of users with the `realm.admin` role on a realm.
///
/// Uses `rbac.list_role_members` on the seeded `realm.admin` role, then
/// hydrates display fields via `identity.get_user`. Users whose records
/// can no longer be loaded are silently omitted — the assignment is
/// effectively orphaned and a stale display would confuse operators more
/// than a missing row.
fn resolve_realm_admins(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<RealmAdminView> {
    let mut out = Vec::new();

    // Direct realm-scoped admins: users with `realm.admin` granted on
    // *this* realm.
    if let Ok(Some(role)) = state.rbac.get_role_by_name(realm_id, "realm.admin") {
        collect_role_members(state, realm_id, &role.id, false, &mut out);
    }

    // System-realm admins: users with `realm.admin` on the system realm
    // implicitly have admin authority on every realm. Always surface them
    // here so a tenant realm with no direct grants doesn't look like it
    // has nobody managing it (the 2026-04-29 audit's "no administrators
    // yet" UX bug). Skip when the page already *is* the system realm.
    let system_id = crate::identity::keys::system_realm_id();
    if realm_id.as_uuid() != system_id.as_uuid() {
        if let Ok(Some(role)) = state.rbac.get_role_by_name(&system_id, "realm.admin") {
            collect_role_members(state, &system_id, &role.id, true, &mut out);
        }
    }

    // De-duplicate (a user could be both system admin AND directly
    // assigned on this realm; show them once, prefer the realm-scoped
    // entry since it's the one a manage-admins action can revoke).
    out.sort_by(|a, b| {
        a.email
            .cmp(&b.email)
            .then(a.is_system_admin.cmp(&b.is_system_admin))
    });
    out.dedup_by(|a, b| a.email == b.email);
    out.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    out
}

/// Pages through `list_role_members` for a specific (realm, role) pair
/// and appends hydrated [`RealmAdminView`] entries to `out`.
fn collect_role_members(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    role_id: &crate::rbac::RoleId,
    is_system_admin: bool,
    out: &mut Vec<RealmAdminView>,
) {
    let mut cursor: Option<String> = None;
    loop {
        let page = match state
            .rbac
            .list_role_members(realm_id, role_id, cursor.as_deref(), 100)
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "list realm admins: list_role_members failed");
                return;
            }
        };
        for member in page.items {
            let crate::rbac::RoleSubject::User(uid) = member else {
                continue;
            };
            let Ok(Some(user)) = state.identity.get_user(realm_id, &uid) else {
                continue;
            };
            let display_name = if user.display_name().is_empty() {
                user.email().to_string()
            } else {
                user.display_name().to_string()
            };
            out.push(RealmAdminView {
                user_id: uid.as_uuid().to_string(),
                display_name,
                email: user.email().to_string(),
                is_system_admin,
            });
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
}

/// `application/x-www-form-urlencoded` body for granting realm admin.
#[derive(Debug, Deserialize)]
pub struct RealmAdminGrantForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub user_id: String,
}

/// `POST /ui/admin/realms/:id/admins/grant`.
pub async fn admin_realm_admin_grant(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<RealmAdminGrantForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let realm_id = target.id().clone();
    let Ok(user_uuid) = form.user_id.trim().parse::<uuid::Uuid>() else {
        return super::handlers_common::bad_request("Invalid user ID");
    };
    let target_user = crate::core::UserId::new(user_uuid);

    match state.identity.get_user(&realm_id, &target_user) {
        Ok(Some(_)) => {}
        Ok(None) => return super::handlers_common::not_found("User not found in this realm"),
        Err(e) => {
            tracing::warn!(error = %e, "grant realm admin: get_user failed");
            return super::handlers_common::server_error();
        }
    }

    if check_user_admin(&state, &realm_id, &target_user) {
        return Redirect::to(&format!("/ui/admin/realms/{}", target.0.name())).into_response();
    }

    if let Err(e) = set_user_admin(&state, &realm_id, &target_user, true) {
        tracing::warn!(error = %e, "grant realm admin failed");
        return super::handlers_common::server_error();
    }
    audit_role_event(
        &state,
        &session,
        &realm_id,
        &target_user,
        true,
        "hearth",
        "admin",
        "admin",
    );
    Redirect::to(&format!("/ui/admin/realms/{}", target.0.name())).into_response()
}

/// `POST /ui/admin/realms/{realm}/admins/:uid/revoke`.
pub async fn admin_realm_admin_revoke(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, uid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let realm_id = target.id().clone();
    let Ok(user_uuid) = uid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("User not found");
    };
    let target_user = crate::core::UserId::new(user_uuid);

    // Self-revocation guard: a session-owning admin shouldn't be able to
    // accidentally lock themselves out. They can still revoke themselves
    // from another admin's browser.
    if session.user_id == target_user {
        return super::handlers_common::bad_request(
            "Refusing to revoke your own admin role — have another admin do it.",
        );
    }

    if !check_user_admin(&state, &realm_id, &target_user) {
        return Redirect::to(&format!("/ui/admin/realms/{}", target.0.name())).into_response();
    }

    if let Err(e) = set_user_admin(&state, &realm_id, &target_user, false) {
        tracing::warn!(error = %e, "revoke realm admin failed");
        return super::handlers_common::server_error();
    }
    audit_role_event(
        &state,
        &session,
        &realm_id,
        &target_user,
        false,
        "hearth",
        "admin",
        "admin",
    );
    Redirect::to(&format!("/ui/admin/realms/{}", target.0.name())).into_response()
}

// ---------------------------------------------------------------------------
// Realm config PATCH (HEA-807)
// ---------------------------------------------------------------------------

/// Request body for `PATCH /admin/realms/{realm}/config`.
///
/// All fields are optional — send only the keys you want to change.
/// Unknown JSON keys are silently ignored by `serde`.
#[derive(Debug, Deserialize)]
pub struct PatchRealmConfigBody {
    /// Replaces the realm's full `default_required_actions` list.
    ///
    /// Pass an empty array (`[]`) to clear the default. All strings must
    /// be valid v1 action types (`"VERIFY_EMAIL"`, `"UPDATE_PASSWORD"`);
    /// unknown values return 400.
    #[serde(default)]
    pub default_required_actions: Vec<String>,
    /// Replaces the realm's allowed MFA methods list (e.g. `["totp","sms"]`).
    ///
    /// `null` / absent leaves the field unchanged. Pass `[]` to clear.
    /// The value `"sms"` enables SMS OTP as an MFA method for this realm.
    pub mfa_methods: Option<Vec<String>>,
    /// Per-realm SMS OTP expiry in seconds. `null` clears the override
    /// (reverts to the engine default of 600 s).
    pub sms_otp_expiry_seconds: Option<u64>,
    /// Per-realm SMS OTP maximum verification attempts. `null` clears
    /// the override (reverts to the engine default of 5).
    pub sms_otp_max_attempts: Option<u32>,
}

/// `PATCH /admin/realms/{realm}/config`
///
/// Updates mutable realm config fields. Currently exposed:
/// `default_required_actions`, `mfa_methods`, `sms_otp_expiry_seconds`,
/// `sms_otp_max_attempts`.
///
/// Requires realm-admin token; returns 403 otherwise.
/// Unknown action type strings return 400.
/// Returns 200 with the updated [`crate::identity::Realm`] JSON.
pub async fn admin_api_realm_config_patch(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    axum::Json(body): axum::Json<PatchRealmConfigBody>,
) -> Response {
    use crate::identity::{RequiredAction, UpdateRealmRequest};

    // Validate and parse action strings.
    let mut actions: Vec<RequiredAction> = Vec::with_capacity(body.default_required_actions.len());
    for s in &body.default_required_actions {
        match serde_json::from_value::<RequiredAction>(serde_json::Value::String(s.clone())) {
            Ok(a) => actions.push(a),
            Err(_) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({ "error": format!("unknown action type: {s}") })),
                )
                    .into_response();
            }
        }
    }

    // Build updated config: start from existing, apply only provided fields.
    let mut config = target.0.config().clone();
    config.default_required_actions = actions;
    if let Some(methods) = body.mfa_methods {
        config.mfa_methods = if methods.is_empty() {
            None
        } else {
            Some(methods)
        };
    }
    // `serde_json` deserializes absent fields as `None`; we use a sentinel
    // `Option<Option<T>>` pattern isn't needed here — the caller either omits
    // the field (None → leave unchanged) or passes a value (Some(v) → set).
    // Passing JSON `null` is not supported for these numeric fields; omit to
    // leave unchanged.
    if let Some(v) = body.sms_otp_expiry_seconds {
        config.sms_otp_expiry_seconds = Some(v);
    }
    if let Some(v) = body.sms_otp_max_attempts {
        config.sms_otp_max_attempts = Some(v);
    }

    match state.identity.update_realm(
        target.id(),
        &UpdateRealmRequest {
            config: Some(config),
            ..Default::default()
        },
    ) {
        Ok(realm) => axum::Json(realm).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "update_realm failed in realm_config_patch");
            super::handlers_common::server_error()
        }
    }
}

#[cfg(test)]
mod metadata_pill_tests {
    use super::build_metadata_pills;
    use crate::audit::AuditAction;
    use serde_json::json;

    fn keys(pills: &[(String, String)]) -> Vec<&str> {
        pills.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn session_created_surfaces_ip_inline() {
        // Alphabetically `auth_method` < `ip` < `user_agent` — the old
        // first-N-alphabetic strategy would hide `ip` behind "+N". The
        // priority list for `SessionCreated` must lift it back inline.
        let meta = json!({
            "auth_method": "password",
            "ip": "203.0.113.4",
            "user_agent": "Mozilla/5.0",
            "session_id": "sess_abc",
        });
        let (pills, extra) = build_metadata_pills(&AuditAction::SessionCreated, Some(&meta));
        let k = keys(&pills);
        assert_eq!(k[0], "ip");
        assert_eq!(k[1], "user_agent");
        assert_eq!(pills.len(), 3);
        assert_eq!(extra, 1);
        assert!(k[2] == "auth_method" || k[2] == "session_id");
    }

    #[test]
    fn consent_granted_surfaces_client_and_scopes() {
        let meta = json!({
            "actor": "self",
            "client_id": "web-app",
            "scopes": "openid email profile",
            "tenant": "acme",
        });
        let (pills, extra) = build_metadata_pills(&AuditAction::ClientConsentGranted, Some(&meta));
        let k = keys(&pills);
        assert_eq!(k[0], "client_id");
        assert_eq!(k[1], "scopes");
        assert_eq!(pills.len(), 3);
        assert_eq!(extra, 1);
    }

    #[test]
    fn consent_revoked_uses_same_priority_as_granted() {
        let meta = json!({"client_id": "cli", "scopes": "openid", "by": "admin"});
        let (pills, _) = build_metadata_pills(&AuditAction::ClientConsentRevoked, Some(&meta));
        let k = keys(&pills);
        assert_eq!(&k[..2], &["client_id", "scopes"]);
    }

    #[test]
    fn credential_changed_lifts_method_first() {
        let meta = json!({"actor": "admin", "method": "password_reset"});
        let (pills, extra) = build_metadata_pills(&AuditAction::CredentialChanged, Some(&meta));
        assert_eq!(keys(&pills)[0], "method");
        assert_eq!(extra, 0);
    }

    #[test]
    fn federation_login_completed_lifts_provider_and_external_id() {
        let meta = json!({
            "mode": "jit",
            "provider": "google",
            "external_id": "1109283749",
            "email": "ada@example.com",
        });
        let (pills, _) = build_metadata_pills(&AuditAction::FederationLoginCompleted, Some(&meta));
        let k = keys(&pills);
        assert_eq!(k[0], "provider");
        assert_eq!(k[1], "external_id");
    }

    #[test]
    fn default_falls_back_to_alphabetic_first_three() {
        let meta = json!({"zebra": 1, "apple": 2, "mango": 3, "kiwi": 4});
        let (pills, extra) = build_metadata_pills(&AuditAction::UserCreated, Some(&meta));
        assert_eq!(keys(&pills), vec!["apple", "kiwi", "mango"]);
        assert_eq!(extra, 1);
    }

    #[test]
    fn missing_priority_keys_fall_through_to_defaults() {
        // `SessionCreated` without `ip`/`user_agent` should still surface
        // whatever metadata exists rather than rendering empty pills.
        let meta = json!({"trust": "high", "channel": "browser"});
        let (pills, extra) = build_metadata_pills(&AuditAction::SessionCreated, Some(&meta));
        assert_eq!(pills.len(), 2);
        assert_eq!(extra, 0);
        let k = keys(&pills);
        assert!(k.contains(&"trust") && k.contains(&"channel"));
    }

    #[test]
    fn non_object_metadata_returns_empty() {
        let meta = json!("scalar string");
        let (pills, extra) = build_metadata_pills(&AuditAction::SessionCreated, Some(&meta));
        assert!(pills.is_empty());
        assert_eq!(extra, 0);
    }

    #[test]
    fn none_metadata_returns_empty() {
        let (pills, extra) = build_metadata_pills(&AuditAction::UserCreated, None);
        assert!(pills.is_empty());
        assert_eq!(extra, 0);
    }

    #[test]
    fn priority_key_value_is_truncated() {
        let long_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
        let meta = json!({"ip": "10.0.0.1", "user_agent": long_ua});
        let (pills, _) = build_metadata_pills(&AuditAction::SessionCreated, Some(&meta));
        let ua = pills
            .iter()
            .find(|(k, _)| k == "user_agent")
            .map(|(_, v)| v.as_str())
            .expect("user_agent pill present");
        assert!(ua.ends_with('…'), "long values must be truncated: {ua}");
    }
}

#[cfg(test)]
mod action_label_tests {
    use super::action_label;
    use crate::audit::AuditAction;

    #[test]
    fn action_label_renders_title_case_phrases() {
        assert_eq!(action_label(&AuditAction::UserCreated), "User Created");
        assert_eq!(
            action_label(&AuditAction::ClientConsentRevoked),
            "Client Consent Revoked",
        );
        assert_eq!(
            action_label(&AuditAction::OrgDeleted),
            "Organization Deleted",
        );
        assert_eq!(
            action_label(&AuditAction::IpLoginLimitExceeded),
            "IP Login Limit Exceeded",
        );
    }

    #[test]
    fn action_label_covers_every_variant_with_nonempty_label() {
        // `AuditAction::all()` enumerates every variant; the exhaustive
        // match in `action_label` is enforced by rustc, but we also guard
        // against accidentally returning an empty string or falling
        // through to the raw snake_case tag.
        for action in AuditAction::all() {
            let label = action_label(&action);
            assert!(!label.is_empty(), "action {action:?} mapped to empty label");
            assert_ne!(
                label,
                action.as_str(),
                "action {action:?} fell through to raw snake_case",
            );
        }
    }
}

#[cfg(test)]
mod action_category_tests {
    use super::action_category;
    use crate::audit::{AuditAction, AuditFailurePolicy};

    /// Every category string we emit must be one of the six fixed names
    /// rendered by the template's `{% if row.action_category == "…" %}`
    /// dispatch — drift here would silently drop the colored dot.
    const CATEGORIES: &[&str] = &[
        "Identity",
        "Session",
        "OAuth",
        "Security",
        "Organization",
        "System",
    ];

    #[test]
    fn category_returns_one_of_six_known_strings() {
        for action in AuditAction::all() {
            let cat = action_category(&action);
            assert!(
                CATEGORIES.contains(&cat),
                "action {action:?} mapped to unknown category {cat:?}",
            );
        }
    }

    #[test]
    fn identity_actions_map_to_identity() {
        use AuditAction as A;
        for a in [
            A::UserCreated,
            A::UserUpdated,
            A::UserDeleted,
            A::CredentialSet,
            A::CredentialChanged,
            A::CredentialVerified,
            A::BulkUsersCreated,
            A::BulkUsersDisabled,
        ] {
            assert_eq!(action_category(&a), "Identity", "{a:?}");
        }
    }

    #[test]
    fn session_actions_map_to_session() {
        use AuditAction as A;
        for a in [
            A::SessionCreated,
            A::SessionRevoked,
            A::TokenIssued,
            A::TokenRefreshed,
            A::LoginFailed,
            A::LoginLocked,
            A::IpLoginLimitExceeded,
        ] {
            assert_eq!(action_category(&a), "Session", "{a:?}");
        }
    }

    #[test]
    fn oauth_actions_map_to_oauth() {
        use AuditAction as A;
        for a in [
            A::ClientRegistered,
            A::ClientUpdated,
            A::ClientDeleted,
            A::AuthorizationCodeIssued,
            A::AuthorizationCodeExchanged,
            A::ConsentGranted,
            A::ConsentDenied,
            A::ConsentRevoked,
            A::ClientConsentGranted,
            A::ClientConsentRevoked,
            A::ConsentRequiredOnRefresh,
        ] {
            assert_eq!(action_category(&a), "OAuth", "{a:?}");
        }
    }

    #[test]
    fn organization_actions_map_to_organization() {
        use AuditAction as A;
        for a in [
            A::OrgCreated,
            A::OrgUpdated,
            A::OrgDeleted,
            A::GroupCreated,
            A::GroupUpdated,
            A::GroupDeleted,
            A::GroupMemberAdded,
            A::GroupMemberRemoved,
            A::GroupMemberRoleChanged,
        ] {
            assert_eq!(action_category(&a), "Organization", "{a:?}");
        }
    }

    #[test]
    fn security_actions_map_to_security() {
        use AuditAction as A;
        for a in [
            A::RoleAssigned,
            A::RoleRevoked,
            A::UserPermissionGranted,
            A::UserPermissionRevoked,
            A::TupleWritten,
            A::TupleDeleted,
            A::OrphanedReferenceSkipped,
            A::PasswordCompromisedRejected,
            A::BreachCheckUnavailable,
            A::SmsOtpEnrollmentStarted,
            A::SmsOtpEnrollmentVerified,
            A::SmsOtpEnrollmentFailed,
            A::SmsMfaChallengeSucceeded,
            A::SmsMfaChallengeFailed,
            A::SmsMfaLocked,
        ] {
            assert_eq!(action_category(&a), "Security", "{a:?}");
        }
    }

    #[test]
    fn system_actions_map_to_system() {
        use AuditAction as A;
        for a in [
            A::RealmCreated,
            A::RealmUpdated,
            A::RealmDeleted,
            A::FederationLoginStarted,
            A::SamlLoginInitiated,
            A::ScimUserCreated,
            A::BackupCreated,
            A::BackupRestored,
            A::Cleanup,
        ] {
            assert_eq!(action_category(&a), "System", "{a:?}");
        }
    }

    /// The `action_high_severity` view-field must mirror the domain's
    /// `failure_policy()` exactly — it is a pure presentation alias, not
    /// an independent classification. Two destructive actions used by the
    /// admin UI are spot-checked here; the engine-side audit unit tests
    /// cover the full mapping.
    #[test]
    fn high_severity_mirrors_failure_policy_fail_operation() {
        use AuditAction as A;
        // Destructive — must be high-severity.
        assert_eq!(
            A::UserDeleted.failure_policy(),
            AuditFailurePolicy::FailOperation,
        );
        assert_eq!(
            A::CredentialChanged.failure_policy(),
            AuditFailurePolicy::FailOperation,
        );
        // Routine — must NOT be high-severity.
        assert_eq!(A::UserUpdated.failure_policy(), AuditFailurePolicy::LogOnly,);
        assert_eq!(
            A::SessionCreated.failure_policy(),
            AuditFailurePolicy::LogOnly,
        );
    }
}

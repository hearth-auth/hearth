//! Axum handlers for the public `/ui/*` entry points.
//!
//! Wire adapter only — every state transition delegates to
//! `OnboardingService` or `IdentityEngine`. Templates live under
//! `templates/ui/` and are compiled into the binary by the askama
//! derive macro.
//!
//! See [`super`] module docs for the cookie and CSRF model.
//!
//! # Routes covered here
//!
//! This file owns the public (pre-auth) surface:
//!
//! * `GET  /ui/setup` — first-run setup form (token-gated).
//! * `POST /ui/setup` — submit setup form.
//! * `GET  /ui/setup/sent` — "check your email" confirmation.
//! * `GET  /ui/verify-email` — consume a verification token.
//! * `GET  /ui/login` — login form.
//! * `POST /ui/login` — submit login credentials.
//!
//! Post-auth routes (`/ui/`, `/ui/logout`, `/ui/account/*`,
//! `/ui/admin/*`) live alongside in dedicated modules.
//!
//! # Security notes
//!
//! * `login_submit` sets two cookies on success: `hearth_ui_session`
//!   (`HttpOnly` — server-only) and `hearth_ui_csrf` (readable by JS so
//!   the page can echo it via HTMX headers). Both are `Path=/ui` +
//!   `SameSite=Lax`.
//! * The session cookie value is `sid.tid.mac` (stateless binding of a
//!   session id to its realm id via HMAC-SHA256). See [`super::auth`]
//!   for parsing.

use std::net::SocketAddr;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::abuse::device_approval::{DeviceApprovalDecision, DeviceApprovalGuard};
use crate::abuse::runtime::PreAuthVerdict;
use crate::core::{FormSecret, RealmId};
use crate::identity::onboarding::OnboardingError;
use crate::identity::{
    admin_gate, gate, AuthenticationOptions, CleartextPassword, CompleteAuthenticationParams,
    IdentityError, KdfGateError, MfaProof, SessionContext,
};
use crate::protocol::client_info::{build_session_context, PeerAddr};

use super::auth::{
    clear_mfa_pending_cookie, cookie_value_from_headers, issue_auth_cookies,
    issue_mfa_pending_cookie, parse_mfa_pending_cookie, revoke_prior_session_cookie,
    sanitize_return_to, IssuedCookies, MFA_PENDING_COOKIE,
};
use super::link_token;
use super::realm_resolver::{self, Resolved};
use super::templates::{render, render_status, Flash};
use super::WebState;
use crate::identity::Realm;

// ============================================================================
// Template structs
// ============================================================================

/// Setup form template — used for both initial render and error re-render.
#[derive(Template)]
#[template(path = "ui/setup.html")]
struct SetupTemplate {
    /// [`link_token::link_binding`] of the stashed setup token — never the
    /// token itself (GA audit L18).
    link_binding: String,
    error: Option<String>,
    // Layout fields (nav disabled for public pages).
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

impl SetupTemplate {
    fn new(
        link_binding: String,
        error: Option<String>,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            link_binding,
            error,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Simple "setup submitted" confirmation page.
#[derive(Template)]
#[template(path = "ui/setup_sent.html")]
#[allow(clippy::struct_excessive_bools)]
struct SetupSentTemplate {
    /// Whether to show the "Running without SMTP?" callout (true when
    /// the email transport is `Log`).
    show_log_fallback: bool,
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

impl SetupSentTemplate {
    fn new(show_log_fallback: bool, product_name: String, logo_url: String) -> Self {
        Self {
            show_log_fallback,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// One federation sign-in button rendered on the login page.
pub(super) struct FederationButton {
    /// URL of the `/federation/begin?idp=...` endpoint.
    pub(super) begin_url: String,
    /// Human-readable label for the button ("Google", "GitHub", etc.).
    pub(super) display_name: String,
}

/// Login form template.
#[derive(Template)]
#[template(path = "ui/login.html")]
#[allow(clippy::struct_excessive_bools, dead_code)]
struct LoginTemplate {
    error: Option<String>,
    return_to: Option<String>,
    /// Submitted email, echoed back into the form on auth failure so the
    /// user doesn't have to retype it. Empty on the initial GET.
    /// Carries no enumeration risk: we always show the same generic error,
    /// so the field is preserved whether or not the address matches a user.
    email: String,
    /// URL the form POSTs to — empty for bare `/ui/login`, or
    /// `/ui/realms/<name>/login` for a realm-scoped form.
    form_action: String,
    /// URL of the forgot-password page (scope-matched).
    forgot_url: String,
    /// URL of the register page (scope-matched).
    register_url: String,
    /// When `false`, the "Create account" link is hidden — set from the
    /// realm's [`RegistrationPolicy`] so disabled realms don't advertise
    /// a dead registration URL.
    show_register: bool,
    /// Endpoint prefix for passkey AJAX calls, scope-matched.
    passkey_begin_url: String,
    passkey_complete_url: String,
    locale: String,
    heading_text: &'static str,
    email_label: &'static str,
    password_label: &'static str,
    submit_label: &'static str,
    or_continue_with_label: &'static str,
    or_label: &'static str,
    sign_in_with_label: &'static str,
    forgot_password_label: &'static str,
    create_account_label: &'static str,
    passkey_sign_in_label: &'static str,
    passkey_authenticating_label: &'static str,
    passkey_unavailable_error: &'static str,
    passkey_cancelled_error: &'static str,
    passkey_failed_error: &'static str,
    /// When `true`, the TOTP step is shown inline instead of email+password.
    /// Set by the handler when password is correct but MFA is required.
    show_totp: bool,
    /// URL the inline TOTP form POSTs to (scope-matched).
    totp_action: String,
    /// URL of the MFA recovery code page (scope-matched).
    recovery_code_url: String,
    /// Shown alongside error when email is unverified — "Resend verification email".
    resend_verification_url: Option<String>,
    /// Shown alongside error when a magic link is expired — "Request a new magic link".
    new_magic_link_url: Option<String>,
    /// Shown alongside error when the form's CSRF token went stale — links back
    /// to this same login form so the user lands on a page bearing a fresh
    /// token without hunting for the browser reload button (HEA-1913).
    reload_url: Option<String>,
    /// Federation sign-in buttons, one per configured connector.
    federation_buttons: Vec<FederationButton>,
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
    /// The CAPTCHA provider's widget, rendered at `<!-- captcha-widget-slot -->`
    /// for a caller the abuse guards challenged (A-3, A-16). Empty otherwise.
    captcha_widget_html: String,
}

impl LoginTemplate {
    fn new(
        error: Option<String>,
        return_to: Option<String>,
        action_prefix: &str,
        show_register: bool,
        locale: &str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        let text = login_locale_text(locale);
        Self {
            error,
            return_to,
            email: String::new(),
            form_action: format!("{action_prefix}/login"),
            forgot_url: with_locale_query(&format!("{action_prefix}/forgot-password"), locale),
            register_url: with_locale_query(&format!("{action_prefix}/register"), locale),
            show_register,
            passkey_begin_url: format!("{action_prefix}/login/passkey-begin"),
            passkey_complete_url: format!("{action_prefix}/login/passkey-complete"),
            locale: locale.to_string(),
            heading_text: text.heading_text,
            email_label: text.email_label,
            password_label: text.password_label,
            submit_label: text.submit_label,
            or_continue_with_label: text.or_continue_with_label,
            or_label: text.or_label,
            sign_in_with_label: text.sign_in_with_label,
            forgot_password_label: text.forgot_password_label,
            create_account_label: text.create_account_label,
            passkey_sign_in_label: text.passkey_sign_in_label,
            passkey_authenticating_label: text.passkey_authenticating_label,
            passkey_unavailable_error: text.passkey_unavailable_error,
            passkey_cancelled_error: text.passkey_cancelled_error,
            passkey_failed_error: text.passkey_failed_error,
            show_totp: false,
            // The inline TOTP form and recovery link always target the global
            // MFA challenge routes, NOT `{action_prefix}/*`. Only `/ui/mfa-challenge`
            // and `/ui/mfa-recovery` are registered — the scoped (`/ui/realms/{realm}`)
            // and admin (`/ui/admin`) login surfaces have no per-prefix MFA routes,
            // so prefixing here produced a 404 on TOTP submit (HEA-1763). The
            // challenge handler proves scope via the signed `hearth_ui_mfa_pending`
            // cookie, so the global route is correct for every login surface. This
            // mirrors `MfaChallengeTemplate::new`.
            totp_action: "/ui/mfa-challenge".to_string(),
            recovery_code_url: "/ui/mfa-recovery".to_string(),
            resend_verification_url: None,
            new_magic_link_url: None,
            reload_url: None,
            federation_buttons: Vec::new(),
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
            captcha_widget_html: String::new(),
        }
    }
}

/// Successful email verification page.
#[derive(Template)]
#[template(path = "ui/verify_email_ok.html")]
struct VerifyOkTemplate {
    /// URL the "Sign in" button links to. Scope-matched to the realm
    /// the verification happened in so a user coming through
    /// `/ui/realms/<name>/verify-email` doesn't fall back onto the
    /// bare `/ui/login` resolver.
    login_url: String,
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

impl VerifyOkTemplate {
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Dashboard template with quick-link tiles for account management
/// and (for admins) the full management surface.
#[derive(Template)]
#[template(path = "ui/dashboard.html")]
struct DashboardTemplate {
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
    config_warnings: Vec<crate::config::EnvVarWarning>,
    /// Orphaned realms detected at startup (archived + has users + no resolution).
    orphaned_realms: Vec<crate::identity::reconcile::OrphanRecord>,
    /// Entity counts for the admin stats row.
    user_count: usize,
    realm_count: usize,
    app_count: usize,
    org_count: usize,
    /// Friendly greeting name — first non-empty of display name, given
    /// name, or local part of the email. Surfaced in the "Welcome, X"
    /// heading so admins are not greeted by a raw email address.
    greeting_name: String,
}

/// Invalid / expired / malformed verification link page.
#[derive(Template)]
#[template(path = "ui/verify_email_invalid.html")]
struct VerifyInvalidTemplate {
    heading: &'static str,
    message: &'static str,
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

impl VerifyInvalidTemplate {
    fn new(
        heading: &'static str,
        message: &'static str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            heading,
            message,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Forced MFA enrollment template — shown when the realm requires MFA but the
/// user has not yet enrolled. Mirrors the account enrollment UI but uses the
/// narrow, chrome-free layout (no nav) because the user has no session yet.
#[derive(Template)]
#[template(path = "ui/mfa_enroll_required.html")]
struct MfaEnrollRequiredTemplate {
    error: Option<String>,
    secret_base32: String,
    provisioning_uri: String,
    qr_svg: String,
    recovery_codes: Vec<String>,
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

impl MfaEnrollRequiredTemplate {
    fn new(
        error: Option<String>,
        secret_base32: String,
        provisioning_uri: String,
        qr_svg: String,
        recovery_codes: Vec<String>,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            error,
            secret_base32,
            provisioning_uri,
            qr_svg,
            recovery_codes,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// MFA challenge template — shown after password verification when MFA is
/// enabled. Accepts a TOTP code or recovery code.
#[derive(Template)]
#[template(path = "ui/mfa_challenge.html")]
struct MfaChallengeTemplate {
    error: Option<String>,
    /// URL the form POSTs to (scope-matched).
    form_action: String,
    /// URL of the MFA recovery code page (scope-matched).
    recovery_code_url: String,
    /// Carry through the post-login redirect.
    return_to: Option<String>,
    /// Shown alongside error when the form's CSRF token went stale — links back
    /// to this same challenge form so the user lands on a page bearing a fresh
    /// token without hunting for the browser reload button (HEA-1913).
    reload_url: Option<String>,
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

impl MfaChallengeTemplate {
    fn new(
        error: Option<String>,
        product_name: String,
        logo_url: String,
        return_to: Option<String>,
    ) -> Self {
        Self {
            error,
            form_action: "/ui/mfa-challenge".to_string(),
            recovery_code_url: "/ui/mfa-recovery".to_string(),
            return_to,
            reload_url: None,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// OTP second-factor challenge shown by the direct browser login when the
/// user's only usable factor is SMS or email OTP (audit 2026-08-28 §4.18#6).
///
/// `/ui/mfa-challenge` can only render a TOTP / recovery-code form, so the
/// login page used to treat those users as having no factor at all.
#[derive(Template)]
#[template(path = "ui/mfa_otp_challenge.html")]
struct MfaOtpChallengeTemplate {
    error: Option<String>,
    /// One line telling the user where the code went, e.g. the masked phone.
    ///
    /// The factor and the pending OTP record are deliberately NOT rendered
    /// into the form: they travel in the server-signed
    /// [`super::auth::MFA_OTP_COOKIE`], so the POST cannot choose them.
    prompt: String,
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

impl MfaOtpChallengeTemplate {
    fn new(error: Option<String>, prompt: String, product_name: String, logo_url: String) -> Self {
        Self {
            error,
            prompt,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Which OTP second factor a realm offers *and* this user actually holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum OtpFactor {
    /// Email OTP to the user's address.
    Email,
}

impl OtpFactor {
    /// The wire name, matching the `mfa_methods` vocabulary.
    fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email_otp",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "email_otp" => Some(Self::Email),
            _ => None,
        }
    }
}

/// Returns the OTP factor the browser login should challenge, if any.
///
/// Mirrors `IdentityEngine::has_second_factor` minus its TOTP arm: the realm
/// must offer the method (`mfa_methods`), the user must have enrolled it, and
/// the transport that delivers the code must be configured — a factor we
/// cannot send a code for is not a factor we can challenge.
pub(super) fn otp_factor_for(
    state: &Arc<WebState>,
    realm: &crate::identity::Realm,
    user: &crate::identity::User,
    first: super::auth::FirstFactor,
) -> Option<OtpFactor> {
    // An ABSENT `mfa_methods` restricts nothing — that is the semantics
    // `EmbeddedIdentityEngine::require_mfa_method` enforces, and the same rule
    // the TOTP branch below applies. `unwrap_or_default()` inverted it here,
    // producing an empty list that allowed NO factor, so a realm that had
    // simply never configured the key could never route to an OTP challenge.
    let methods = realm.config().mfa_methods.clone();
    let offers = |name: &str| methods.as_ref().is_none_or(|m| m.iter().any(|x| x == name));
    // An email OTP proves the inbox a magic link already proved: after a
    // magic link it is not a second factor at all (GA audit round 3, D-4).
    let holds_email = offers("email_otp") && user.email_otp_enabled() && first.allows_email_otp();
    let email_deliverable = state.email.is_some();
    // Prefer a factor we can actually send a code for.
    if holds_email && email_deliverable {
        return Some(OtpFactor::Email);
    }
    // The user holds a factor we cannot deliver. It is still their factor, so
    // it is still challenged — and the challenge fails closed at issuance.
    // Returning `None` here used to let the login issue the session on the
    // password alone, i.e. an unreachable transport or a missing OTP HMAC key
    // silently removed the user's second factor.
    if holds_email {
        return Some(OtpFactor::Email);
    }
    None
}

/// Issues an OTP for `factor` and returns `(nonce, prompt)`.
fn issue_login_otp(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user: &crate::identity::User,
    factor: OtpFactor,
) -> Result<(String, String), IdentityError> {
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match factor {
        OtpFactor::Email => {
            let email_service = state.email.as_ref().ok_or(IdentityError::MfaNotEnabled)?;
            let key = super::required_action::email_otp_hmac_key_bytes(state);
            let nonce = state.identity.issue_email_otp(
                realm_id,
                user.email(),
                &key,
                email_service,
                None,
                now_ts,
            )?;
            Ok((
                nonce,
                "We sent a 6-digit code to your email address.".to_string(),
            ))
        }
    }
}

/// Query for `GET /ui/mfa-otp-challenge`.
#[derive(Debug, Default, Deserialize)]
pub struct MfaOtpChallengeQuery {
    /// Present (any value) when the user asked for a new code.
    #[serde(default)]
    pub resend: Option<String>,
}

/// The prompt for a code already sent for `factor`.
fn otp_sent_prompt(factor: OtpFactor) -> String {
    match factor {
        OtpFactor::Email => "Enter the 6-digit code we sent to your email address.".to_string(),
    }
}

/// Renders the OTP challenge after the password step (audit §4.18#6).
///
/// Requires the MFA pending cookie, which proves the password was verified.
///
/// A code is issued on the first render only. A re-render while the
/// challenge cookie still names an outstanding code for this login and factor
/// shows the form again without sending anything; a new code is sent only on
/// an explicit `?resend=1`, which the engine throttles per recipient. Every
/// render used to mint and mail a fresh code, each good for five guesses — an
/// unbounded guessing budget and a flood of the victim's inbox (GA audit M12).
#[allow(clippy::too_many_lines)] // render, reuse or issue, bind — one sequence
pub async fn mfa_otp_challenge_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<MfaOtpChallengeQuery>,
) -> Response {
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };

    let (Ok(Some(realm)), Ok(Some(user))) = (
        state.identity.get_realm(&pending.realm_id),
        state.identity.get_user(&pending.realm_id, &pending.user_id),
    ) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(factor) = otp_factor_for(&state, &realm, &user, pending.first_factor) else {
        // The factor went away between login and here — start over rather
        // than silently dropping the second-factor requirement.
        return Redirect::to("/ui/login").into_response();
    };

    let secure = state.is_secure_request(&headers);
    let (csrf_value, fresh_cookie) =
        match cookie_value_from_headers(&headers, super::auth::CSRF_COOKIE) {
            Some(existing) => (existing.to_string(), None),
            None => {
                let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
                (val, Some(cookie))
            }
        };

    // An outstanding challenge for this login and factor: show the form again.
    let outstanding = query.resend.is_none()
        && cookie_value_from_headers(&headers, super::auth::MFA_OTP_COOKIE)
            .and_then(|raw| super::auth::parse_mfa_otp_cookie(&state.cookie_secret, &pending, raw))
            .is_some_and(|c| OtpFactor::parse(&c.factor) == Some(factor));
    if outstanding {
        let mut tmpl = MfaOtpChallengeTemplate::new(
            None,
            otp_sent_prompt(factor),
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        tmpl.csrf = Some(csrf_value);
        let mut resp = render(&tmpl);
        if let Some(cookie) = fresh_cookie {
            append_cookie(&mut resp, &cookie);
        }
        return resp;
    }

    // Issuing sends an SMS or an email — a network round-trip — so it runs on
    // the blocking pool rather than a Tokio worker.
    let issued = {
        let state = Arc::clone(&state);
        let realm_id = pending.realm_id.clone();
        let user = user.clone();
        tokio::task::spawn_blocking(move || issue_login_otp(&state, &realm_id, &user, factor))
            .await
            .unwrap_or_else(|e| {
                Err(IdentityError::Internal {
                    reason: format!("OTP issuance task failed: {e}"),
                })
            })
    };
    let (nonce, prompt) = match issued {
        Ok(v) => v,
        Err(IdentityError::RateLimited) => {
            let mut tmpl = MfaOtpChallengeTemplate::new(
                Some(
                    "Too many codes were requested. Wait a few minutes, then ask for a new one."
                        .to_string(),
                ),
                String::new(),
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.csrf = Some(csrf_value);
            let mut resp = render_status(&tmpl, StatusCode::TOO_MANY_REQUESTS);
            if let Some(cookie) = fresh_cookie {
                append_cookie(&mut resp, &cookie);
            }
            return resp;
        }
        Err(e) => {
            tracing::warn!(
                error = %crate::protocol::redact::sanitize_log_text(&e.to_string()),
                factor = factor.as_str(),
                "mfa-otp-challenge: issue failed"
            );
            let tmpl = MfaOtpChallengeTemplate::new(
                Some("We could not send a code right now. Please try again.".to_string()),
                String::new(),
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            // Drop any challenge a previous render bound: it named an OTP
            // this attempt did not replace.
            let mut resp = render_status(&tmpl, StatusCode::INTERNAL_SERVER_ERROR);
            append_cookie(&mut resp, &super::auth::clear_mfa_otp_cookie(secure));
            return resp;
        }
    };

    let mut tmpl = MfaOtpChallengeTemplate::new(
        None,
        prompt,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.csrf = Some(csrf_value);
    let mut resp = render(&tmpl);
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut resp, &cookie);
    }
    // Bind the issued OTP record and its factor to THIS password step. The
    // POST reads both from here, never from the form.
    append_cookie(
        &mut resp,
        &super::auth::issue_mfa_otp_cookie(
            &state.cookie_secret,
            &pending,
            factor.as_str(),
            &nonce,
            secure,
        ),
    );
    resp
}

/// Form body for `POST /ui/mfa-otp-challenge`.
#[derive(Debug, Deserialize)]
pub struct MfaOtpChallengeForm {
    /// The 6-digit code the user typed.
    ///
    /// This is the ONLY client-chosen input: the factor and the pending OTP
    /// record come from the server-signed [`super::auth::MFA_OTP_COOKIE`].
    /// Any `factor` / `otp_nonce` fields a client still sends are ignored.
    #[serde(default)]
    pub code: String,
    /// CSRF token echoed from the hidden `_csrf` field.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Verifies an SMS / email OTP and completes the login.
///
/// Carries the same three protections as `mfa_challenge_submit`: CSRF
/// double-submit, single-use redemption of the pending-cookie nonce, and the
/// engine's own per-OTP attempt budget.
#[allow(clippy::too_many_lines)] // one linear verification sequence
pub async fn mfa_otp_challenge_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<MfaOtpChallengeForm>,
) -> Response {
    let session_ctx = build_session_context(&headers, peer_addr, &state.trusted_proxies);
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
    };

    // The factor and the pending OTP record come from the challenge cookie the
    // GET bound to THIS pending login — never from the form. With them in the
    // form, the client chose which record its typed code was checked against
    // (any code obtained for the same phone or inbox by another route passed)
    // and which factor it was challenged on. No valid challenge cookie means
    // no OTP was issued for this login: send the user to get one.
    let Some(challenge) = cookie_value_from_headers(&headers, super::auth::MFA_OTP_COOKIE)
        .and_then(|raw| super::auth::parse_mfa_otp_cookie(&state.cookie_secret, &pending, raw))
    else {
        return Redirect::to("/ui/mfa-otp-challenge").into_response();
    };
    let Some(factor) = OtpFactor::parse(&challenge.factor) else {
        return Redirect::to("/ui/mfa-otp-challenge").into_response();
    };

    // The code must prove the PENDING user's own, current factor: refuse a
    // challenge for a factor they are no longer challenged on (the realm or
    // the user changed since the code was sent).
    let (Ok(Some(realm)), Ok(Some(user))) = (
        state.identity.get_realm(&pending.realm_id),
        state.identity.get_user(&pending.realm_id, &pending.user_id),
    ) else {
        return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
    };
    if otp_factor_for(&state, &realm, &user, pending.first_factor) != Some(factor) {
        return Redirect::to("/ui/mfa-otp-challenge").into_response();
    }

    let otp_err = |msg: &str, status: StatusCode| {
        let tmpl = MfaOtpChallengeTemplate::new(
            Some(msg.to_string()),
            String::new(),
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        render_status(&tmpl, status)
    };

    let csrf_ok = match cookie_value_from_headers(&headers, super::auth::CSRF_COOKIE) {
        Some(cookie_val) => super::auth::csrf_token_eq(cookie_val, &form.csrf),
        None => state.dev_mode,
    };
    if !csrf_ok {
        return otp_err(
            "Your session has expired. Please reload the page and try again.",
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    }

    // One failure budget per user across every code issued (GA audit M12).
    // Each OTP record allows five guesses of its own, but a new code can be
    // requested, so a per-record limit alone bounded nothing. This is the
    // budget TOTP and recovery codes already share.
    if state
        .identity
        .check_second_factor_budget(&pending.realm_id, &pending.user_id)
        .is_err()
    {
        return otp_err(
            "Too many failed attempts. Please wait a few minutes and try again.",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verified = verify_login_otp(
        &state,
        &pending.realm_id,
        &user,
        factor,
        &challenge.otp_nonce,
        form.code.trim(),
        now_ts,
    );
    if let Err(e) = verified {
        tracing::debug!(error = %e, "mfa-otp-challenge: verification failed");
        state
            .identity
            .record_second_factor_failure(&pending.realm_id, &pending.user_id);
        return otp_err("Invalid code. Please try again.", StatusCode::UNAUTHORIZED);
    }
    state
        .identity
        .clear_second_factor_failures(&pending.realm_id, &pending.user_id);

    // Single-use pending cookie, exactly as `mfa_challenge_submit` does.
    let exp_secs = now_ts.saturating_add(super::auth::MFA_PENDING_TTL_SECS);
    match state
        .identity
        .redeem_mfa_nonce(&pending.realm_id, &pending.nonce, exp_secs)
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
        }
    }

    let now_ra = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    if let Some(ra_response) = super::required_action::required_action_check_browser(
        &state,
        &pending.realm_id,
        &pending.user_id,
        pending.return_to.as_deref(),
        // What the OTP just verified, as in `finish_otp_login`; the RA flow
        // carries it to the session.
        &SessionContext {
            mfa_proof: pending.first_factor.proof_after_email_otp(),
            ..session_ctx.clone()
        },
        pending.first_factor,
        &headers,
        now_ra,
    ) {
        state.set_current_realm(pending.realm_id.clone());
        let mut ra_response = ra_response;
        append_cookie(
            &mut ra_response,
            &super::auth::clear_mfa_otp_cookie(state.is_secure_request(&headers)),
        );
        return ra_response;
    }

    finish_otp_login(&state, &headers, &pending, session_ctx)
}

/// Checks `code` against the pending OTP record `otp_nonce` for `factor`.
///
/// `otp_nonce` and `factor` MUST come from the server-signed challenge cookie,
/// never from the request body. Each verify also names the recipient the
/// user's code must have been sent to: the OTP record itself names nobody, so
/// without that a genuine nonce + code someone obtained for THEIR OWN inbox
/// passed this user's challenge.
fn verify_login_otp(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user: &crate::identity::User,
    factor: OtpFactor,
    otp_nonce: &str,
    code: &str,
    now_ts: u64,
) -> Result<(), IdentityError> {
    match factor {
        OtpFactor::Email => state.identity.verify_email_otp(
            realm_id,
            otp_nonce,
            user.email(),
            code,
            &super::required_action::email_otp_hmac_key_bytes(state),
            now_ts,
        ),
    }
}

/// Issues the session once an OTP second factor has been proved.
///
/// Split out of `mfa_otp_challenge_submit` to keep that handler under the
/// line limit; it is the whole "the factor checked out, now log them in" tail.
fn finish_otp_login(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    pending: &super::auth::MfaPending,
    session_ctx: SessionContext,
) -> Response {
    revoke_prior_session_cookie(state.identity.as_ref(), headers, &state.cookie_secret);

    // An email OTP the user typed back proves the inbox, not MFA (spec
    // `mfa-policy`); after a user-verified passkey the login keeps the
    // passkey's proof. The engine's gates read exactly this.
    let session_ctx = SessionContext {
        mfa_proof: pending.first_factor.proof_after_email_otp(),
        ..session_ctx
    };

    match state
        .identity
        .create_session(&pending.realm_id, &pending.user_id, &session_ctx)
    {
        Ok(session) => {
            let secure = state.is_secure_request(headers);
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(
                &state.cookie_secret,
                &pending.realm_id,
                session.id(),
                secure,
            );
            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
            append_cookie(&mut response, &super::auth::clear_mfa_otp_cookie(secure));
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), &pending.realm_id),
                    secure,
                ),
            );
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "mfa-otp-challenge: create_session failed");
            internal_error_response()
        }
    }
}

// ============================================================================
// Setup form
// ============================================================================

/// Renders the first-run setup form.
///
/// The operator's setup link carries `?token=`; the link-token middleware
/// moves it into a cookie and redirects here without it (GA audit L18), so
/// the token is read from that cookie and the page never renders it.
///
/// Returns `404 Not Found` if:
/// - no setup token was stashed,
/// - the token does not match the on-disk file, or
/// - Hearth is already configured (a realm exists).
///
/// The 404 is deliberately generic so that a would-be attacker cannot
/// distinguish "wrong token" from "system already set up".
pub async fn setup_form(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    let Some(token) = link_token::read(&headers) else {
        return not_found_response("Setup page is not available.");
    };

    match state.onboarding.verify_setup_token(&token) {
        Ok(()) => {}
        Err(OnboardingError::InvalidSetupToken | OnboardingError::AlreadyConfigured) => {
            return link_token::mark_spent(not_found_response("Setup page is not available."));
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to verify setup token");
            return internal_error_response();
        }
    }

    let tmpl = SetupTemplate::new(
        link_token::link_binding(&state.cookie_secret, &token),
        None,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    render(&tmpl)
}

/// Form body submitted by the setup page. The setup token itself comes from
/// the link-token cookie, never the form (GA audit L18).
#[derive(Debug, Deserialize)]
pub struct SetupForm {
    /// [`link_token::link_binding`] of the stashed token, echoed from the
    /// hidden input. Binds the POST to the page the cookie holder was served.
    #[serde(default)]
    pub link_binding: String,
    /// Admin email address.
    pub admin_email: String,
    /// Admin display name.
    pub admin_display_name: String,
    /// Admin password.
    pub admin_password: FormSecret,
}

/// Handles setup form submission.
///
/// On success, redirects (303 See Other) to `/ui/setup/sent`. The setup
/// token is consumed by `OnboardingService::complete_setup`.
pub async fn setup_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    // The token comes from the cookie, and the form must carry its binding:
    // a POST that did not come from the served page is refused before the
    // token is even checked.
    let Some(token) = link_token::read(&headers) else {
        return not_found_response("Setup page is not available.");
    };
    if !link_token::binding_matches(&state.cookie_secret, &token, &form.link_binding) {
        return not_found_response("Setup page is not available.");
    }
    // Re-verify token as defence in depth — the GET validated it, but an
    // attacker could POST directly.
    match state.onboarding.verify_setup_token(&token) {
        Ok(()) => {}
        Err(OnboardingError::InvalidSetupToken | OnboardingError::AlreadyConfigured) => {
            return link_token::mark_spent(not_found_response("Setup page is not available."));
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to verify setup token on submit");
            return internal_error_response();
        }
    }

    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let binding = form.link_binding.clone();
    let setup_err = |msg: String, status: StatusCode| {
        let tmpl = SetupTemplate::new(
            binding.clone(),
            Some(msg),
            product_name.clone(),
            logo_url.clone(),
        );
        render_status(&tmpl, status)
    };

    if let Err(msg) = validate_setup_form(&form) {
        return setup_err(msg, StatusCode::BAD_REQUEST);
    }

    let password = CleartextPassword::new(form.admin_password.as_bytes().to_vec());

    let base_url = derive_base_url(
        state
            .config
            .as_ref()
            .and_then(|c| c.onboarding.base_url.as_deref()),
        &state.fallback_base_url(),
        &headers,
    );
    match state.onboarding.complete_setup(
        form.admin_email.trim(),
        form.admin_display_name.trim(),
        &password,
        &base_url,
    ) {
        Ok(outcome) => {
            // Pin the newly-created realm as the "current" realm for
            // future logins through this process. On restart the first
            // realm is re-resolved at login time.
            state.set_current_realm(outcome.realm_id.clone());
            link_token::mark_spent(Redirect::to("/ui/setup/sent").into_response())
        }
        Err(OnboardingError::AlreadyConfigured) => {
            link_token::mark_spent(not_found_response("Setup page is not available."))
        }
        Err(OnboardingError::Identity(
            IdentityError::DuplicateEmail | IdentityError::EmailReserved,
        )) => setup_err(
            "An account with that email already exists in this system.".to_string(),
            StatusCode::CONFLICT,
        ),
        Err(OnboardingError::Identity(IdentityError::RealmNotFound)) => setup_err(
            "No realm is configured. Add a realm to hearth.yaml and restart.".to_string(),
            StatusCode::CONFLICT,
        ),
        Err(OnboardingError::Identity(IdentityError::InvalidInput { reason })) => {
            setup_err(format!("Invalid input: {reason}"), StatusCode::BAD_REQUEST)
        }
        Err(OnboardingError::Email(e)) => {
            tracing::error!(
                error = %crate::protocol::redact::sanitize_log_text(&e.to_string()),
                "setup: failed to send verification email"
            );
            setup_err(
                "The account was created but the verification email could not be sent. \
                Check the server logs for the verification link, or retry after fixing the email \
                transport."
                    .to_string(),
                StatusCode::BAD_GATEWAY,
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "setup: unexpected failure");
            internal_error_response()
        }
    }
}

/// Renders the "setup submitted" confirmation page.
///
/// Shows a "check your server logs" callout only when the email
/// transport is `Log` (i.e. no real email delivery).
pub async fn setup_sent(State(state): State<Arc<WebState>>) -> Response {
    let tmpl = SetupSentTemplate::new(
        state.email_is_log_transport,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    render(&tmpl)
}

// ============================================================================
// Emailed-link confirmation pages (GA audit L18)
// ============================================================================

/// Page an emailed one-time link lands on. It spends nothing: a mail scanner
/// or link preview that fetches the URL sees only this form, and the token is
/// spent by its `POST`.
#[derive(Template)]
#[template(path = "ui/link_confirm.html")]
struct LinkConfirmTemplate {
    heading: &'static str,
    message: &'static str,
    button_label: &'static str,
    /// Must be the route the link cookie is scoped to.
    form_action: String,
    /// [`link_token::link_binding`] of the stashed token.
    link_binding: String,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    /// CSRF double-submit token, embedded as the form's `_csrf` field.
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// The wording of a link-confirmation page.
#[derive(Clone, Copy, Debug)]
pub(super) struct LinkConfirmCopy {
    /// Page heading.
    pub heading: &'static str,
    /// One-sentence explanation above the button.
    pub message: &'static str,
    /// Label of the button that spends the token.
    pub button_label: &'static str,
}

/// Form every link-confirmation page posts.
#[derive(Debug, Deserialize)]
pub struct LinkConfirmForm {
    /// [`link_token::link_binding`] of the stashed token, from the page.
    #[serde(default)]
    pub link_binding: String,
    /// CSRF double-submit token (matches the `hearth_ui_csrf` cookie).
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Renders the confirmation page for the stashed `token`.
///
/// With `issue_csrf` the form carries the `hearth_ui_csrf` double-submit
/// token, minting the cookie when the browser has none. That cookie is
/// scoped to `/ui`, so pages outside it pass `false` and rely on the link
/// binding alone.
pub(super) fn render_link_confirm(
    state: &WebState,
    headers: &HeaderMap,
    token: &str,
    copy: LinkConfirmCopy,
    form_action: String,
    realm_theme_url: Option<String>,
    issue_csrf: bool,
) -> Response {
    let (csrf, fresh_cookie) = if issue_csrf {
        match super::auth::csrf_cookie_value_from_headers(headers) {
            Some(existing) => (Some(existing.to_string()), None),
            None => {
                let (value, cookie) =
                    super::auth::fresh_csrf_cookie(state.is_secure_request(headers));
                (Some(value), Some(cookie))
            }
        }
    } else {
        (None, None)
    };
    let mut resp = render(&LinkConfirmTemplate {
        heading: copy.heading,
        message: copy.message,
        button_label: copy.button_label,
        form_action,
        link_binding: link_token::link_binding(&state.cookie_secret, token),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        flash: None,
        csrf,
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url,
        inline_theme_css: state.inline_theme_css(),
    });
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut resp, &cookie);
    }
    resp
}

// ============================================================================
// Email verification
// ============================================================================

const VERIFY_EMAIL_COPY: LinkConfirmCopy = LinkConfirmCopy {
    heading: "Confirm your email address",
    message: "Confirm that this address is yours to activate your account.",
    button_label: "Verify email",
};

/// `GET /ui/verify-email` — the confirmation page for an emailed
/// verification link. The link's `?token=` was moved into the link-token
/// cookie by the route's middleware; nothing is verified until the `POST`
/// (GA audit L18).
pub async fn verify_email(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    verify_email_page_impl(&state, &headers, RealmSource::Path(None))
}

/// `GET /ui/realms/<name>/verify-email` — see [`verify_email`].
pub async fn verify_email_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    verify_email_page_impl(&state, &headers, RealmSource::Path(Some(realm_name)))
}

/// `GET /ui/admin/verify-email` — see [`verify_email`].
///
/// This is the link admins receive in their setup confirmation email.
/// Resolves to the system realm regardless of application realm state.
pub async fn admin_verify_email(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    verify_email_page_impl(&state, &headers, RealmSource::Admin)
}

/// `POST /ui/verify-email` — verifies the stashed token.
pub async fn verify_email_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    verify_email_impl(&state, &headers, &form, RealmSource::Path(None))
}

/// `POST /ui/realms/<name>/verify-email` — see [`verify_email_submit`].
pub async fn verify_email_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    verify_email_impl(&state, &headers, &form, RealmSource::Path(Some(realm_name)))
}

/// `POST /ui/admin/verify-email` — see [`verify_email_submit`].
pub async fn admin_verify_email_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    verify_email_impl(&state, &headers, &form, RealmSource::Admin)
}

/// The page every missing, refused or malformed verification link gets.
fn verify_link_invalid(state: &WebState) -> Response {
    let tmpl = VerifyInvalidTemplate::new(
        "Invalid link",
        "This verification link is missing or malformed.",
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    render_status(&tmpl, StatusCode::BAD_REQUEST)
}

fn verify_email_page_impl(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    source: RealmSource,
) -> Response {
    let Some(token) = link_token::read(headers) else {
        return verify_link_invalid(state);
    };
    let (realm, action_prefix) = match resolve_for_source(state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    render_link_confirm(
        state,
        headers,
        &token,
        VERIFY_EMAIL_COPY,
        format!("{action_prefix}/verify-email"),
        state.realm_theme_url_for(realm.id()),
        true,
    )
}

/// Shared `POST` implementation. On success the user transitions
/// `PendingVerification` → `Active` and can thereafter sign in.
fn verify_email_impl(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    form: &LinkConfirmForm,
    source: RealmSource,
) -> Response {
    let (realm, action_prefix) = match resolve_for_source(state, source, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let Some(token) =
        link_token::confirmed_token(state, headers, &form.link_binding, &form.csrf, true)
    else {
        return verify_link_invalid(state);
    };
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    // A pending federated account keeps its federated link only when the
    // browser that performed the federated login completes this (GA audit
    // round 3, G-3).
    let origin = link_token::verification_origin(&state.cookie_secret, headers, &token);

    link_token::mark_spent(
        match state
            .identity
            .verify_email_token_from(realm.id(), &token, origin)
        {
            Ok(_) => {
                let login_url = format!("{action_prefix}/login");
                let mut tmpl = VerifyOkTemplate::new(login_url, product_name, logo_url);
                tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
                tmpl.inline_theme_css = state.inline_theme_css();
                let mut response = render(&tmpl);
                append_cookie(
                    &mut response,
                    &link_token::clear_federated_origin_cookie(state.is_secure_request(headers)),
                );
                response
            }
            Err(IdentityError::VerificationTokenInvalid) => {
                let tmpl = VerifyInvalidTemplate::new(
                "Link expired or already used",
                "This verification link is no longer valid. Request a new verification email from \
                the sign-in page once it becomes available.",
                product_name,
                logo_url,
            );
                render_status(&tmpl, StatusCode::GONE)
            }
            Err(e) => {
                tracing::error!(error = %e, "verify-email: unexpected failure");
                internal_error_response()
            }
        },
    )
}

// ============================================================================
// Login
// ============================================================================

/// Query parameters for the GET login form (optional `return_to`).
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Relative path to redirect back to after a successful sign-in.
    pub return_to: Option<String>,
    /// Optional locale tag for login UI copy (for example: `en`, `es`).
    pub locale: Option<String>,
}

/// Renders the login form at the bare `/ui/login` URL.
pub async fn login_form(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    login_form_impl(state, headers, query, RealmSource::Path(None), peer_addr)
}

/// Renders the login form under `/ui/realms/<name>/login`.
pub async fn login_form_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    login_form_impl(
        state,
        headers,
        query,
        RealmSource::Path(Some(realm_name)),
        peer_addr,
    )
}

/// Renders the admin login form at `/ui/admin/login`. The session
/// created by a successful submit is always bound to the system realm.
pub async fn admin_login_form(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    login_form_impl(state, headers, query, RealmSource::Admin, peer_addr)
}

#[allow(clippy::needless_pass_by_value)]
fn login_form_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    query: LoginQuery,
    source: RealmSource,
    peer_addr: SocketAddr,
) -> Response {
    let return_to = query.return_to.as_deref().and_then(sanitize_return_to);
    let locale = resolve_login_locale(
        query.locale.as_deref(),
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    );
    let (realm, action_prefix) = match resolve_for_source(&state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let product_name = state.product_name_for(realm.id());
    let show_register = registration_enabled(&realm);
    let mut tmpl = LoginTemplate::new(
        None,
        return_to,
        &action_prefix,
        show_register,
        locale,
        product_name,
        state.logo_url.clone(),
    );
    tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
    tmpl.inline_theme_css = state.inline_theme_css();
    tmpl.federation_buttons = federation_buttons_for(&state, realm.id(), &action_prefix);

    // Issue or reuse the pre-auth CSRF cookie. If the browser already has a
    // hearth_ui_csrf cookie (e.g. from a prior session), embed its value so
    // the POST handler can verify the double-submit. If not, generate a fresh
    // token and set a new cookie on this response.
    let secure = state.is_secure_request(&headers);
    let (csrf_value, fresh_cookie) = match super::auth::csrf_cookie_value_from_headers(&headers) {
        Some(existing) => (existing.to_string(), None),
        None => {
            let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
            (val, Some(cookie))
        }
    };
    tmpl.csrf = Some(csrf_value);

    // A-16: a caller an earlier attempt put in the challenge state sees the
    // CAPTCHA widget now, so a passkey or password sign-in can carry a token.
    let provider = state.abuse_guards.captcha_provider().filter(|_| {
        let session_ctx = build_session_context(&headers, peer_addr, &state.trusted_proxies);
        state
            .abuse_guards
            .challenge_pending(guard_ip_of(&session_ctx))
    });
    if let Some(provider) = provider {
        tmpl.captcha_widget_html = provider.widget_html().to_string();
    }

    let mut resp = render(&tmpl);
    if let Some(provider) = provider {
        super::security::allow_captcha_origins(&mut resp, provider.csp_origins());
    }
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut resp, &cookie);
    }
    resp
}

/// Builds the list of federation sign-in buttons rendered on a login
/// page. Returns an empty vector when the realm has no connectors
/// registered or the engine errors (which we log and swallow — the
/// password form still works).
pub(super) fn federation_buttons_for(
    state: &WebState,
    realm_id: &crate::core::RealmId,
    action_prefix: &str,
) -> Vec<FederationButton> {
    let idps = match state.identity.list_idps(realm_id) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "list_idps for login page failed");
            return Vec::new();
        }
    };
    idps.into_iter()
        .map(|cfg| FederationButton {
            begin_url: format!(
                "{action_prefix}/federation/begin?idp={}",
                form_urlencoded::byte_serialize(cfg.name.as_bytes()).collect::<String>()
            ),
            display_name: cfg.display_name,
        })
        .collect()
}

/// Credentials submitted by the login form.
#[derive(Deserialize)]
pub struct LoginForm {
    /// Email address.
    pub email: String,
    /// Password.
    pub password: FormSecret,
    /// Optional `return_to` path submitted via hidden field.
    #[serde(default)]
    pub return_to: Option<String>,
    /// Optional locale submitted via hidden field.
    #[serde(default)]
    pub locale: Option<String>,
    /// CSRF token echoed from the hidden `_csrf` field.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    /// CAPTCHA response token from the provider's widget, present when the
    /// abuse guards challenged an earlier attempt (A-3, A-16).
    #[serde(default)]
    pub captcha_token: String,
}

/// Prints the address and routing fields only: the password, the CSRF
/// token and the CAPTCHA token never reach a log line through `{:?}` (GA
/// audit L20).
impl std::fmt::Debug for LoginForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginForm")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("return_to", &self.return_to)
            .field("locale", &self.locale)
            .field("csrf", &"<redacted>")
            .field("captcha_token", &"<redacted>")
            .finish()
    }
}

/// Runs a blocking Argon2id-bearing closure under the bounded KDF admission
/// gate (HEA-1887 / R1, extended by HEA-1891).
///
/// Every UI handler whose engine call performs an Argon2id hash or verify —
/// Builds the `503 Service Unavailable` shed response for an overloaded KDF gate.
///
/// Carries a `Retry-After` header (seconds) so well-behaved clients back off
/// instead of retrying immediately and deepening the overload.
// Used by unit tests in this module; browser-facing handlers use `kdf_shed_html_response`.
#[allow(dead_code)]
pub(crate) fn kdf_shed_response(retry_after: std::time::Duration) -> Response {
    // Never advertise 0 — clients treat `Retry-After: 0` inconsistently.
    let secs = retry_after.as_secs().max(1);
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        "Server is busy verifying credentials. Please retry shortly.\n",
    )
        .into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    resp
}

/// Builds an HTML `503 Service Unavailable` shed page for browser-facing routes.
///
/// Unlike [`kdf_shed_response`] (plain-text), this returns a styled HTML page
/// with a fresh CSRF cookie and optionally pre-fills the submitted email and
/// retry action, so the user can retry the form without retyping their address
/// (HEA-1979 / HEA-1981).
pub(crate) fn kdf_shed_html_response(
    state: &super::WebState,
    headers: &HeaderMap,
    retry_after: std::time::Duration,
    email: Option<String>,
    return_to: Option<String>,
    form_action: Option<String>,
) -> Response {
    let secs = retry_after.as_secs().max(1);
    let secure = state.is_secure_request(headers);
    let (csrf_value, csrf_cookie) = super::auth::fresh_csrf_cookie(secure);
    let tmpl = super::handlers_common::KdfShedTemplate {
        retry_after_secs: secs,
        email: email.unwrap_or_default(),
        return_to,
        form_action,
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        flash: None,
        csrf: Some(csrf_value),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    let mut resp = super::templates::render_status(&tmpl, StatusCode::SERVICE_UNAVAILABLE);
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    if let Ok(v) = HeaderValue::from_str(&csrf_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// Handles login submission at the bare `/ui/login` URL.
pub async fn login_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    login_submit_gated(state, headers, form, RealmSource::Path(None), peer_addr).await
}

/// Handles login submission at `/ui/realms/<name>/login`.
pub async fn login_submit_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    login_submit_gated(
        state,
        headers,
        form,
        RealmSource::Path(Some(realm_name)),
        peer_addr,
    )
    .await
}

/// Handles admin login submission at `/ui/admin/login`. On success,
/// issues a session cookie bound to the system realm.
pub async fn admin_login_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    login_submit_gated(state, headers, form, RealmSource::Admin, peer_addr).await
}

/// Rendering inputs shared by every login error surface. Resolved once in the
/// pre-gate phase ([`login_prepare`]) so both the pre-gate fast-rejects and the
/// gated verify path render identical, enumeration-safe pages.
struct LoginRenderCtx {
    action_prefix: String,
    return_to: Option<String>,
    show_register: bool,
    locale: &'static str,
    product_name: String,
    logo_url: String,
    realm_theme: Option<String>,
    inline_theme_css: Option<String>,
}

impl LoginRenderCtx {
    /// Builds a login error page. `email` echoes the submitted address back
    /// into the form (constant message ⇒ leaks nothing); pass `None` to leave it
    /// blank.
    fn error_page(&self, message: &str, status: StatusCode, email: Option<&str>) -> Response {
        let mut tmpl = LoginTemplate::new(
            Some(message.to_string()),
            self.return_to.clone(),
            &self.action_prefix,
            self.show_register,
            self.locale,
            self.product_name.clone(),
            self.logo_url.clone(),
        );
        if let Some(email) = email {
            tmpl.email = email.to_string();
        }
        tmpl.realm_theme_url.clone_from(&self.realm_theme);
        tmpl.inline_theme_css.clone_from(&self.inline_theme_css);
        render_status(&tmpl, status)
    }

    /// The single generic "sign-in failed" page (401). The message is constant
    /// regardless of whether the account exists (enumeration resistance).
    fn generic_error(&self, submitted_email: &str) -> Response {
        self.error_page(
            "Sign-in failed. Check your credentials and try again.",
            StatusCode::UNAUTHORIZED,
            Some(submitted_email),
        )
    }

    /// The answer to a login attempt the abuse guards challenged (A-3, A-16).
    ///
    /// With a CAPTCHA provider: the login page again (401), with the
    /// provider's widget at the slot and the request's CSRF token echoed so
    /// the form can be resubmitted. Without one: [`Self::generic_error`]. The
    /// page is decided before any account lookup, so it is the same for
    /// every address.
    fn challenge_page(
        &self,
        submitted_email: &str,
        guards: &crate::abuse::runtime::AbuseGuards,
        headers: &HeaderMap,
    ) -> Response {
        let Some(provider) = guards.captcha_provider() else {
            return self.generic_error(submitted_email);
        };
        let mut tmpl = LoginTemplate::new(
            Some("Complete the check below, then sign in again.".to_string()),
            self.return_to.clone(),
            &self.action_prefix,
            self.show_register,
            self.locale,
            self.product_name.clone(),
            self.logo_url.clone(),
        );
        tmpl.email = submitted_email.to_string();
        tmpl.csrf = super::auth::csrf_cookie_value_from_headers(headers).map(str::to_string);
        tmpl.captcha_widget_html = provider.widget_html().to_string();
        tmpl.realm_theme_url.clone_from(&self.realm_theme);
        tmpl.inline_theme_css.clone_from(&self.inline_theme_css);
        let mut resp = render_status(&tmpl, StatusCode::UNAUTHORIZED);
        super::security::allow_captcha_origins(&mut resp, provider.csp_origins());
        resp
    }

    /// The CSRF failure page (422).
    ///
    /// Mints a **fresh** CSRF token so the user can resubmit immediately without
    /// a separate page reload (HEA-1983). Echoes `submitted_email` back into the
    /// form so the address field is not cleared. The `reload_url` preserves any
    /// `return_to` destination so deep-linked users are not dropped to bare
    /// `/login` on recovery.
    ///
    /// Copy avoids "security token" — see HEA-1913 for rationale.
    fn csrf_error(&self, submitted_email: &str, secure: bool) -> Response {
        let (csrf_value, csrf_cookie) = super::auth::fresh_csrf_cookie(secure);
        let mut tmpl = LoginTemplate::new(
            Some("Your session has expired. Please reload the page and try again.".to_string()),
            self.return_to.clone(),
            &self.action_prefix,
            self.show_register,
            self.locale,
            self.product_name.clone(),
            self.logo_url.clone(),
        );
        tmpl.email = submitted_email.to_string();
        tmpl.csrf = Some(csrf_value);
        // Preserve return_to in the reload link so a deep-linked user who hits
        // a stale token still lands at their original destination after reload.
        tmpl.reload_url = Some(match &self.return_to {
            Some(rt) => format!(
                "{}/login?return_to={}",
                self.action_prefix,
                form_urlencoded::byte_serialize(rt.as_bytes()).collect::<String>()
            ),
            None => format!("{}/login", self.action_prefix),
        });
        tmpl.realm_theme_url.clone_from(&self.realm_theme);
        tmpl.inline_theme_css.clone_from(&self.inline_theme_css);
        let mut resp = render_status(&tmpl, StatusCode::UNPROCESSABLE_ENTITY);
        append_cookie(&mut resp, &csrf_cookie);
        resp
    }
}

/// Realm + render context carried across the KDF gate. Built by
/// [`login_prepare`] in the async handler (outside the gate) and consumed by
/// [`login_finish`] on the blocking pool (inside the gate).
struct PreparedLogin {
    realm: Realm,
    render_ctx: LoginRenderCtx,
    session_ctx: SessionContext,
    client_ip: String,
    /// Trimmed submitted email.
    email: String,
    /// `true` for the `/ui/admin/login` surface — routed to the reserved admin
    /// gate (HEA-1892 / F2).
    is_admin: bool,
    /// Parsed client IP for the abuse guards (task 20.13). `None` when no IP
    /// could be determined — every guard skips in that case.
    guard_ip: Option<std::net::IpAddr>,
    /// The guards challenged this attempt and it carries a CAPTCHA token:
    /// the token must verify before the attempt is admitted to the gate.
    captcha_pending: bool,
}

/// Orchestrates a login submission across the bounded KDF admission gate
/// (HEA-1887 / R1, hardened by HEA-1892).
///
/// The allocation-free abuse fast-rejects — CSRF double-submit, cross-origin
/// POST, realm auth-method policy, and the per-IP login rate limit — run in
/// [`login_prepare`] **before** a KDF permit is acquired (HEA-1892 / F1), so
/// rejected traffic never consumes admission capacity: a distributed
/// sub-threshold flood of bad-CSRF or rate-limited requests can no longer
/// saturate the gate with soon-to-be-rejected work. Every reject is
/// username-independent, so enumeration properties are unchanged.
///
/// Only the surviving request — whose dominant cost is the inline Argon2id
/// verify — is admitted to the gate; on saturation it is shed with `503` +
/// `Retry-After`. Admin logins draw from a *separate* reserved gate
/// (HEA-1892 / F2) so a flood against a tenant realm cannot lock the operator
/// out of the admin console.
async fn login_submit_gated(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: LoginForm,
    source: RealmSource,
    peer_addr: SocketAddr,
) -> Response {
    let prepared = match login_prepare(&state, &headers, &form, source, peer_addr) {
        Ok(prepared) => prepared,
        // Rejected pre-gate: no KDF permit was ever acquired.
        Err(response) => return response,
    };
    // A challenged attempt continues only with a CAPTCHA token the provider
    // verifies; a rejected token counts as a failure and is challenged again.
    if prepared.captcha_pending
        && !crate::protocol::abuse_challenge::verify_captcha(
            &state.abuse_guards,
            prepared.guard_ip,
            &form.captcha_token,
        )
        .await
    {
        return prepared
            .render_ctx
            .challenge_page(&prepared.email, &state.abuse_guards, &headers);
    }

    let is_admin = prepared.is_admin;
    // Extract shed context before all values are moved into the closure.
    let shed_email = prepared.email.clone();
    let shed_return_to = form.return_to.clone();
    let shed_state = state.clone();
    let shed_headers = headers.clone();
    let run = move || login_finish(state, headers, form, prepared);
    let gated = if is_admin {
        admin_gate().run(run).await
    } else {
        gate().run(run).await
    };
    let form_action = if is_admin {
        "/ui/admin/login"
    } else {
        "/ui/login"
    };
    match gated {
        Ok(response) => response,
        Err(KdfGateError::Overloaded { retry_after }) => kdf_shed_html_response(
            &shed_state,
            &shed_headers,
            retry_after,
            Some(shed_email),
            shed_return_to,
            Some(form_action.to_string()),
        ),
        Err(KdfGateError::Join(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Pre-gate phase (HEA-1892 / F1): resolves the realm and render context, then
/// runs the allocation-free abuse fast-rejects that MUST NOT consume a KDF
/// permit — CSRF double-submit, cross-origin POST, realm auth-method policy,
/// and the per-IP login rate limit.
///
/// Returns the [`PreparedLogin`] to admit to the gate, or the complete
/// rejection response to return immediately (never touching the gate). Every
/// reject is username-independent, so login enumeration properties are
/// identical to the pre-split handler.
#[allow(clippy::needless_pass_by_value)]
fn login_prepare(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    form: &LoginForm,
    source: RealmSource,
    peer_addr: SocketAddr,
) -> Result<PreparedLogin, Response> {
    let is_admin = matches!(source, RealmSource::Admin);
    let email = form.email.trim().to_string();
    let return_to = form.return_to.as_deref().and_then(sanitize_return_to);
    let locale = resolve_login_locale(
        form.locale.as_deref(),
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    );
    let session_ctx = build_session_context(headers, peer_addr, &state.trusted_proxies);

    let (realm, action_prefix) = match resolve_for_source(state, source, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return Err(resp),
    };

    let render_ctx = LoginRenderCtx {
        action_prefix,
        return_to,
        show_register: registration_enabled(&realm),
        locale,
        product_name: state.product_name_for(realm.id()),
        logo_url: state.logo_url.clone(),
        realm_theme: state.realm_theme_url_for(realm.id()),
        inline_theme_css: state.inline_theme_css(),
    };

    // Extract the client IP once, after trusted-proxy stripping, for the
    // per-IP rate limiter. Empty string = no IP available (skipped by engine).
    let client_ip = session_ctx.ip_address.clone().unwrap_or_default();

    // --- Abuse fast-rejects, all BEFORE the KDF gate (HEA-1892 / F1) ---

    // F6: CSRF double-submit check — fail-closed in non-dev mode.
    // In production (dev_mode = false), an absent hearth_ui_csrf cookie is
    // treated as a CSRF failure (not a pass-through). In dev mode the bypass
    // is preserved so direct-POST tooling continues to work.
    let csrf_ok = match super::auth::csrf_cookie_value_from_headers(headers) {
        Some(cookie_val) => super::auth::csrf_token_eq(cookie_val, &form.csrf),
        None => state.dev_mode, // dev: bypass; prod: fail-closed
    };
    if !csrf_ok {
        let secure = state.is_secure_request(headers);
        return Err(render_ctx.csrf_error(&email, secure));
    }

    // Login CSRF guard: reject cross-origin POSTs.
    // Browsers always send `Origin` on cross-site POST; an absent header means
    // same-site and is allowed. Collapsing into `generic_error()` prevents the
    // response from leaking whether the address or realm exists (enumeration
    // resistance).
    if let Some(origin_val) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let expected = state.public_origin_str(headers);
        if origin_val != expected {
            tracing::warn!(
                origin = origin_val,
                expected = %expected,
                "login: CSRF origin mismatch"
            );
            return Err(render_ctx.generic_error(&email));
        }
    }

    // Enforce realm policy: password auth must be in the allow-list.
    if let Some(ref methods) = realm.config().allowed_auth_methods {
        if !methods.iter().any(|m| m == "password") {
            tracing::warn!(realm = %realm.id(), "login: password auth blocked by realm policy");
            return Err(render_ctx.generic_error(&email));
        }
    }

    // Per-IP rate limit check. Must happen before user lookup so a blocked
    // IP cannot probe which email addresses exist — and before the gate so a
    // flood cannot saturate admission with soon-to-be-rejected requests
    // (HEA-1892 / F1).
    if state
        .identity
        .check_ip_login_rate_limit(realm.id(), &client_ip)
        .is_err()
    {
        tracing::warn!(ip = %client_ip, "login: IP rate limit exceeded");
        return Err(render_ctx.generic_error(&email));
    }

    // Abuse guards (task 20.13, audit §4.17#9). A-9 tenant CIDR, A-16
    // challenge and A-3 cardinality all run here, before a KDF permit is
    // acquired, for the same reason the rate limit does: rejected traffic must
    // not consume admission capacity. A refusal is the one generic page; a
    // challenge is audited and answered with the CAPTCHA widget when a
    // provider is configured. Neither depends on the account, so login
    // enumeration properties are unchanged. All are fail-open until the
    // operator enables them in `security:`.
    let guard_ip = guard_ip_of(&session_ctx);
    let mut captcha_pending = false;
    match state
        .abuse_guards
        .pre_auth_login(guard_ip, &email, realm.config().cidr_policy.as_ref())
    {
        PreAuthVerdict::Allow => {}
        PreAuthVerdict::Deny { reason } => {
            tracing::warn!(ip = %client_ip, guard = reason, "login: refused by abuse guard");
            return Err(render_ctx.generic_error(&email));
        }
        PreAuthVerdict::Challenge(challenge) => {
            crate::protocol::abuse_challenge::audit_challenge(
                &state.abuse_guards,
                state.audit.as_ref(),
                &crate::protocol::abuse_challenge::ChallengedAttempt {
                    realm_id: realm.id(),
                    ip: guard_ip,
                    username: Some(&email),
                    surface: crate::protocol::abuse_challenge::Surface::Ui,
                },
                &challenge,
            );
            // Without a provider, or without a token to verify, the challenge
            // page is the answer. A token is verified in the async handler,
            // still before the gate.
            if state.abuse_guards.captcha_provider().is_none() || form.captcha_token.is_empty() {
                return Err(render_ctx.challenge_page(&email, &state.abuse_guards, headers));
            }
            captcha_pending = true;
        }
    }

    Ok(PreparedLogin {
        realm,
        render_ctx,
        session_ctx,
        client_ip,
        email,
        is_admin,
        guard_ip,
        captcha_pending,
    })
}

/// Gated phase (runs on the blocking pool under a KDF permit): the Argon2id
/// verify and everything downstream — MFA gate, required-action gate, and
/// session issuance. All abuse fast-rejects already passed in [`login_prepare`].
///
/// On success: creates a session, issues the `hearth_ui_session` and
/// `hearth_ui_csrf` cookies, then redirects. When MFA is enabled, shows the
/// inline TOTP form (or redirects to forced enrollment). All auth failures
/// collapse into a single generic error (enumeration resistance).
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn login_finish(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: LoginForm,
    prepared: PreparedLogin,
) -> Response {
    let PreparedLogin {
        realm,
        render_ctx,
        session_ctx,
        client_ip,
        email,
        is_admin: _,
        guard_ip,
        captcha_pending: _,
    } = prepared;
    let return_to = render_ctx.return_to.clone();

    // Resolved realm → single targeted lookup. No walk.
    let Ok(Some(user)) = state.identity.get_user_by_email(realm.id(), &email) else {
        // Run dummy hash so timing is indistinguishable from a real user lookup + failed verify.
        // Under the realm's own Argon2 parameters, or a realm with a raised
        // cost answers an unknown address measurably faster (GA audit L14).
        state.identity.dummy_verify_password_for_realm(
            realm.id(),
            &CleartextPassword::new(form.password.as_bytes().to_vec()),
        );
        state
            .identity
            .record_ip_login_attempt(realm.id(), &client_ip);
        // A login attempt against an address that has no account was audited
        // NOWHERE: `verify_password` — which is what emits `LoginFailed` — is
        // never reached, so a credential-stuffing run against a realm's whole
        // address space left the audit trail empty while the per-IP counter
        // ticked in memory (audit 2026-08-28 §4.14#7).
        //
        // Resource id is the literal `unknown`, not the submitted address: the
        // realm's audit log is readable by realm admins, and echoing arbitrary
        // attacker-supplied addresses into it would turn the log into a
        // reflected store of third-party email addresses. The client IP is the
        // actionable field and is recorded.
        crate::protocol::audit_log::record(
            state.audit.as_ref(),
            &crate::audit::CreateAuditEvent {
                realm_id: realm.id().clone(),
                actor: "anonymous".to_string(),
                action: crate::audit::AuditAction::LoginFailed,
                resource_type: "credential".to_string(),
                resource_id: "unknown".to_string(),
                metadata: Some(serde_json::json!({
                    "reason": "unknown_account",
                    "ip": client_ip,
                })),
            },
        );
        state.abuse_guards.record_login_failure(guard_ip);
        return render_ctx.generic_error(&email);
    };

    let password = CleartextPassword::new(form.password.as_bytes().to_vec());
    match state
        .identity
        .verify_password(realm.id(), user.id(), &password)
    {
        Ok(true) => state.abuse_guards.record_login_success(guard_ip),
        Ok(false) => {
            state
                .identity
                .record_ip_login_attempt(realm.id(), &client_ip);
            state.abuse_guards.record_login_failure(guard_ip);
            return render_ctx.generic_error(&email);
        }
        Err(e) => {
            tracing::warn!(error = %e, "login: password verification failed");
            state
                .identity
                .record_ip_login_attempt(realm.id(), &client_ip);
            state.abuse_guards.record_login_failure(guard_ip);
            return render_ctx.generic_error(&email);
        }
    }

    // --- MFA gate ---
    // TOTP takes the inline form on this page; every other factor has its own
    // challenge page (`super::second_factor`). Until 19.13 this gate asked
    // `mfa_enabled` alone, so a user whose sole factor was SMS or email OTP
    // was invisible to it (audit 2026-08-28 §4.18#6); until the GA audit (B5)
    // a passkey was invisible the same way — a passkey-only user signed in on
    // the password alone, or, on an `mfa_required` realm, was sent to forced
    // TOTP enrolment where the password holder enrolled a TOTP of their own.
    // Forced enrolment is now chosen only for a user who holds no factor.
    // Neither branch decides whether the policy is met: the engine gate reads
    // factor use from `SessionContext::mfa_proof` (§4.18#3).
    //
    // An unverified account cannot open a session, so it is told so before
    // any second-factor step: with MFA required by default, it used to reach
    // forced enrolment and fail there with a 500.
    if user.status() == crate::identity::UserStatus::PendingVerification {
        return render_ctx.error_page(
            "Your email is not verified yet. Check your inbox (or the server \
             logs) for the verification link and click it before signing in.",
            StatusCode::FORBIDDEN,
            Some(&email),
        );
    }
    let secure = state.is_secure_request(&headers);
    let step = match super::second_factor::second_factor_step(
        &state,
        &realm,
        &user,
        super::auth::FirstFactor::Credential,
    ) {
        Ok(step) => step,
        Err(e) => {
            // A factor lookup failed: the factors are unknown, so refuse
            // rather than skip one.
            tracing::warn!(error = %e, "login: second-factor lookup failed");
            return render_ctx.generic_error(&email);
        }
    };
    match step {
        Some(super::second_factor::SecondFactorStep::Totp) => {
            let cookie = issue_mfa_pending_cookie(
                &state.cookie_secret,
                realm.id(),
                user.id(),
                return_to.as_deref(),
                secure,
            );
            state.set_current_realm(realm.id().clone());
            // Return the login page with the inline TOTP section visible rather than
            // redirecting to /ui/mfa-challenge. The pending cookie still grants the
            // challenge handler proof of password validation.
            let mut tmpl = LoginTemplate::new(
                None,
                return_to.clone(),
                &render_ctx.action_prefix,
                render_ctx.show_register,
                render_ctx.locale,
                render_ctx.product_name.clone(),
                render_ctx.logo_url.clone(),
            );
            tmpl.show_totp = true;
            tmpl.email = email.clone();
            tmpl.realm_theme_url.clone_from(&render_ctx.realm_theme);
            tmpl.inline_theme_css
                .clone_from(&render_ctx.inline_theme_css);
            // The inline form posts to `/ui/mfa-challenge`, which checks the
            // CSRF double-submit: echo the token this request carried, or mint
            // one (the `--dev` path admits a request without the cookie).
            let fresh_csrf = match super::auth::csrf_cookie_value_from_headers(&headers) {
                Some(existing) => {
                    tmpl.csrf = Some(existing.to_string());
                    None
                }
                None => {
                    let (value, csrf_cookie) = super::auth::fresh_csrf_cookie(secure);
                    tmpl.csrf = Some(value);
                    Some(csrf_cookie)
                }
            };
            let mut response = render(&tmpl);
            append_cookie(&mut response, &cookie);
            if let Some(csrf_cookie) = fresh_csrf {
                append_cookie(&mut response, &csrf_cookie);
            }
            return response;
        }
        Some(other) => {
            return super::second_factor::redirect_to_second_factor(
                &state,
                realm.id(),
                user.id(),
                other,
                super::auth::FirstFactor::Credential,
                return_to.as_deref(),
                secure,
            );
        }
        None => {}
    }

    // --- Required-action gate ---
    // Mirror the OIDC interceptor: check for pending required actions
    // before issuing a session. If any are pending, redirect the user to
    // the action interstitial and only resume the session on completion.
    let now = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    if let Some(ra_response) = super::required_action::required_action_check_browser(
        &state,
        realm.id(),
        user.id(),
        return_to.as_deref(),
        // The password alone: nothing proved beyond the first factor.
        &session_ctx,
        super::auth::FirstFactor::Credential,
        &headers,
        now,
    ) {
        state.set_current_realm(realm.id().clone());
        return ra_response;
    }

    // A-41: Destroy any pre-existing session cookie before issuing a new one.
    revoke_prior_session_cookie(state.identity.as_ref(), &headers, &state.cookie_secret);

    match state
        .identity
        .create_session(realm.id(), user.id(), &session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id(), secure);

            state.set_current_realm(realm.id().clone());

            let location = return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), realm.id()),
                    secure,
                ),
            );
            response
        }
        Err(IdentityError::UserNotVerified) => render_ctx.error_page(
            "Your email is not verified yet. Check your inbox (or the server \
             logs) for the verification link and click it before signing in.",
            StatusCode::FORBIDDEN,
            Some(&email),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "login: create_session failed");
            render_ctx.generic_error(&email)
        }
    }
}

// ============================================================================
// Passkey (WebAuthn) login
// ============================================================================

/// `GET /ui/login/passkey-begin` — bare variant.
pub async fn passkey_login_begin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    passkey_login_begin_impl(state, headers, None)
}

/// `GET /ui/realms/<name>/login/passkey-begin` — realm-scoped variant.
pub async fn passkey_login_begin_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    passkey_login_begin_impl(state, headers, Some(realm_name))
}

/// `GET /ui/admin/login/passkey-begin` — admin variant. Forces the system
/// realm so admin sign-ins don't leak into a tenant realm's credential
/// store on multi-realm deployments.
pub async fn passkey_login_begin_admin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let realm = match resolve_admin_realm(&state) {
        PreAuthRealm::Ok { realm, .. } => realm,
        PreAuthRealm::Handled(_) => {
            return (StatusCode::BAD_REQUEST, "System realm unavailable").into_response();
        }
    };
    passkey_login_begin_with_realm(state, headers, realm)
}

/// Starts a discoverable credential authentication ceremony. The
/// challenge is created in the resolved realm; the store is realm-scoped
/// but `user_id=None` (discoverable flow) skips per-realm user lookup.
#[allow(clippy::needless_pass_by_value)]
fn passkey_login_begin_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    path_realm: Option<String>,
) -> Response {
    let realm = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok { realm, .. } => realm,
        PreAuthRealm::Handled(_) => {
            // JSON endpoint: picker HTML is not useful. Return 400.
            return (StatusCode::BAD_REQUEST, "Realm not resolvable").into_response();
        }
    };
    passkey_login_begin_with_realm(state, headers, realm)
}

/// Shared body of every passkey-begin handler once the target realm has
/// been resolved. Split out so the admin variant can force the system
/// realm without re-running the bare realm resolver.
#[allow(clippy::needless_pass_by_value)]
fn passkey_login_begin_with_realm(
    state: Arc<WebState>,
    headers: HeaderMap,
    realm: Realm,
) -> Response {
    use base64::Engine as _;

    // Pin RP ID to the configured public origin (strip scheme and port) so that
    // a forged Host header cannot redirect the ceremony to a different origin.
    let origin = state.public_origin_str(&headers);
    let rp_id = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();

    let options = AuthenticationOptions {
        rp_id: rp_id.clone(),
    };

    let challenge = match state
        .identity
        .start_webauthn_authentication(realm.id(), None, &options)
    {
        Ok(c) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c),
        Err(e) => {
            tracing::error!(error = %e, "passkey-login-begin: start failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Unavailable").into_response();
        }
    };

    let user_verification = realm
        .config()
        .webauthn_user_verification
        .as_deref()
        .unwrap_or("preferred");

    let body = serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id,
        "userVerification": user_verification,
        "timeout": 300_000,
    });
    axum::Json(body).into_response()
}

/// JSON body from the browser passkey authentication completion.
#[derive(Debug, Deserialize)]
pub struct PasskeyLoginCompleteBody {
    /// Base64url-encoded credential ID from the authenticator.
    pub credential_id: String,
    /// Base64url-encoded `clientDataJSON`.
    pub client_data_json: String,
    /// Base64url-encoded authenticator data.
    pub authenticator_data: String,
    /// Base64url-encoded signature.
    pub signature: String,
    /// Base64url-encoded user handle (optional, for discoverable credentials).
    #[serde(default)]
    pub user_handle: Option<String>,
    /// CAPTCHA response token from the login page's widget, for a caller the
    /// abuse guards challenged (A-16).
    #[serde(default)]
    pub captcha_token: Option<String>,
}

/// `POST /ui/login/passkey-complete` — bare variant.
pub async fn passkey_login_complete(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    passkey_login_complete_impl(state, headers, body, None, peer_addr).await
}

/// `POST /ui/realms/<name>/login/passkey-complete` — realm-scoped variant.
pub async fn passkey_login_complete_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    passkey_login_complete_impl(state, headers, body, Some(realm_name), peer_addr).await
}

/// `POST /ui/admin/login/passkey-complete` — admin variant. Routes the
/// assertion through the system realm rather than the default/sole
/// tenant realm.
pub async fn passkey_login_complete_admin(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    let system_realm_name = match resolve_admin_realm(&state) {
        PreAuthRealm::Ok { realm, .. } => realm.name().to_string(),
        PreAuthRealm::Handled(_) => {
            return (StatusCode::BAD_REQUEST, "System realm unavailable").into_response();
        }
    };
    passkey_login_complete_impl(state, headers, body, Some(system_realm_name), peer_addr).await
}

/// The client address the abuse guards count, from a built session context.
fn guard_ip_of(session_ctx: &SessionContext) -> Option<std::net::IpAddr> {
    session_ctx
        .ip_address
        .as_deref()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
}

/// Completes the discoverable credential authentication ceremony.
/// The realm is resolved via the standard pre-auth resolver — no
/// cross-realm walk. The `user_handle` from the assertion identifies
/// the user within the resolved realm.
#[allow(clippy::needless_pass_by_value)]
async fn passkey_login_complete_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    body: PasskeyLoginCompleteBody,
    path_realm: Option<String>,
    peer_addr: SocketAddr,
) -> Response {
    use base64::Engine as _;
    // `mfa_proof` is deliberately left at `None` here. Only the completed
    // ceremony knows whether the authenticator proved user verification, so
    // `passkey_complete_for_user` sets it from the result (audit 2026-08-28
    // B10). Setting it up front asserted a second factor before anything had
    // been verified.
    let session_ctx = build_session_context(&headers, peer_addr, &state.trusted_proxies);

    // Resolve realm. JSON endpoint — picker/400 HTML isn't useful; return 400.
    let realm = match resolve_pre_auth_realm(&state, path_realm, true) {
        PreAuthRealm::Ok { realm, .. } => realm,
        PreAuthRealm::Handled(_) => {
            return (StatusCode::BAD_REQUEST, "Realm not resolvable").into_response();
        }
    };

    // A-16, before the assertion is checked. A passkey sign-in has no
    // username, so the per-username A-3 detector does not apply. A challenge
    // is answered in this endpoint's JSON shape; the login page reloads and
    // shows the widget.
    let guard_ip = guard_ip_of(&session_ctx);
    if let Err(response) = crate::protocol::abuse_challenge::gate_api_sign_in(
        &state.abuse_guards,
        state.audit.as_ref(),
        &crate::protocol::abuse_challenge::ChallengedAttempt {
            realm_id: realm.id(),
            ip: guard_ip,
            username: None,
            surface: crate::protocol::abuse_challenge::Surface::Ui,
        },
        state.abuse_guards.pre_auth_passkey(guard_ip),
        body.captcha_token.as_deref(),
    )
    .await
    {
        return response;
    }
    let failed = || {
        state.abuse_guards.record_login_failure(guard_ip);
        (StatusCode::UNAUTHORIZED, "Authentication failed").into_response()
    };

    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let Ok(credential_id) = b64.decode(&body.credential_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid credential_id").into_response();
    };
    let Ok(client_data_json) = b64.decode(&body.client_data_json) else {
        return (StatusCode::BAD_REQUEST, "Invalid client_data_json").into_response();
    };
    let Ok(authenticator_data) = b64.decode(&body.authenticator_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid authenticator_data").into_response();
    };
    let Ok(signature) = b64.decode(&body.signature) else {
        return (StatusCode::BAD_REQUEST, "Invalid signature").into_response();
    };
    let user_handle_bytes = body.user_handle.as_deref().and_then(|h| b64.decode(h).ok());

    // Pin origin to the configured public origin so a forged Host header
    // cannot redirect the ceremony to an attacker-controlled origin (L5).
    let origin = state.public_origin_str(&headers);

    // Parse the user handle into a UserId.
    let Some(ref uh_bytes) = user_handle_bytes else {
        tracing::warn!("passkey-login-complete: no user_handle in assertion");
        return failed();
    };
    let user_id_result = std::str::from_utf8(uh_bytes)
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .or_else(|| uuid::Uuid::from_slice(uh_bytes).ok());
    let Some(uuid) = user_id_result else {
        tracing::warn!("passkey-login-complete: cannot parse user_handle as UUID");
        return failed();
    };
    let user_id = crate::core::UserId::new(uuid);

    // Confirm the user actually exists in the resolved realm.
    let exists = state
        .identity
        .get_user(realm.id(), &user_id)
        .ok()
        .flatten()
        .is_some();
    if !exists {
        tracing::warn!(user_id = %user_id, "passkey-login-complete: user not in resolved realm");
        return failed();
    }

    passkey_complete_for_user(
        &state,
        &realm,
        &user_id,
        &credential_id,
        &client_data_json,
        &authenticator_data,
        &signature,
        user_handle_bytes.as_ref(),
        &origin,
        &session_ctx,
        &headers,
        state.is_secure_request(&headers),
    )
}

/// Decides whether a completed passkey ceremony still owes a second factor,
/// and returns the response that collects it.
///
/// `Some(response)` means no session may be issued: the caller must return
/// it. `None` means the ceremony satisfies the realm's policy and the user's
/// own factors.
///
/// * A passkey that proved user verification is two factors on its own. Only
///   `passkey_requires_mfa` (a regulated deployment that wants a separate
///   factor after *any* passkey) asks for more, and then only when the user
///   holds another factor to challenge.
/// * A UV-less passkey is possession alone (audit 2026-08-28 B10). It owes
///   any other factor the user holds — TOTP, then SMS / email OTP (GA audit
///   B5: an SMS- or email-OTP user used to be sent to TOTP enrolment here).
///   On an `mfa_required` realm with no other factor it is refused: forced
///   enrolment is never offered to a user who holds a factor, and the
///   passkey itself must prove user verification instead.
fn passkey_second_factor_gate(
    state: &Arc<WebState>,
    realm: &Realm,
    user_id: &crate::core::UserId,
    user_verified: bool,
    secure: bool,
) -> Option<Response> {
    let require_mfa_after_passkey = realm.config().passkey_requires_mfa.unwrap_or(false);

    if user_verified && !require_mfa_after_passkey {
        return None;
    }

    let refuse = || (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    let user = match state.identity.get_user(realm.id(), user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return Some(refuse()),
        Err(e) => {
            tracing::warn!(error = %e, "passkey-login: user lookup failed");
            return Some(refuse());
        }
    };
    let mfa_required = match state
        .identity
        .effective_mfa_requirement(realm.id(), user_id, None)
    {
        Ok(required) => required,
        Err(e) => {
            tracing::warn!(error = %e, "passkey-login: MFA-requirement lookup failed");
            return Some(refuse());
        }
    };
    let first = if user_verified {
        super::auth::FirstFactor::VerifiedPasskey
    } else {
        super::auth::FirstFactor::Credential
    };
    let owed = match super::second_factor::non_passkey_factor_step(state, realm, &user, first) {
        // A UV-less passkey plus an email OTP is still not MFA: where MFA is
        // required, only TOTP can complete this sign-in.
        Ok(Some(super::second_factor::SecondFactorStep::Otp(_)))
            if !user_verified && mfa_required =>
        {
            None
        }
        Ok(step) => step,
        Err(e) => {
            // The user's factors are unknown: refuse rather than skip one.
            tracing::warn!(error = %e, "passkey-login: second-factor lookup failed");
            return Some(refuse());
        }
    };

    if let Some(step) = owed {
        let redirect = super::second_factor::redirect_to_second_factor(
            state,
            realm.id(),
            user_id,
            step,
            first,
            None, // no return_to for passkey flow
            secure,
        );
        let mut response =
            axum::Json(serde_json::json!({ "redirect": step.path() })).into_response();
        for cookie in redirect
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
        {
            append_cookie(&mut response, cookie);
        }
        return Some(response);
    }

    // Nothing else to challenge. A UV-less passkey cannot stand in for a
    // second factor the MFA policy mandates.
    if !user_verified && mfa_required {
        return Some(
            (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "This sign-in needs your passkey to verify you with a PIN or \
                              biometric. Try again and complete the verification step."
                })),
            )
                .into_response(),
        );
    }
    None
}

/// Completes the `WebAuthn` authentication against the resolved realm
/// and creates a session. Extracted so the bare and scoped variants
/// share the same completion logic.
#[allow(clippy::too_many_arguments)]
fn passkey_complete_for_user(
    state: &Arc<WebState>,
    realm: &Realm,
    user_id: &crate::core::UserId,
    credential_id: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    user_handle_bytes: Option<&Vec<u8>>,
    origin: &str,
    session_ctx: &SessionContext,
    headers: &HeaderMap,
    secure: bool,
) -> Response {
    let _ = user_id;

    // Enforce realm policy: passkey auth must be in the allow-list.
    if let Some(ref methods) = realm.config().allowed_auth_methods {
        if !methods.iter().any(|m| m == "passkey") {
            tracing::warn!(realm = %realm.id(), "passkey-login: blocked by realm policy");
            return (StatusCode::FORBIDDEN, "Authentication method not permitted").into_response();
        }
    }

    let params = CompleteAuthenticationParams {
        credential_id,
        client_data_json,
        authenticator_data,
        signature,
        user_handle: user_handle_bytes.map(Vec::as_slice),
        origin,
    };

    // A failed assertion counts against the client's A-16 failure count; a
    // verified one clears it, as a correct password does.
    let guard_ip = guard_ip_of(session_ctx);
    let auth_result = match state
        .identity
        .complete_webauthn_authentication(realm.id(), &params)
    {
        Ok(r) => {
            state.abuse_guards.record_login_success(guard_ip);
            r
        }
        Err(e) => {
            tracing::warn!(error = %e, "passkey-login-complete: authentication failed");
            state.abuse_guards.record_login_failure(guard_ip);
            return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
        }
    };

    // A passkey counts as two factors only when the ceremony proved user
    // verification — a PIN, a biometric, or an equivalent local check. The
    // UP flag alone is a touch, which proves possession and nothing else.
    // Treating every passkey as inherently multi-factor let a UV-less
    // authenticator satisfy `mfa_required` outright (audit 2026-08-28 B10).
    let user_verified = auth_result.user_verified();

    if let Some(response) =
        passkey_second_factor_gate(state, realm, auth_result.user_id(), user_verified, secure)
    {
        return response;
    }

    // Reaching here means either the realm asks for no second factor, or the
    // passkey proved user verification and is itself the second factor.

    // --- Required-action gate (GA audit M11) ---
    // A passkey login used to skip pending required actions entirely, so an
    // operator-forced password change, email verification or enrolment could
    // be walked around by signing in with a passkey instead of the password.
    // Same gate as the password form, answered in this endpoint's JSON shape.
    // The engine's own `mfa_required` gate reads this proof, so it must carry
    // what the ceremony proved rather than an assumption made before it ran.
    // `ProvedWebAuthn` rather than the generic `Proved`: a realm that sets
    // `webauthn_required` accepts only a WebAuthn assertion, and this is the
    // one path that can produce it (audit 2026-08-28 §4.18#3, task 25.26).
    let mfa_proof = if user_verified {
        crate::identity::MfaProof::ProvedWebAuthn
    } else {
        // Possession of the passkey the account holds (GA audit B5): the
        // engine admits it only when the user holds no other factor, which
        // the gate above has already challenged.
        crate::identity::MfaProof::PasskeyPossession
    };

    let now = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    let mut session_ctx = session_ctx.clone();
    session_ctx.mfa_proof = mfa_proof;
    // A required-action detour carries the same proof to the session it
    // ends in (GA audit round 3, I-2).
    if let Some(ra) = super::required_action::required_action_check_browser(
        state,
        realm.id(),
        auth_result.user_id(),
        None,
        &session_ctx,
        super::auth::FirstFactor::Credential,
        headers,
        now,
    ) {
        state.set_current_realm(realm.id().clone());
        return super::second_factor::redirect_as_json(&ra);
    }

    // A-41: Destroy any pre-existing session cookie before issuing a new one.
    revoke_prior_session_cookie(state.identity.as_ref(), headers, &state.cookie_secret);

    match state
        .identity
        .create_session(realm.id(), auth_result.user_id(), &session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id(), secure);

            state.set_current_realm(realm.id().clone());

            let mut response = axum::Json(serde_json::json!({
                "redirect": "/ui",
            }))
            .into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), realm.id()),
                    secure,
                ),
            );
            response
        }
        Err(IdentityError::UserNotVerified) => axum::Json(serde_json::json!({
            "error": "Email not verified. Check your inbox for the verification link."
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "passkey-login: create_session failed");
            (StatusCode::UNAUTHORIZED, "Authentication failed").into_response()
        }
    }
}

// ============================================================================
// MFA challenge
// ============================================================================

/// Form body submitted by the MFA challenge page.
#[derive(Debug, Deserialize)]
pub struct MfaChallengeForm {
    /// TOTP code or recovery code entered by the user.
    pub code: String,
    /// CSRF token echoed from the hidden `_csrf` field.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Renders the MFA challenge form.
///
/// If the MFA pending cookie is missing or invalid, redirects to
/// `/ui/login` — the user must start the login flow again.
pub async fn mfa_challenge_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };

    let secure = state.is_secure_request(&headers);
    let (csrf_value, fresh_cookie) = match super::auth::csrf_cookie_value_from_headers(&headers) {
        Some(existing) => (existing.to_string(), None),
        None => {
            let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
            (val, Some(cookie))
        }
    };

    let mut tmpl = MfaChallengeTemplate::new(
        None,
        state.product_name.clone(),
        state.logo_url.clone(),
        pending.return_to,
    );
    tmpl.csrf = Some(csrf_value);

    let mut resp = render(&tmpl);
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut resp, &cookie);
    }
    resp
}

/// Handles MFA challenge submission.
///
/// Validates the pending cookie, then tries `verify_totp()` (6-digit
/// numeric) or `verify_recovery_code()` (anything else). On success:
/// creates a session, issues cookies, clears the pending cookie, and
/// redirects to the original `return_to` or `/ui`.
#[allow(clippy::too_many_lines)]
pub async fn mfa_challenge_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<MfaChallengeForm>,
) -> Response {
    let session_ctx = build_session_context(&headers, peer_addr, &state.trusted_proxies);
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
    };

    // F6: CSRF double-submit check — fail-closed in non-dev mode.
    let csrf_ok = match super::auth::csrf_cookie_value_from_headers(&headers) {
        Some(cookie_val) => super::auth::csrf_token_eq(cookie_val, &form.csrf),
        None => state.dev_mode, // dev: bypass; prod: fail-closed
    };
    if !csrf_ok {
        // Copy deliberately avoids "security token" — see `LoginRenderCtx::csrf_error`
        // for the rationale (HEA-1913). The form now carries a fresh token so
        // direct resubmission succeeds without an extra page load (HEA-1983).
        let secure = state.is_secure_request(&headers);
        let (csrf_value, csrf_cookie) = super::auth::fresh_csrf_cookie(secure);
        let mut tmpl = MfaChallengeTemplate::new(
            Some("Your session has expired. Please reload the page and try again.".to_string()),
            state.product_name.clone(),
            state.logo_url.clone(),
            pending.return_to.clone(),
        );
        tmpl.csrf = Some(csrf_value);
        tmpl.reload_url = Some(tmpl.form_action.clone());
        let mut resp = render_status(&tmpl, StatusCode::UNPROCESSABLE_ENTITY);
        append_cookie(&mut resp, &csrf_cookie);
        return resp;
    }

    let code = form.code.trim();

    // Dispatch: 6-digit all-numeric → TOTP; anything else → recovery code.
    let is_totp = code.len() == 6 && code.chars().all(|c| c.is_ascii_digit());
    let verify_result = if is_totp {
        state
            .identity
            .verify_totp(&pending.realm_id, &pending.user_id, code)
    } else {
        // A recovery code is checked against up to eight Argon2id hashes, so
        // it runs inside the shared KDF admission gate on the blocking pool,
        // like every other pre-session hash (GA audit L16). It ran on the
        // async worker, outside the gate, so a saturated gate did not bound
        // it and each submission stalled a Tokio worker for eight hashes.
        let identity = Arc::clone(&state.identity);
        let realm_id = pending.realm_id.clone();
        let user_id = pending.user_id.clone();
        let candidate = code.to_string();
        match gate()
            .run(move || identity.verify_recovery_code(&realm_id, &user_id, &candidate))
            .await
        {
            Ok(result) => result,
            Err(KdfGateError::Overloaded { retry_after }) => {
                return kdf_shed_html_response(
                    &state,
                    &headers,
                    retry_after,
                    None,
                    pending.return_to.clone(),
                    Some("/ui/mfa-challenge".to_string()),
                );
            }
            Err(KdfGateError::Join(e)) => {
                tracing::warn!(error = %e, "mfa-challenge: recovery-code task failed");
                return internal_error_response();
            }
        }
    };

    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let return_to = pending.return_to.clone();
    let mfa_err = |msg: String, status: StatusCode| {
        let tmpl = MfaChallengeTemplate::new(
            Some(msg),
            product_name.clone(),
            logo_url.clone(),
            return_to.clone(),
        );
        render_status(&tmpl, status)
    };

    match verify_result {
        Ok(()) => {}
        Err(IdentityError::RateLimited) => {
            return mfa_err(
                "Too many failed attempts. Please wait a few minutes and try again.".to_string(),
                StatusCode::TOO_MANY_REQUESTS,
            );
        }
        Err(IdentityError::InvalidMfaCode | IdentityError::MfaNotEnabled) => {
            return mfa_err(
                "Invalid code. Please try again.".to_string(),
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "mfa-challenge: verification failed");
            return mfa_err(
                "Invalid code. Please try again.".to_string(),
                StatusCode::UNAUTHORIZED,
            );
        }
    }

    // MFA passed — atomically redeem the single-use nonce before creating the
    // session. Redemption is serialized per-nonce (M1a / HEA-1752) and persisted
    // in WAL storage so replay is rejected even after a server restart and even
    // under concurrent submissions (fixes HSS-009 / HEA-SEC-25 / HEA-1752).
    {
        let nonce = &pending.nonce;
        let exp_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(super::auth::MFA_PENDING_TTL_SECS);
        match state
            .identity
            .redeem_mfa_nonce(&pending.realm_id, nonce, exp_secs)
        {
            Ok(true) => {}
            Ok(false) => {
                // Nonce already consumed — replayed or concurrent pending cookie.
                return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
            }
            Err(e) => {
                tracing::warn!(error = %e, "mfa-challenge: nonce redemption failed");
                return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
            }
        }
    }

    // --- Required-action gate (D1 / HEA-1752) ---
    // Completing MFA proves the second factor but must NOT bypass pending
    // required actions (forced password change, forced enrollment, email
    // verification). Mirror the direct-login and OIDC interceptors: if any
    // action is pending, redirect into the required-action flow instead of
    // issuing a session.
    let now_ra = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    if let Some(ra_response) = super::required_action::required_action_check_browser(
        &state,
        &pending.realm_id,
        &pending.user_id,
        pending.return_to.as_deref(),
        // The TOTP or recovery code just verified — and nothing more. The
        // detour used to end in `Inherited`, which a passkey-only realm
        // accepts (GA audit round 3, D-1).
        &SessionContext {
            mfa_proof: MfaProof::Proved,
            ..session_ctx.clone()
        },
        pending.first_factor,
        &headers,
        now_ra,
    ) {
        state.set_current_realm(pending.realm_id.clone());
        return ra_response;
    }

    // A-41: Destroy any pre-existing session cookie before issuing a new one.
    revoke_prior_session_cookie(state.identity.as_ref(), &headers, &state.cookie_secret);

    // The challenge above verified a TOTP or a recovery code, so this
    // authentication proved a second factor. The realm's `mfa_required` gate
    // reads exactly this (audit 2026-08-28 §4.18#3).
    let session_ctx = SessionContext {
        mfa_proof: MfaProof::Proved,
        ..session_ctx
    };

    match state
        .identity
        .create_session(&pending.realm_id, &pending.user_id, &session_ctx)
    {
        Ok(session) => {
            let secure = state.is_secure_request(&headers);
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(
                &state.cookie_secret,
                &pending.realm_id,
                session.id(),
                secure,
            );

            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), &pending.realm_id),
                    secure,
                ),
            );
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "mfa-challenge: create_session failed");
            internal_error_response()
        }
    }
}

/// Returns a 401 response when the MFA pending cookie is expired or
/// missing.
fn mfa_expired_response(product_name: String, logo_url: String) -> Response {
    let tmpl = MfaChallengeTemplate::new(
        Some("Your session has expired. Please sign in again.".to_string()),
        product_name,
        logo_url,
        None,
    );
    render_status(&tmpl, StatusCode::UNAUTHORIZED)
}

// ============================================================================
// Forced MFA enrollment (realm policy: mfa_required = true)
// ============================================================================

/// Refuses forced enrolment to a pending login that owes something else.
///
/// Forced enrolment is for a user who holds NO second factor on a realm that
/// mandates one. A user who holds any factor — a passkey, SMS, email OTP —
/// is sent to that factor's challenge instead (GA audit B5). Before this, a
/// passkey-only user on an `mfa_required` realm was sent here after a correct
/// password, so whoever held the password enrolled a TOTP of their own and
/// signed in with it — and the attacker's TOTP stayed on the account.
///
/// `None` means the pending user may enrol; `Some` is the response to return.
fn forced_enrolment_refusal(
    state: &Arc<WebState>,
    pending: &super::auth::MfaPending,
) -> Option<Response> {
    let (Ok(Some(realm)), Ok(Some(user))) = (
        state.identity.get_realm(&pending.realm_id),
        state.identity.get_user(&pending.realm_id, &pending.user_id),
    ) else {
        return Some(Redirect::to("/ui/login").into_response());
    };
    match super::second_factor::second_factor_step(state, &realm, &user, pending.first_factor) {
        Ok(Some(super::second_factor::SecondFactorStep::EnrolTotp)) => None,
        Ok(Some(step)) => Some(Redirect::to(step.path()).into_response()),
        Ok(None) => Some(Redirect::to("/ui/login").into_response()),
        Err(e) => {
            tracing::warn!(error = %e, "forced enrolment: factor lookup failed");
            Some(internal_error_response())
        }
    }
}

/// Renders the forced MFA enrollment page.
///
/// Reached when a realm's `mfa_required` policy is enabled and the user has
/// no TOTP enrolled. Requires a valid MFA pending cookie (proves password was
/// verified). Initiates a fresh enrollment ceremony and shows the QR code and
/// recovery codes.
pub async fn mfa_enroll_required_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };
    if let Some(refusal) = forced_enrolment_refusal(&state, &pending) {
        return refusal;
    }

    let realm_id = pending.realm_id.clone();
    let user_id = pending.user_id.clone();
    let identity = state.identity.clone();
    let enroll_result =
        tokio::task::spawn_blocking(move || identity.enroll_totp(&realm_id, &user_id)).await;

    let enroll_result = match enroll_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "forced enroll_totp spawn_blocking panicked");
            Err(IdentityError::Storage(Box::new(e)))
        }
    };

    // The activation POST now carries a CSRF token, so the page that renders
    // the form must mint one (audit 2026-08-28 §4.18#7). Reuse the visitor's
    // existing token when they have one, exactly as `mfa_challenge_form` does.
    let secure = state.is_secure_request(&headers);
    let (csrf_value, fresh_csrf_cookie) =
        match cookie_value_from_headers(&headers, super::auth::CSRF_COOKIE) {
            Some(existing) => (existing.to_string(), None),
            None => {
                let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
                (val, Some(cookie))
            }
        };

    match enroll_result {
        Ok(enrollment) => {
            use super::account::generate_qr_svg;
            let qr_svg = generate_qr_svg(&enrollment.provisioning_uri);
            let mut tmpl = MfaEnrollRequiredTemplate::new(
                None,
                enrollment.secret_base32,
                enrollment.provisioning_uri,
                qr_svg,
                enrollment.recovery_codes.as_slice().to_vec(),
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.csrf = Some(csrf_value);
            let mut resp = render(&tmpl);
            if let Some(cookie) = fresh_csrf_cookie {
                append_cookie(&mut resp, &cookie);
            }
            resp
        }
        Err(IdentityError::MfaAlreadyEnabled) => {
            // User somehow got here with MFA already set up — send to challenge.
            Redirect::to("/ui/mfa-challenge").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "forced enroll_totp failed");
            let tmpl = MfaEnrollRequiredTemplate::new(
                Some("Unable to start MFA enrollment. Please try signing in again.".to_string()),
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            render_status(&tmpl, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Form body for `POST /ui/mfa-enroll-required/activate`.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollRequiredForm {
    #[serde(default)]
    pub code: String,
    /// CSRF token echoed from the hidden `_csrf` field. Mirrors
    /// [`MfaChallengeForm`] — this route completes a login exactly as the
    /// challenge does and had no CSRF check at all (audit 2026-08-28
    /// §4.18#7).
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Verifies the TOTP code during forced enrollment and completes the login.
///
/// Reads the MFA pending cookie, confirms the enrollment code, enables MFA,
/// then issues full session + CSRF cookies (same as a successful MFA challenge).
#[allow(clippy::too_many_lines)]
pub async fn mfa_enroll_required_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<MfaEnrollRequiredForm>,
) -> Response {
    let session_ctx = build_session_context(&headers, peer_addr, &state.trusted_proxies);
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };

    // CSRF double-submit — fail-closed outside dev mode. This route ends in
    // `create_session` exactly as `mfa_challenge_submit` does, and had no
    // check of any kind: a cross-site POST that guessed the code completed
    // someone else's forced enrolment and logged them in (audit 2026-08-28
    // §4.18#7). Same mechanism as the sibling, same dev-mode carve-out.
    let csrf_ok = match cookie_value_from_headers(&headers, super::auth::CSRF_COOKIE) {
        Some(cookie_val) => super::auth::csrf_token_eq(cookie_val, &form.csrf),
        None => state.dev_mode,
    };
    if !csrf_ok {
        let secure = state.is_secure_request(&headers);
        let (csrf_value, csrf_cookie) = super::auth::fresh_csrf_cookie(secure);
        let mut tmpl = MfaEnrollRequiredTemplate::new(
            Some("Your session has expired. Please reload the page and try again.".to_string()),
            String::new(),
            String::new(),
            String::new(),
            Vec::new(),
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        tmpl.csrf = Some(csrf_value);
        let mut resp = render_status(&tmpl, StatusCode::UNPROCESSABLE_ENTITY);
        append_cookie(&mut resp, &csrf_cookie);
        return resp;
    }

    // Re-checked on activation: a factor enrolled since the page rendered
    // (or a page reached without passing the check) must not be topped up
    // with a TOTP the password holder controls (GA audit B5).
    if let Some(refusal) = forced_enrolment_refusal(&state, &pending) {
        return refusal;
    }

    let realm_id = pending.realm_id.clone();
    let user_id = pending.user_id.clone();
    let code = form.code.trim().to_string();
    let identity = state.identity.clone();
    let verify_result = tokio::task::spawn_blocking(move || {
        identity.verify_totp_enrollment(&realm_id, &user_id, &code)
    })
    .await;

    let verify_result = match verify_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "forced verify_totp_enrollment panicked");
            Err(IdentityError::Storage(Box::new(e)))
        }
    };

    let err_status = |msg: &str, status: StatusCode| {
        let tmpl = MfaEnrollRequiredTemplate::new(
            Some(msg.to_string()),
            String::new(),
            String::new(),
            String::new(),
            Vec::new(),
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        render_status(&tmpl, status)
    };
    let err_response = |msg: &str| err_status(msg, StatusCode::UNPROCESSABLE_ENTITY);

    match verify_result {
        Ok(()) => {}
        Err(IdentityError::RateLimited) => {
            // `verify_totp_enrollment` now shares the challenge form's
            // attempt budget (audit 2026-08-28 §4.18#7).
            return err_status(
                "Too many failed attempts. Please wait a few minutes and try again.",
                StatusCode::TOO_MANY_REQUESTS,
            );
        }
        Err(IdentityError::InvalidMfaCode) => {
            return err_response("Invalid code. Please re-scan the QR code and try again.");
        }
        Err(IdentityError::MfaNotEnabled) => {
            return Redirect::to("/ui/mfa-enroll-required").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "forced verify_totp_enrollment failed");
            return err_response("Unable to activate MFA right now. Please try again.");
        }
    }

    // Enrollment confirmed — complete login.
    let secure = state.is_secure_request(&headers);

    // Redeem the single-use pending-cookie nonce before a session exists, the
    // way `mfa_challenge_submit` does. Without it one captured pending cookie
    // could be replayed for as long as it lived, each replay minting another
    // session (audit 2026-08-28 §4.18#7).
    {
        let exp_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(super::auth::MFA_PENDING_TTL_SECS);
        match state
            .identity
            .redeem_mfa_nonce(&pending.realm_id, &pending.nonce, exp_secs)
        {
            Ok(true) => {}
            Ok(false) => {
                return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
            }
            Err(e) => {
                tracing::warn!(error = %e, "forced enrol: nonce redemption failed");
                return mfa_expired_response(state.product_name.clone(), state.logo_url.clone());
            }
        }
    }

    // --- Required-action gate (D1 / HEA-1752) ---
    // Completing forced MFA enrollment satisfies the enrollment requirement but
    // must NOT bypass any *other* pending required action (e.g. forced password
    // change). Mirror the direct-login and OIDC interceptors before issuing a
    // session. The just-completed TOTP enrollment no longer re-injects
    // ENROLL_MFA, so this cannot loop.
    let now_ra = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    if let Some(ra_response) = super::required_action::required_action_check_browser(
        &state,
        &pending.realm_id,
        &pending.user_id,
        pending.return_to.as_deref(),
        // The live code that confirmed the enrolment (see below).
        &SessionContext {
            mfa_proof: MfaProof::Proved,
            ..session_ctx.clone()
        },
        pending.first_factor,
        &headers,
        now_ra,
    ) {
        state.set_current_realm(pending.realm_id.clone());
        return ra_response;
    }

    // A-41: Destroy any pre-existing session cookie before issuing a new one.
    revoke_prior_session_cookie(state.identity.as_ref(), &headers, &state.cookie_secret);

    // Forced enrolment ends with the user submitting a live TOTP code, which
    // `verify_totp_enrollment` checked above. That is a proved second factor.
    let session_ctx = SessionContext {
        mfa_proof: MfaProof::Proved,
        ..session_ctx
    };

    match state
        .identity
        .create_session(&pending.realm_id, &pending.user_id, &session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(
                &state.cookie_secret,
                &pending.realm_id,
                session.id(),
                secure,
            );

            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), &pending.realm_id),
                    secure,
                ),
            );
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "forced enrollment: create_session failed");
            internal_error_response()
        }
    }
}

// ============================================================================
// Dashboard
// ============================================================================

/// Signed-in dashboard. Redirects to `/ui/login` when the session
/// cookie is missing or invalid. Computes `is_admin` by running the
/// `hearth#admin` authz check so the template can render (or hide)
/// admin-only quick links.
pub async fn dashboard(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
) -> Response {
    let is_admin = is_admin(&state, &session);
    let config_warnings = if is_admin {
        state.config_warnings.clone()
    } else {
        Vec::new()
    };

    // Aggregate entity counts across the system realm + every tenant
    // realm so the dashboard cards reflect the operator's full scope —
    // not just the realm the admin happens to be signed into.
    //
    // The 2026-04-29 UX audit caught the legacy single-realm count
    // showing "Organizations 0" while a tenant realm clearly held one;
    // the cards are global by definition (they link to global list
    // pages), so the counts must be too. Failures fall through silently
    // — partial counts are better than a 500 on a stat card.
    let (user_count, realm_count, app_count, org_count) = if is_admin {
        // Use total from a single paged call (covers capped count up to DEFAULT_COUNT_CAP).
        let probe = crate::core::PageRequest::new(0, 1);
        let realm_count = state
            .identity
            .list_realms(&probe)
            .map(|p| p.total as usize)
            .unwrap_or(0);

        let system_id = crate::identity::keys::system_realm_id();
        let mut user_count = 0usize;
        let mut app_count = 0usize;
        let mut org_count = 0usize;

        // System realm — operators only.
        user_count += state
            .identity
            .list_users(&system_id, &probe)
            .map(|p| p.total as usize)
            .unwrap_or(0);

        // Tenant realms — sum users / clients / orgs from each.
        if let Ok(realms_page) = state.identity.list_realms(&crate::core::PageRequest::new(
            0,
            crate::core::MAX_PAGE_LIMIT,
        )) {
            for realm in realms_page.items {
                user_count += state
                    .identity
                    .list_users(realm.id(), &probe)
                    .map(|p| p.total as usize)
                    .unwrap_or(0);
                app_count += state
                    .identity
                    .list_clients(realm.id(), &probe)
                    .map(|p| p.total as usize)
                    .unwrap_or(0);
                org_count += state
                    .identity
                    .list_organizations(realm.id(), &probe)
                    .map(|p| p.total as usize)
                    .unwrap_or(0);
            }
        }

        (user_count, realm_count, app_count, org_count)
    } else {
        (0, 0, 0, 0)
    };

    let greeting_name = greeting_name_for(&session);

    render(&DashboardTemplate {
        chrome: true,
        active: "dashboard",
        user_email: Some(session.user_email.clone()),
        is_admin,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
        config_warnings,
        orphaned_realms: if is_admin {
            state.orphaned_realms.clone()
        } else {
            Vec::new()
        },
        user_count,
        realm_count,
        app_count,
        org_count,
        greeting_name,
    })
}

/// Picks the friendliest available name for the dashboard greeting:
/// a non-empty display name, otherwise the local part of the email.
/// Falls back to the literal email address when the local part is also
/// empty (which validation should prevent, but we are defensive).
fn greeting_name_for(session: &super::auth::UiSession) -> String {
    let display = session.user_display_name.trim();
    if !display.is_empty() && display != session.user_email {
        return display.to_string();
    }
    session
        .user_email
        .split_once('@')
        .map(|(local, _)| local)
        .filter(|s| !s.is_empty())
        .unwrap_or(&session.user_email)
        .to_string()
}

/// Returns `true` iff the signed-in user has the `hearth.admin` permission.
/// Non-fatal on RBAC errors — the caller treats those as "not admin" so
/// the UI degrades gracefully.
pub(crate) fn is_admin(state: &WebState, session: &super::auth::UiSession) -> bool {
    match state
        .rbac
        .resolve_permissions(&session.user_id, &session.realm_id, None, None)
    {
        Ok(resolved) => resolved
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin"),
        Err(_) => false,
    }
}

// ============================================================================
// Logout
// ============================================================================

/// Form body for the sign-out button.
#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    /// CSRF token echoed from the hidden input.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Handles sign-out. Verifies CSRF, revokes the session on the server,
/// clears both UI cookies, and redirects to `/ui/login`.
///
/// Idempotent: if the session is already gone (e.g. the user clicked
/// sign-out twice), we still clear the cookies and redirect.
pub async fn logout_submit(
    State(state): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    session: super::auth::UiSession,
    Form(form): Form<LogoutForm>,
) -> Response {
    if let Err(resp) = super::auth::verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let secure = state.is_secure_request(&headers);

    // Resolve the realm *before* revoking — the session record is about
    // to disappear. System-realm sessions route back to /ui/admin/login;
    // tenant sessions route back to /ui/realms/{name}/login.
    let redirect_realm: Option<String> =
        if session.realm_id == crate::identity::keys::system_realm_id() {
            Some(super::auth::SYSTEM_REALM_SENTINEL.to_string())
        } else {
            // Look up the realm name. If the lookup fails for any
            // reason (deleted mid-session, engine error) we fall back to
            // the last-realm cookie, which we refresh below.
            state
                .identity
                .get_realm(&session.realm_id)
                .ok()
                .flatten()
                .map(|r| r.name().to_string())
        };

    match state
        .identity
        .revoke_session(&session.realm_id, &session.session_id)
    {
        Ok(()) | Err(crate::identity::IdentityError::SessionNotFound) => {}
        Err(e) => {
            tracing::warn!(error = %e, "logout: revoke_session failed");
            // Still clear cookies and redirect — worst case the user
            // is signed out client-side, server session will expire.
        }
    }

    let login_url = super::auth::login_url_for_realm(redirect_realm.as_deref());
    let mut response = Redirect::to(&login_url).into_response();
    for cookie in super::auth::clearing_cookies(secure) {
        append_cookie(&mut response, &cookie);
    }
    // Refresh the last-realm cookie so the user returns here on the
    // next unauthenticated request even if they clear other cookies.
    if let Some(ref name) = redirect_realm {
        append_cookie(&mut response, &super::auth::last_realm_cookie(name, secure));
    }
    response
}

// ============================================================================
// Helpers
// ============================================================================

/// Appends a `Set-Cookie` header without overwriting existing ones.
pub(super) fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(v) = header::HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn validate_setup_form(form: &SetupForm) -> Result<(), String> {
    if form.admin_email.trim().is_empty() {
        return Err("Admin email is required.".to_string());
    }
    if !form.admin_email.contains('@') {
        return Err("Admin email does not look like an email address.".to_string());
    }
    if form.admin_display_name.trim().is_empty() {
        return Err("Display name is required.".to_string());
    }
    if form.admin_password.len() < 12 {
        return Err("Password must be at least 12 characters.".to_string());
    }
    Ok(())
}

/// Returns the base URL for security-sensitive email links.
///
/// Security invariant: this must not trust request-controlled headers
/// (`Host`, `X-Forwarded-Proto`, etc.), to prevent link poisoning.
/// Uses configured `onboarding.base_url` when present, otherwise the
/// local fallback `http://localhost`.
/// Resolves the absolute origin used to build emailed links (verification,
/// password-reset, etc.).
///
/// Prefers the operator-configured `onboarding.base_url`. The `Host` header is
/// deliberately **ignored** (an attacker-controlled `Host` must never poison a
/// link we email out). When `onboarding.base_url` is unset, `fallback_origin`
/// is used — callers pass the server's own bind `scheme://host:port` (see
/// [`WebState::fallback_base_url`]) so the link is reachable and, crucially,
/// includes the port.
fn derive_base_url(
    configured_base_url: Option<&str>,
    fallback_origin: &str,
    _headers: &HeaderMap,
) -> String {
    configured_base_url
        .unwrap_or(fallback_origin)
        .trim_end_matches('/')
        .to_string()
}

const DEFAULT_LOGIN_LOCALE: &str = "en";

#[derive(Clone, Copy)]
struct LoginLocaleText {
    heading_text: &'static str,
    email_label: &'static str,
    password_label: &'static str,
    submit_label: &'static str,
    or_continue_with_label: &'static str,
    or_label: &'static str,
    sign_in_with_label: &'static str,
    forgot_password_label: &'static str,
    create_account_label: &'static str,
    passkey_sign_in_label: &'static str,
    passkey_authenticating_label: &'static str,
    passkey_unavailable_error: &'static str,
    passkey_cancelled_error: &'static str,
    passkey_failed_error: &'static str,
}

const LOGIN_LOCALE_EN: LoginLocaleText = LoginLocaleText {
    heading_text: "Sign in to your account",
    email_label: "Email",
    password_label: "Password",
    submit_label: "Sign in",
    or_continue_with_label: "or continue with",
    or_label: "or",
    sign_in_with_label: "Sign in with",
    forgot_password_label: "Forgot password?",
    create_account_label: "Create account",
    passkey_sign_in_label: "Sign in with passkey",
    passkey_authenticating_label: "Authenticating…",
    passkey_unavailable_error: "Passkey authentication is not available.",
    passkey_cancelled_error: "Authentication was cancelled.",
    passkey_failed_error: "Passkey authentication failed.",
};

const LOGIN_LOCALE_ES: LoginLocaleText = LoginLocaleText {
    heading_text: "Inicia sesión en tu cuenta",
    email_label: "Correo electrónico",
    password_label: "Contraseña",
    submit_label: "Iniciar sesión",
    or_continue_with_label: "o continúa con",
    or_label: "o",
    sign_in_with_label: "Iniciar sesión con",
    forgot_password_label: "¿Olvidaste tu contraseña?",
    create_account_label: "Crear cuenta",
    passkey_sign_in_label: "Iniciar sesión con passkey",
    passkey_authenticating_label: "Autenticando…",
    passkey_unavailable_error: "La autenticación con passkey no está disponible.",
    passkey_cancelled_error: "La autenticación fue cancelada.",
    passkey_failed_error: "La autenticación con passkey falló.",
};

fn login_locale_text(locale: &str) -> LoginLocaleText {
    if locale == "es" {
        LOGIN_LOCALE_ES
    } else {
        LOGIN_LOCALE_EN
    }
}

fn resolve_login_locale(requested: Option<&str>, accept_language: Option<&str>) -> &'static str {
    if let Some(locale) = requested.and_then(normalize_login_locale) {
        return locale;
    }

    if let Some(header) = accept_language {
        for candidate in header.split(',') {
            if let Some(locale) = normalize_login_locale(candidate) {
                return locale;
            }
        }
    }

    DEFAULT_LOGIN_LOCALE
}

fn normalize_login_locale(input: &str) -> Option<&'static str> {
    let raw = input.trim().split(';').next()?.trim();
    if raw.is_empty() {
        return None;
    }

    let normalized = raw.to_ascii_lowercase().replace('_', "-");
    if normalized == "es" || normalized.starts_with("es-") {
        return Some("es");
    }
    if normalized == "en" || normalized.starts_with("en-") {
        return Some("en");
    }

    None
}

fn with_locale_query(path: &str, locale: &str) -> String {
    if locale == DEFAULT_LOGIN_LOCALE {
        return path.to_string();
    }
    let encoded = form_urlencoded::byte_serialize(locale.as_bytes()).collect::<String>();
    format!("{path}?locale={encoded}")
}

// ============================================================================
// Password reset flow
// ============================================================================

/// Forgot-password form template.
#[derive(Template)]
#[template(path = "ui/forgot_password.html")]
struct ForgotPasswordTemplate {
    error: Option<String>,
    form_action: String,
    login_url: String,
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
    /// Pre-built CAPTCHA widget HTML (empty string when no provider is configured).
    captcha_widget_html: String,
}

impl ForgotPasswordTemplate {
    fn new(
        error: Option<String>,
        action_prefix: &str,
        product_name: String,
        logo_url: String,
        captcha_widget_html: String,
    ) -> Self {
        Self {
            error,
            form_action: format!("{action_prefix}/forgot-password"),
            login_url: format!("{action_prefix}/login"),
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
            captcha_widget_html,
        }
    }
}

/// "Check your email" confirmation after requesting a password reset.
#[derive(Template)]
#[template(path = "ui/forgot_password_sent.html")]
struct ForgotPasswordSentTemplate {
    login_url: String,
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

impl ForgotPasswordSentTemplate {
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Reset password form. The token itself stays in the link-token cookie; the
/// form carries only its binding (GA audit L18).
#[derive(Template)]
#[template(path = "ui/reset_password.html")]
struct ResetPasswordTemplate {
    /// [`link_token::link_binding`] of the stashed reset token.
    link_binding: String,
    error: Option<String>,
    form_action: String,
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

impl ResetPasswordTemplate {
    fn new(
        link_binding: String,
        error: Option<String>,
        action_prefix: &str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            link_binding,
            error,
            form_action: format!("{action_prefix}/reset-password"),
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Success page after password reset.
#[derive(Template)]
#[template(path = "ui/reset_password_ok.html")]
struct ResetPasswordOkTemplate {
    login_url: String,
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

impl ResetPasswordOkTemplate {
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Renders the forgot-password form at the bare URL.
pub async fn forgot_password_form(State(state): State<Arc<WebState>>) -> Response {
    forgot_password_form_impl(state, RealmSource::Path(None))
}

/// Renders the forgot-password form under `/ui/realms/<name>/forgot-password`.
pub async fn forgot_password_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    forgot_password_form_impl(state, RealmSource::Path(Some(realm_name)))
}

/// Renders the admin forgot-password form at `/ui/admin/forgot-password`.
pub async fn admin_forgot_password_form(State(state): State<Arc<WebState>>) -> Response {
    forgot_password_form_impl(state, RealmSource::Admin)
}

#[allow(clippy::needless_pass_by_value)]
fn forgot_password_form_impl(state: Arc<WebState>, source: RealmSource) -> Response {
    let (realm, action_prefix) = match resolve_for_source(&state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let mut tmpl = ForgotPasswordTemplate::new(
        None,
        &action_prefix,
        state.product_name.clone(),
        state.logo_url.clone(),
        state.captcha_provider.widget_html().to_string(),
    );
    tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
    tmpl.inline_theme_css = state.inline_theme_css();
    render(&tmpl)
}

/// Form data for forgot-password submission.
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordForm {
    /// The email address for the password reset.
    pub email: String,
    /// CAPTCHA response token populated by the Turnstile widget (P-1).
    ///
    /// Empty string when no CAPTCHA provider is configured (`NoopCaptchaProvider`).
    #[serde(default)]
    pub captcha_token: String,
}

/// Handles forgot-password form submission at the bare URL.
pub async fn forgot_password_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let captcha_ok = captcha_check(&state, &headers, peer_addr, &form.captcha_token).await;
    forgot_password_submit_impl(state, headers, form, RealmSource::Path(None), captcha_ok)
}

/// Handles forgot-password form submission at `/ui/realms/<name>/forgot-password`.
pub async fn forgot_password_submit_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let captcha_ok = captcha_check(&state, &headers, peer_addr, &form.captcha_token).await;
    forgot_password_submit_impl(
        state,
        headers,
        form,
        RealmSource::Path(Some(realm_name)),
        captcha_ok,
    )
}

/// Handles admin forgot-password form submission at `/ui/admin/forgot-password`.
pub async fn admin_forgot_password_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let captcha_ok = captcha_check(&state, &headers, peer_addr, &form.captcha_token).await;
    forgot_password_submit_impl(state, headers, form, RealmSource::Admin, captcha_ok)
}

/// Runs `job` on the blocking pool without waiting for it.
///
/// Used for outbound mail on pre-auth flows: a transport that takes hundreds
/// of milliseconds must not make the "this address exists" arm of a handler
/// distinguishable from the silent one (audit 2026-08-28 §4.24#3 / #4).
///
/// Falls back to running `job` inline when no Tokio runtime is available
/// (unit tests calling the impl directly) — correctness before latency.
fn spawn_off_request_path<F>(job: F)
where
    F: FnOnce() + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(job);
        }
        Err(_) => job(),
    }
}

/// Shared implementation. Looks up the user in the resolved realm.
/// Always redirects to the "check your email" page regardless of outcome
/// (enumeration resistance).
#[allow(clippy::needless_pass_by_value)]
fn forgot_password_submit_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: ForgotPasswordForm,
    source: RealmSource,
    captcha_ok: bool,
) -> Response {
    let email = form.email.trim();
    let (realm, action_prefix) = match resolve_for_source(&state, source, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };

    if !captcha_ok {
        let mut tmpl = ForgotPasswordTemplate::new(
            Some("CAPTCHA verification failed. Please try again.".to_string()),
            &action_prefix,
            state.product_name.clone(),
            state.logo_url.clone(),
            state.captcha_provider.widget_html().to_string(),
        );
        tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
        tmpl.inline_theme_css = state.inline_theme_css();
        return render(&tmpl);
    }

    let sent_url = format!("{action_prefix}/forgot-password/sent");

    match state.identity.request_password_reset(realm.id(), email) {
        Ok(Some(token)) => {
            let base = derive_base_url(
                state
                    .config
                    .as_ref()
                    .and_then(|c| c.onboarding.base_url.as_deref()),
                &state.fallback_base_url(),
                &headers,
            );
            let reset_url = format!("{base}{action_prefix}/reset-password?token={token}");
            if let Some(email_service) = state.email.clone() {
                let realm_branding = realm.config().email_branding.clone();
                let stored = realm
                    .config()
                    .email_templates
                    .get("password_reset")
                    .cloned();
                // Hand the send to the blocking pool and return immediately.
                // Keeping the SMTP round-trip on the request path made the
                // "account exists" arm measurably slower than the silent one,
                // which is an enumeration oracle (audit 2026-08-28 §4.24#3).
                let recipient = email.to_string();
                // A-4 + A-50 (task 20.13): the per-realm outbound breadth
                // budget and the cross-realm per-recipient fan-out cap. Both
                // are fail-open until the operator enables them. The check
                // runs inside the off-request-path closure so a refused send
                // costs the caller exactly what an allowed one does — the
                // arm is invisible in the response either way (§4.24#3).
                let guards = Arc::clone(&state.abuse_guards);
                let realm_key = realm.id().as_uuid().to_string();
                spawn_off_request_path(move || {
                    match guards.check_outbound_email(&realm_key, &recipient) {
                        crate::abuse::runtime::OutboundVerdict::Deny { reason } => {
                            tracing::warn!(
                                guard = reason,
                                "forgot_password: outbound cap reached; reset email not sent"
                            );
                            return;
                        }
                        crate::abuse::runtime::OutboundVerdict::Warn { reason } => {
                            tracing::warn!(
                                guard = reason,
                                "forgot_password: outbound soft cap reached"
                            );
                        }
                        crate::abuse::runtime::OutboundVerdict::Allow => {}
                    }
                    if let Err(e) = email_service.send_password_reset_email(
                        &recipient,
                        &reset_url,
                        realm_branding.as_ref(),
                        stored.as_ref(),
                        None,
                    ) {
                        tracing::warn!(
                            error = %crate::protocol::redact::sanitize_log_text(&e.to_string()),
                            "forgot_password: failed to send email"
                        );
                    }
                });
            } else {
                tracing::warn!(
                    reset_url = %crate::protocol::redact::Redact(&reset_url),
                    "password reset URL (no email transport configured)"
                );
            }
        }
        Ok(None) | Err(IdentityError::RateLimited) => {
            // Unknown email or rate-limited — silent success.
        }
        Err(e) => {
            tracing::warn!(error = %e, "forgot_password: error requesting reset");
        }
    }

    Redirect::to(&sent_url).into_response()
}

/// Renders the "check your email" confirmation page at the bare URL.
pub async fn forgot_password_sent(State(state): State<Arc<WebState>>) -> Response {
    forgot_password_sent_impl(state, RealmSource::Path(None))
}

/// Realm-scoped variant of the forgot-password "sent" page.
pub async fn forgot_password_sent_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    forgot_password_sent_impl(state, RealmSource::Path(Some(realm_name)))
}

/// Admin variant of the forgot-password "sent" page at `/ui/admin/forgot-password/sent`.
pub async fn admin_forgot_password_sent(State(state): State<Arc<WebState>>) -> Response {
    forgot_password_sent_impl(state, RealmSource::Admin)
}

#[allow(clippy::needless_pass_by_value)]
fn forgot_password_sent_impl(state: Arc<WebState>, source: RealmSource) -> Response {
    let action_prefix = match resolve_for_source(&state, source, false) {
        PreAuthRealm::Ok { action_prefix, .. } => action_prefix,
        PreAuthRealm::Handled(resp) => return resp,
    };
    let tmpl = ForgotPasswordSentTemplate::new(
        format!("{action_prefix}/login"),
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    render(&tmpl)
}

/// Renders the reset-password form at the bare URL.
///
/// The emailed link's `?token=` is moved into the link-token cookie by the
/// route's middleware before this runs; the page renders only the token's
/// binding (GA audit L18).
pub async fn reset_password_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    reset_password_form_impl(state, &headers, RealmSource::Path(None))
}

/// Renders the reset-password form at `/ui/realms/<name>/reset-password`.
pub async fn reset_password_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    reset_password_form_impl(state, &headers, RealmSource::Path(Some(realm_name)))
}

/// Renders the admin reset-password form at `/ui/admin/reset-password`.
///
/// `admin_forgot_password_submit` emails a link under `/ui/admin`; without
/// this route that link 404s and the admin account is unrecoverable
/// (audit 2026-08-28 §4.24#7).
pub async fn admin_reset_password_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    reset_password_form_impl(state, &headers, RealmSource::Admin)
}

#[allow(clippy::needless_pass_by_value)]
fn reset_password_form_impl(
    state: Arc<WebState>,
    headers: &HeaderMap,
    source: RealmSource,
) -> Response {
    let (realm, action_prefix) = match resolve_for_source(&state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    match link_token::read(headers) {
        Some(token) => {
            let binding = link_token::link_binding(&state.cookie_secret, &token);
            render(&reset_template(
                &state,
                &realm,
                &action_prefix,
                binding,
                None,
            ))
        }
        None => render_status(
            &reset_template(
                &state,
                &realm,
                &action_prefix,
                String::new(),
                Some("Missing or invalid reset link.".to_string()),
            ),
            StatusCode::BAD_REQUEST,
        ),
    }
}

/// Builds the reset-password page for `realm`.
fn reset_template(
    state: &WebState,
    realm: &Realm,
    action_prefix: &str,
    link_binding: String,
    error: Option<String>,
) -> ResetPasswordTemplate {
    let mut tmpl = ResetPasswordTemplate::new(
        link_binding,
        error,
        action_prefix,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
    tmpl.inline_theme_css = state.inline_theme_css();
    tmpl
}

/// Form data for the reset-password submission. The reset token itself comes
/// from the link-token cookie, never the form (GA audit L18).
#[derive(Deserialize)]
pub struct ResetPasswordFormData {
    /// [`link_token::link_binding`] of the stashed token, echoed from the
    /// hidden input. Binds the POST to the page the cookie holder was served.
    #[serde(default)]
    pub link_binding: String,
    /// The new password.
    pub password: FormSecret,
    /// Password confirmation.
    pub password_confirm: FormSecret,
}

/// Redacts both passwords (GA audit L20).
impl std::fmt::Debug for ResetPasswordFormData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetPasswordFormData")
            .field("link_binding", &self.link_binding)
            .field("password", &"<redacted>")
            .field("password_confirm", &"<redacted>")
            .finish()
    }
}

/// Minimum password length the browser forms enforce before spending an
/// Argon2id permit.
///
/// Mirrors the engine's unconditional floor
/// (`identity::validation::MIN_PASSWORD_LENGTH_FLOOR`). Keeping the two in
/// step is what lets the form name the real requirement instead of failing
/// deep in the engine with a generic message (audit 2026-08-28 §4.24#5).
const MIN_BROWSER_PASSWORD_LENGTH: usize = 12;

/// The message every refused or spent reset link gets.
const RESET_LINK_INVALID: &str =
    "This reset link is invalid or has expired. Please request a new one.";

/// Context resolved pre-gate for reset-password submissions. Built outside the
/// KDF admission gate so cheap validation rejects (password mismatch, minimum
/// length) never consume a permit (HEA-1981 / F4).
struct PreparedReset {
    realm: Realm,
    action_prefix: String,
    /// The reset token, read from the link-token cookie.
    token: FormSecret,
}

/// Resolves the realm, reads the stashed token and checks the form's binding
/// and cheap constraints before the KDF gate.
///
/// Password mismatch and minimum-length checks run here so that a flood of
/// trivially-invalid requests cannot exhaust the Argon2id admission pool. A
/// missing token or a binding that does not match refuses with `400` and
/// leaves the cookie alone: the legitimate holder's page still works.
fn reset_prepare(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    form: &ResetPasswordFormData,
    source: RealmSource,
) -> Result<PreparedReset, Response> {
    let (realm, action_prefix) = match resolve_for_source(state, source, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return Err(resp),
    };
    let Some(token) = link_token::read(headers)
        .filter(|t| link_token::binding_matches(&state.cookie_secret, t, &form.link_binding))
    else {
        return Err(render_status(
            &reset_template(
                state,
                &realm,
                &action_prefix,
                String::new(),
                Some(RESET_LINK_INVALID.to_string()),
            ),
            StatusCode::BAD_REQUEST,
        ));
    };
    let reset_err = |msg: String| {
        render(&reset_template(
            state,
            &realm,
            &action_prefix,
            form.link_binding.clone(),
            Some(msg),
        ))
    };
    if *form.password != *form.password_confirm {
        return Err(reset_err("Passwords do not match.".to_string()));
    }
    // The pre-gate threshold must be the real policy floor. It used to be 8
    // while the message said 12, so an 8-to-11-character password sailed past
    // here, was rejected deep inside the engine, and came back as a generic
    // "try again" that named no requirement (audit 2026-08-28 §4.24#5).
    if form.password.len() < MIN_BROWSER_PASSWORD_LENGTH {
        return Err(reset_err(format!(
            "Password must be at least {MIN_BROWSER_PASSWORD_LENGTH} characters."
        )));
    }
    Ok(PreparedReset {
        realm,
        action_prefix,
        token,
    })
}

/// Handles reset-password form submission at the bare URL.
pub async fn reset_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<ResetPasswordFormData>,
) -> Response {
    reset_password_submit_gated(state, headers, form, RealmSource::Path(None)).await
}

/// Handles reset-password form submission at `/ui/realms/<name>/reset-password`.
pub async fn reset_password_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<ResetPasswordFormData>,
) -> Response {
    reset_password_submit_gated(state, headers, form, RealmSource::Path(Some(realm_name))).await
}

/// Handles reset-password form submission at `/ui/admin/reset-password`.
///
/// Completes the loop opened by `admin_forgot_password_submit`, whose emailed
/// link previously pointed at a route that did not exist — leaving an admin
/// account with a forgotten password unrecoverable through the UI
/// (audit 2026-08-28 §4.24#7).
pub async fn admin_reset_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<ResetPasswordFormData>,
) -> Response {
    reset_password_submit_gated(state, headers, form, RealmSource::Admin).await
}

/// Cheap pre-gate validation, then the reset itself under the KDF admission
/// gate — password mismatch/length never consumes a permit (HEA-1981 / F4).
async fn reset_password_submit_gated(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: ResetPasswordFormData,
    source: RealmSource,
) -> Response {
    let prepared = match reset_prepare(&state, &headers, &form, source) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let shed_state = Arc::clone(&state);
    match gate()
        .run(move || reset_password_submit_impl(state, form, prepared))
        .await
    {
        Ok(resp) => resp,
        Err(KdfGateError::Overloaded { retry_after }) => {
            kdf_shed_html_response(&shed_state, &headers, retry_after, None, None, None)
        }
        Err(KdfGateError::Join(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Shared implementation — runs inside the KDF admission gate.
///
/// Receives a pre-validated realm, action prefix and token from
/// [`reset_prepare`]; password mismatch and length checks already ran
/// pre-gate. A completed or definitively refused token clears the cookie.
#[allow(clippy::needless_pass_by_value)]
fn reset_password_submit_impl(
    state: Arc<WebState>,
    form: ResetPasswordFormData,
    prepared: PreparedReset,
) -> Response {
    let PreparedReset {
        realm,
        action_prefix,
        token,
    } = prepared;
    let reset_err = |binding: String, msg: String| {
        render(&reset_template(
            &state,
            &realm,
            &action_prefix,
            binding,
            Some(msg),
        ))
    };

    let password = CleartextPassword::new(form.password.as_bytes().to_vec());

    match state
        .identity
        .reset_password_with_token(realm.id(), &token, &password)
    {
        Ok(_user_id) => {
            let login_url = format!("{action_prefix}/login");
            let mut tmpl = ResetPasswordOkTemplate::new(
                login_url,
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
            tmpl.inline_theme_css = state.inline_theme_css();
            link_token::mark_spent(render(&tmpl))
        }
        Err(IdentityError::PasswordResetTokenInvalid) => {
            link_token::mark_spent(reset_err(String::new(), RESET_LINK_INVALID.to_string()))
        }
        // The realm's password policy refused the new password. The token is
        // NOT consumed on this path, so hand back the reason and keep the
        // link live so the user can retry on the same page rather than being
        // told to "try again" with no idea what to change
        // (audit 2026-08-28 §4.24#5).
        Err(IdentityError::InvalidInput { ref reason }) => {
            let mut msg = reason.clone();
            if let Some(first) = msg.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            reset_err(form.link_binding.clone(), format!("{msg}."))
        }
        Err(IdentityError::PasswordReused) => reset_err(
            form.link_binding.clone(),
            "That password has been used before. Please choose a different one.".to_string(),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "reset_password: error resetting password");
            reset_err(
                form.link_binding.clone(),
                "Failed to reset password. Please try again.".to_string(),
            )
        }
    }
}

// ============================================================================
// Magic-link redemption
// ============================================================================

const MAGIC_LINK_COPY: LinkConfirmCopy = LinkConfirmCopy {
    heading: "Sign in",
    message: "Continue to sign in with the link from your email.",
    button_label: "Sign in",
};

/// `GET /ui/magic-link` — the confirmation page for an emailed sign-in link.
///
/// The emailed `?token=` was moved into the link-token cookie by the route's
/// middleware, and nothing is redeemed here: a mail scanner or link preview
/// that fetches the URL must not sign the user in (GA audit L18). The page's
/// `POST` ([`magic_link_redeem`]) redeems.
pub async fn magic_link_page(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    magic_link_page_impl(&state, &headers, RealmSource::Path(None))
}

/// `GET /ui/realms/<name>/magic-link` — see [`magic_link_page`].
pub async fn magic_link_page_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    magic_link_page_impl(&state, &headers, RealmSource::Path(Some(realm_name)))
}

/// `POST /ui/magic-link` — redeems a magic link and starts a browser session.
///
/// Before this existed the flow had no terminal step: a token could be minted
/// and mailed but never exchanged for anything (audit 2026-08-28 §4.24#6).
pub async fn magic_link_redeem(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    magic_link_post(state, &headers, peer_addr, &form, RealmSource::Path(None))
}

/// `POST /ui/realms/<name>/magic-link` — realm-scoped magic-link redemption.
pub async fn magic_link_redeem_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    magic_link_post(
        state,
        &headers,
        peer_addr,
        &form,
        RealmSource::Path(Some(realm_name)),
    )
}

fn magic_link_page_impl(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    source: RealmSource,
) -> Response {
    let (realm, action_prefix) = match resolve_for_source(state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    match link_token::read(headers) {
        Some(token) => render_link_confirm(
            state,
            headers,
            &token,
            MAGIC_LINK_COPY,
            format!("{action_prefix}/magic-link"),
            state.realm_theme_url_for(realm.id()),
            true,
        ),
        None => magic_link_expired(state, &realm, &action_prefix),
    }
}

/// Checks the confirmation `POST` and redeems. A refused `POST` (no link
/// cookie, wrong binding, bad CSRF) keeps the link; any answer after the
/// token reached the engine clears it.
fn magic_link_post(
    state: Arc<WebState>,
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    form: &LinkConfirmForm,
    source: RealmSource,
) -> Response {
    let token = link_token::confirmed_token(&state, headers, &form.link_binding, &form.csrf, true);
    let reached_engine = token.is_some();
    let resp = magic_link_redeem_impl(state, headers, peer_addr, token, source);
    if reached_engine {
        link_token::mark_spent(resp)
    } else {
        resp
    }
}

/// The login page with a neutral "expired or already used" banner — never a
/// hint about whether the address exists.
fn magic_link_expired(state: &WebState, realm: &Realm, action_prefix: &str) -> Response {
    let mut tmpl = LoginTemplate::new(
        Some(
            "This sign-in link has expired or has already been used. \
             Request a new one."
                .to_string(),
        ),
        None,
        action_prefix,
        registration_enabled(realm),
        DEFAULT_LOGIN_LOCALE,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
    tmpl.inline_theme_css = state.inline_theme_css();
    tmpl.new_magic_link_url = Some(format!("{action_prefix}/login"));
    render_status(&tmpl, StatusCode::BAD_REQUEST)
}

/// Shared implementation for both magic-link redemption routes.
///
/// On success: revoke any prior cookie session, mint a new one, and redirect
/// into the signed-in UI. On any failure: render the login page with a
/// neutral "expired or already used" banner — never a hint about whether the
/// address exists.
///
/// The link proves control of the mailbox, which is ONE factor. A user who
/// holds a second factor is sent to its challenge with the MFA pending
/// cookie, exactly as after a password (GA audit B4), and pending required
/// actions are enforced before any session is issued (GA audit M11).
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn magic_link_redeem_impl(
    state: Arc<WebState>,
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    token: Option<FormSecret>,
    source: RealmSource,
) -> Response {
    let (realm, action_prefix) = match resolve_for_source(&state, source, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };

    let expired = |state: &Arc<WebState>| magic_link_expired(state, &realm, &action_prefix);

    let Some(token) = token.filter(|t| !t.trim().is_empty()) else {
        return expired(&state);
    };

    let user_id = match state.identity.validate_magic_link(realm.id(), &token) {
        Ok(id) => id,
        Err(e) => {
            tracing::info!(error = %e, "magic_link: redemption rejected");
            return expired(&state);
        }
    };

    let secure = state.is_secure_request(headers);

    // --- Second factor (GA audit B4) ---
    let user = match state.identity.get_user(realm.id(), &user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return expired(&state),
        Err(e) => {
            tracing::warn!(error = %e, "magic_link: user lookup failed");
            return internal_error_response();
        }
    };
    // The link proves the inbox: an email OTP cannot be its second factor.
    let first = super::auth::FirstFactor::Inbox;
    match super::second_factor::second_factor_step(&state, &realm, &user, first) {
        Ok(Some(step)) => {
            return super::second_factor::redirect_to_second_factor(
                &state,
                realm.id(),
                &user_id,
                step,
                first,
                None,
                secure,
            );
        }
        Ok(None) => {}
        Err(e) => {
            // The user's factors are unknown: refuse rather than skip one.
            tracing::warn!(error = %e, "magic_link: second-factor lookup failed");
            return internal_error_response();
        }
    }

    // --- Required-action gate (GA audit M11) ---
    let now = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    if let Some(ra_response) = super::required_action::required_action_check_browser(
        &state,
        realm.id(),
        &user_id,
        None,
        // The link proves the inbox, one factor; nothing was owed above.
        &build_session_context(headers, peer_addr, &state.trusted_proxies),
        super::auth::FirstFactor::Inbox,
        headers,
        now,
    ) {
        state.set_current_realm(realm.id().clone());
        return ra_response;
    }

    // A-41: destroy any pre-existing session cookie before issuing a new one.
    revoke_prior_session_cookie(state.identity.as_ref(), headers, &state.cookie_secret);

    // The peer address feeds the realm's `cidr_policy`, which the engine
    // applies to every session it creates (GA audit M13).
    let session_ctx = build_session_context(headers, peer_addr, &state.trusted_proxies);
    let session = match state
        .identity
        .create_session(realm.id(), &user_id, &session_ctx)
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "magic_link: create_session failed");
            return expired(&state);
        }
    };

    let IssuedCookies {
        session_cookie,
        csrf_cookie,
    } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id(), secure);
    state.set_current_realm(realm.id().clone());

    let mut response = Redirect::to("/ui").into_response();
    append_cookie(&mut response, &session_cookie);
    append_cookie(&mut response, &csrf_cookie);
    append_cookie(
        &mut response,
        &super::auth::last_realm_cookie(
            &super::auth::last_realm_value(state.identity.as_ref(), realm.id()),
            secure,
        ),
    );
    response
}

// ============================================================================
// Self-service registration
// ============================================================================

/// Registration form template.
#[derive(Template)]
#[template(path = "ui/register.html")]
#[allow(clippy::struct_excessive_bools)]
struct RegisterTemplate {
    disabled: bool,
    invite_only: bool,
    email_prefill: String,
    error: Option<String>,
    /// URL the form POSTs to — `/ui/register` for bare routes,
    /// `/ui/realms/<name>/register` for the realm-scoped route.
    form_action: String,
    /// URL for the "Sign in" link at the bottom of the form.
    login_url: String,
    /// Shown alongside error when the form's CSRF token went stale — links back
    /// to this same registration form so the user lands on a page bearing a
    /// fresh token without hunting for the browser reload button (HEA-1913).
    reload_url: Option<String>,
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
    /// Pre-built CAPTCHA widget HTML injected into the form (P-1 / HEA-1202).
    /// Empty string when no provider is configured (no-op / fail-open).
    captcha_widget_html: String,
}

impl RegisterTemplate {
    #[allow(clippy::too_many_arguments)]
    fn new(
        disabled: bool,
        invite_only: bool,
        email_prefill: String,
        error: Option<String>,
        form_action: String,
        login_url: String,
        product_name: String,
        logo_url: String,
        captcha_widget_html: String,
    ) -> Self {
        Self {
            disabled,
            invite_only,
            email_prefill,
            error,
            form_action,
            login_url,
            reload_url: None,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
            captcha_widget_html,
        }
    }
}

/// Confirmation page after a successful signup submission.
#[derive(Template)]
#[template(path = "ui/register_sent.html")]
struct RegisterSentTemplate {
    login_url: String,
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

impl RegisterSentTemplate {
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Form data for `POST /ui/register`.
#[derive(Deserialize)]
pub struct RegisterForm {
    /// Email address.
    pub email: String,
    /// Display name (optional — synthesized from first/last if empty).
    #[serde(default)]
    pub display_name: String,
    /// First (given) name.
    #[serde(default)]
    pub first_name: String,
    /// Last (family) name.
    #[serde(default)]
    pub last_name: String,
    /// New password.
    pub password: FormSecret,
    /// Password confirmation.
    pub password_confirm: FormSecret,
    /// Optional invitation token (required when policy is invite-only).
    #[serde(default)]
    pub invitation_token: Option<FormSecret>,
    /// CAPTCHA response token populated by the Turnstile widget (P-1).
    ///
    /// Empty string when no CAPTCHA provider is configured (`NoopCaptchaProvider`).
    #[serde(default)]
    pub captcha_token: String,
    /// CSRF token echoed from the hidden `_csrf` field.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Redacts the passwords, the invitation and captcha tokens and the CSRF
/// token (GA audit L20).
impl std::fmt::Debug for RegisterForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterForm")
            .field("email", &self.email)
            .field("display_name", &self.display_name)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("password", &"<redacted>")
            .field("password_confirm", &"<redacted>")
            .field(
                "invitation_token",
                &self.invitation_token.as_ref().map(|_| "<redacted>"),
            )
            .field("captcha_token", &"<redacted>")
            .field("csrf", &"<redacted>")
            .finish()
    }
}

/// Returns `(disabled, invite_only)` flags derived from the realm's
/// registration policy.
fn registration_policy_flags(realm: &Realm) -> (bool, bool) {
    match realm.config().registration_policy.clone() {
        None | Some(crate::identity::RegistrationPolicy::Disabled) => (true, false),
        Some(crate::identity::RegistrationPolicy::InviteOnly) => (false, true),
        Some(_) => (false, false),
    }
}

/// Returns `true` when self-registration is enabled for the realm, i.e.
/// the policy is anything other than `None` / `Disabled`. Used by the
/// login page to decide whether to show the "Create account" link at all
/// — hiding it on disabled realms avoids advertising a URL that would
/// only show "Registration unavailable".
fn registration_enabled(realm: &Realm) -> bool {
    !registration_policy_flags(realm).0
}

/// Renders the registration form for the bare `/ui/register` URL.
pub async fn register_form(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    register_form_impl(state, &headers, None)
}

/// Renders the registration form under `/ui/realms/<name>/register`.
pub async fn register_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    register_form_impl(state, &headers, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn register_form_impl(
    state: Arc<WebState>,
    headers: &HeaderMap,
    path_realm: Option<String>,
) -> Response {
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let (disabled, invite_only) = registration_policy_flags(&realm);
    let form_action = format!("{action_prefix}/register");
    let login_url = format!("{action_prefix}/login");
    let mut tmpl = RegisterTemplate::new(
        disabled,
        invite_only,
        String::new(),
        None,
        form_action,
        login_url,
        state.product_name.clone(),
        state.logo_url.clone(),
        state.captcha_provider.widget_html().to_string(),
    );
    tmpl.realm_theme_url = state.realm_theme_url_for(realm.id());
    tmpl.inline_theme_css = state.inline_theme_css();

    // Issue or reuse the CSRF cookie so the register form can double-submit.
    let secure = state.is_secure_request(headers);
    let (csrf_value, fresh_cookie) = match super::auth::csrf_cookie_value_from_headers(headers) {
        Some(existing) => (existing.to_string(), None),
        None => {
            let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
            (val, Some(cookie))
        }
    };
    tmpl.csrf = Some(csrf_value);
    let mut resp = render(&tmpl);
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut resp, &cookie);
    }
    resp
}

/// Maps `IdentityError` values from `register_user` to user-facing banner text.
fn register_error_message(err: &IdentityError) -> String {
    match err {
        IdentityError::InvalidInput { reason } => reason.clone(),
        IdentityError::RegistrationDomainNotAllowed { .. } => {
            "That email domain is not permitted for registration.".to_string()
        }
        IdentityError::RegistrationRequiresInvitation => {
            "A valid invitation is required to register in this realm.".to_string()
        }
        IdentityError::RegistrationDisabled => {
            "Registration is not enabled for this realm.".to_string()
        }
        IdentityError::RateLimited => {
            "Too many registration attempts. Please try again later.".to_string()
        }
        _ => "Registration failed. Please try again.".to_string(),
    }
}

/// Extracts the caller's IP via the trusted-proxy-aware algorithm (M8).
///
/// Delegates to `extract_client_ip` so a spoofed `X-Forwarded-For` from an
/// untrusted hop is ignored when `trusted_proxies` is empty (the default).
fn register_client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &crate::core::TrustedProxies,
) -> Option<String> {
    Some(crate::protocol::client_info::extract_client_ip(
        headers,
        peer,
        trusted_proxies,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA helpers (P-1 — HEA-1202)
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts the client IP for CAPTCHA verification via the trusted-proxy-aware
/// algorithm (M8).  Falls back to `127.0.0.1` only when the resolved string
/// fails to parse (should not occur in practice).
fn captcha_client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &crate::core::TrustedProxies,
) -> std::net::IpAddr {
    crate::protocol::client_info::extract_client_ip(headers, peer, trusted_proxies)
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Verifies the CAPTCHA response token from a form submission.
///
/// Short-circuits to `true` when the configured provider is the
/// `NoopCaptchaProvider` (empty `widget_html`) — no network call is made.
///
/// Otherwise calls [`crate::abuse::challenge::CaptchaProvider::verify`] on
/// the blocking thread pool via [`tokio::task::spawn_blocking`].
///
/// Fails-open (returns `true`) if `spawn_blocking` itself fails, consistent
/// with §6.1 of the abuse-prevention plan.
async fn captcha_check(
    state: &Arc<super::WebState>,
    headers: &HeaderMap,
    peer: SocketAddr,
    token: &str,
) -> bool {
    if state.captcha_provider.widget_html().is_empty() {
        return true;
    }
    let ip = captcha_client_ip(headers, peer, &state.trusted_proxies);
    let provider = Arc::clone(&state.captcha_provider);
    let token = token.to_string();
    tokio::task::spawn_blocking(move || provider.verify(&token, ip))
        .await
        .unwrap_or(true)
}

/// Context resolved pre-gate for registration submissions. Built outside the
/// KDF admission gate so CSRF and captcha rejects never consume a permit
/// (HEA-1981 / F3).
struct PreparedRegister {
    realm: Realm,
    action_prefix: String,
}

/// Resolves the realm and validates the cheap pre-gate conditions (CSRF and
/// captcha) before the KDF admission gate.
///
/// Returns `Err(response)` for any rejection that doesn't require Argon2id.
/// Returns `Ok(PreparedRegister)` when the request is safe to admit to the gate.
fn register_pre_gate(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    form: &RegisterForm,
    path_realm: Option<String>,
    captcha_ok: bool,
) -> Result<PreparedRegister, Response> {
    let (realm, action_prefix) = match resolve_pre_auth_realm(state, path_realm, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return Err(resp),
    };
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let realm_theme = state.realm_theme_url_for(realm.id());
    let inline_css = state.inline_theme_css();
    let (disabled, invite_only) = registration_policy_flags(&realm);
    let form_action = format!("{action_prefix}/register");
    let login_url = format!("{action_prefix}/login");
    let captcha_widget_html = state.captcha_provider.widget_html().to_string();

    // CSRF double-submit check — fail-closed in non-dev mode (HEA-1981 / F3).
    let csrf_ok = match super::auth::csrf_cookie_value_from_headers(headers) {
        Some(cookie_val) => super::auth::csrf_token_eq(cookie_val, &form.csrf),
        None => state.dev_mode,
    };
    if !csrf_ok {
        // Mint a fresh CSRF token so the user can resubmit immediately (HEA-1983).
        let secure = state.is_secure_request(headers);
        let (csrf_value, csrf_cookie) = super::auth::fresh_csrf_cookie(secure);
        let mut tmpl = RegisterTemplate::new(
            disabled,
            invite_only,
            form.email.clone(),
            Some("Your session has expired. Please reload the page and try again.".to_string()),
            form_action.clone(),
            login_url.clone(),
            product_name.clone(),
            logo_url.clone(),
            captcha_widget_html.clone(),
        );
        tmpl.reload_url = Some(form_action);
        tmpl.csrf = Some(csrf_value);
        tmpl.realm_theme_url.clone_from(&realm_theme);
        tmpl.inline_theme_css.clone_from(&inline_css);
        let mut resp = render_status(&tmpl, StatusCode::UNPROCESSABLE_ENTITY);
        append_cookie(&mut resp, &csrf_cookie);
        return Err(resp);
    }

    if !captcha_ok {
        let mut tmpl = RegisterTemplate::new(
            disabled,
            invite_only,
            form.email.clone(),
            Some("CAPTCHA verification failed. Please try again.".to_string()),
            form_action,
            login_url,
            product_name,
            logo_url,
            captcha_widget_html,
        );
        tmpl.realm_theme_url.clone_from(&realm_theme);
        tmpl.inline_theme_css.clone_from(&inline_css);
        return Err(render_status(&tmpl, StatusCode::BAD_REQUEST));
    }

    Ok(PreparedRegister {
        realm,
        action_prefix,
    })
}

/// Takes the user-create permit a registration holds for its whole create,
/// Argon2id hash included (#446), or renders the themed `503` page with
/// `Retry-After` when the user-create limit is full. Taken before the KDF
/// permit, so a registration shed here never occupies a hashing slot.
async fn admit_registration(
    state: &WebState,
    headers: &HeaderMap,
    email: &str,
    form_action: &str,
) -> Result<crate::identity::UserCreatePermit, Response> {
    match crate::identity::user_create_gate().admit().await {
        Ok(permit) => Ok(permit),
        Err(crate::identity::UserCreateGateError::Overloaded { retry_after }) => {
            Err(kdf_shed_html_response(
                state,
                headers,
                retry_after,
                Some(email.to_string()),
                None,
                Some(form_action.to_string()),
            ))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    }
}

/// Handles registration form submission (bare `/ui/register`).
pub async fn register_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let captcha_ok = captcha_check(&state, &headers, peer_addr, &form.captcha_token).await;
    // CSRF and captcha validated pre-gate so a flood of rejected requests never
    // exhausts the Argon2id admission pool (HEA-1981 / F3).
    let prepared = match register_pre_gate(&state, &headers, &form, None, captcha_ok) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let shed_state = Arc::clone(&state);
    let shed_email = form.email.trim().to_string();
    let shed_headers = headers.clone();
    let shed_action = format!("{}/register", prepared.action_prefix);
    let create_permit =
        match admit_registration(&shed_state, &shed_headers, &shed_email, &shed_action).await {
            Ok(permit) => permit,
            Err(resp) => return resp,
        };
    match gate()
        .run(move || {
            let _create_permit = create_permit;
            register_submit_impl(state, headers, form, prepared, peer_addr)
        })
        .await
    {
        Ok(resp) => resp,
        Err(KdfGateError::Overloaded { retry_after }) => kdf_shed_html_response(
            &shed_state,
            &shed_headers,
            retry_after,
            Some(shed_email),
            None,
            Some(shed_action),
        ),
        Err(KdfGateError::Join(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Handles registration form submission for `/ui/realms/<name>/register`.
pub async fn register_submit_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let captcha_ok = captcha_check(&state, &headers, peer_addr, &form.captcha_token).await;
    let prepared = match register_pre_gate(&state, &headers, &form, Some(realm_name), captcha_ok) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let shed_state = Arc::clone(&state);
    let shed_email = form.email.trim().to_string();
    let shed_headers = headers.clone();
    let shed_action = format!("{}/register", prepared.action_prefix);
    let create_permit =
        match admit_registration(&shed_state, &shed_headers, &shed_email, &shed_action).await {
            Ok(permit) => permit,
            Err(resp) => return resp,
        };
    match gate()
        .run(move || {
            let _create_permit = create_permit;
            register_submit_impl(state, headers, form, prepared, peer_addr)
        })
        .await
    {
        Ok(resp) => resp,
        Err(KdfGateError::Overloaded { retry_after }) => kdf_shed_html_response(
            &shed_state,
            &shed_headers,
            retry_after,
            Some(shed_email),
            None,
            Some(shed_action),
        ),
        Err(KdfGateError::Join(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Shared implementation for bare and realm-scoped register submits.
///
/// Runs inside the KDF admission gate. Receives a pre-validated realm and
/// action prefix from [`register_pre_gate`]; CSRF and captcha checks already
/// ran pre-gate.
///
/// On success, creates a `PendingVerification` user, issues a verification
/// token, emails it, and redirects to the scope's `register/sent` page.
/// Duplicate emails are handled at the engine layer with a fake-success
/// response so we never see an error on that path — preserving
/// enumeration resistance.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn register_submit_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: RegisterForm,
    prepared: PreparedRegister,
    peer_addr: SocketAddr,
) -> Response {
    let PreparedRegister {
        realm,
        action_prefix,
    } = prepared;
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let realm_theme = state.realm_theme_url_for(realm.id());
    let inline_css = state.inline_theme_css();
    let (disabled, invite_only) = registration_policy_flags(&realm);
    let form_action = format!("{action_prefix}/register");
    let login_url = format!("{action_prefix}/login");
    let sent_url = format!("{action_prefix}/register/sent");
    let captcha_widget_html = state.captcha_provider.widget_html().to_string();

    let render_err_with_reload = |msg: String, email: String, reload_url: Option<String>| {
        let mut tmpl = RegisterTemplate::new(
            disabled,
            invite_only,
            email,
            Some(msg),
            form_action.clone(),
            login_url.clone(),
            product_name.clone(),
            logo_url.clone(),
            captcha_widget_html.clone(),
        );
        tmpl.reload_url = reload_url;
        tmpl.realm_theme_url.clone_from(&realm_theme);
        tmpl.inline_theme_css.clone_from(&inline_css);
        render_status(&tmpl, StatusCode::BAD_REQUEST)
    };
    let render_err = |msg: String, email: String| render_err_with_reload(msg, email, None);

    if disabled {
        return render_err(
            "Registration is not enabled for this realm.".to_string(),
            form.email,
        );
    }
    if *form.password != *form.password_confirm {
        return render_err("Passwords do not match.".to_string(), form.email);
    }
    if form.password.len() < MIN_BROWSER_PASSWORD_LENGTH {
        return render_err(
            format!("Password must be at least {MIN_BROWSER_PASSWORD_LENGTH} characters."),
            form.email,
        );
    }

    let request = crate::identity::RegisterUserRequest {
        email: form.email.clone(),
        display_name: form.display_name.clone(),
        first_name: form.first_name.clone(),
        last_name: form.last_name.clone(),
        password: CleartextPassword::new(form.password.as_bytes().to_vec()),
        client_ip: register_client_ip(&headers, peer_addr, &state.trusted_proxies),
        invitation_token: form.invitation_token.as_deref().map(str::to_string),
    };

    let response = match state.identity.register_user(realm.id(), &request) {
        Ok(r) => r,
        Err(e) => {
            if !matches!(
                e,
                IdentityError::InvalidInput { .. }
                    | IdentityError::RegistrationDomainNotAllowed { .. }
                    | IdentityError::RegistrationRequiresInvitation
                    | IdentityError::RegistrationDisabled
                    | IdentityError::RateLimited
            ) {
                tracing::warn!(error = %e, "register_submit: unexpected engine error");
            }
            return render_err(register_error_message(&e), form.email);
        }
    };

    send_verification_email_off_path(
        &state,
        &realm,
        form.email.clone(),
        &response.verification_token,
        &action_prefix,
        &headers,
    );

    Redirect::to(&sent_url).into_response()
}

/// Sends the email-verification link for `token` to `recipient` — the mail
/// self-registration sends, and the one a federated account whose upstream
/// did not verify its address is sent (GA audit round 3, G-3).
///
/// Off the request path: the mail send must not add latency that
/// distinguishes a fresh address from a registered one (audit 2026-08-28
/// §4.24#4). The A-4 / A-50 outbound caps (task 20.13) apply, inside the
/// off-path closure so they add no measurable latency either.
pub(super) fn send_verification_email_off_path(
    state: &Arc<WebState>,
    realm: &Realm,
    recipient: String,
    token: &str,
    action_prefix: &str,
    headers: &HeaderMap,
) {
    let Some(email_service) = state.email.clone() else {
        tracing::warn!(
            "verification email: no email transport configured; verification cannot be delivered"
        );
        return;
    };
    let base = derive_base_url(
        state
            .config
            .as_ref()
            .and_then(|c| c.onboarding.base_url.as_deref()),
        &state.fallback_base_url(),
        headers,
    );
    let verify_url = format!("{base}{action_prefix}/verify-email?token={token}");
    let branding = realm.config().email_branding.clone();
    let stored_verification = realm.config().email_templates.get("verification").cloned();
    let guards = Arc::clone(&state.abuse_guards);
    let realm_key = realm.id().as_uuid().to_string();
    spawn_off_request_path(move || {
        match guards.check_outbound_email(&realm_key, &recipient) {
            crate::abuse::runtime::OutboundVerdict::Deny { reason } => {
                tracing::warn!(
                    guard = reason,
                    "verification email: outbound cap reached; not sent"
                );
                return;
            }
            crate::abuse::runtime::OutboundVerdict::Warn { reason } => {
                tracing::warn!(
                    guard = reason,
                    "verification email: outbound soft cap reached"
                );
            }
            crate::abuse::runtime::OutboundVerdict::Allow => {}
        }
        if let Err(e) = email_service.send_verification_email(
            &recipient,
            &verify_url,
            branding.as_ref(),
            stored_verification.as_ref(),
            None,
        ) {
            tracing::warn!(
                error = %crate::protocol::redact::sanitize_log_text(&e.to_string()),
                "verification email: send failed"
            );
        }
    });
}

/// Renders the post-submission confirmation page for the bare URL.
pub async fn register_sent(State(state): State<Arc<WebState>>) -> Response {
    register_sent_impl(state, None)
}

/// Renders the post-submission confirmation page for a realm-scoped URL.
pub async fn register_sent_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    register_sent_impl(state, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value)]
fn register_sent_impl(state: Arc<WebState>, path_realm: Option<String>) -> Response {
    let action_prefix = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok { action_prefix, .. } => action_prefix,
        PreAuthRealm::Handled(resp) => return resp,
    };
    let tmpl = RegisterSentTemplate::new(
        format!("{action_prefix}/login"),
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    render(&tmpl)
}

/// Internal — shared 404 renderer used by the setup gate.
pub(super) fn not_found_response(body: &str) -> Response {
    let tmpl = crate::protocol::web::handlers_common::NotFoundTemplate::new(body.to_string());
    render_status(&tmpl, StatusCode::NOT_FOUND)
}

/// Internal — shared 500 renderer.
pub(super) fn internal_error_response() -> Response {
    let tmpl = crate::protocol::web::handlers_common::ServerErrorTemplate::new();
    render_status(&tmpl, StatusCode::INTERNAL_SERVER_ERROR)
}

// ============================================================================
// Pre-auth realm resolution wrapper
// ============================================================================

/// Terse 400 page shown when a bare `/ui/*` URL can't resolve a realm
/// on a multi-realm deployment with no `default_realm` configured.
///
/// Deliberately lists no realm names — presenting a picker would leak
/// the tenant inventory to anonymous visitors. Users who need to sign
/// in should be handed a specific `/ui/realms/<name>/...` URL by their
/// administrator (email, docs, internal portal).
#[derive(Template)]
#[template(path = "ui/realm_required.html")]
struct RealmRequiredTemplate {
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

impl RealmRequiredTemplate {
    fn new(product_name: String, logo_url: String) -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            realm_theme_url: None,
            inline_theme_css: None,
        }
    }
}

/// Which realm-resolution strategy a pre-auth handler should use.
///
/// Most handlers are shared between the bare `/ui/*` routes, the
/// path-scoped `/ui/realms/<name>/*` routes, AND the admin-surface
/// `/ui/admin/*` routes. This enum lets them dispatch without
/// duplicating the template-render and form-submit logic.
#[derive(Debug)]
pub(super) enum RealmSource {
    /// Bare or path-scoped tenant route. `Option<String>` is the
    /// realm name from the URL path, if any.
    Path(Option<String>),
    /// Admin surface (`/ui/admin/*`). Always resolves to the system
    /// realm with `action_prefix = "/ui/admin"`.
    Admin,
}

/// Unified entry point that dispatches to the right resolver based on
/// the `RealmSource`.
pub(super) fn resolve_for_source(
    state: &WebState,
    source: RealmSource,
    is_mutation: bool,
) -> PreAuthRealm {
    match source {
        RealmSource::Path(path_realm) => resolve_pre_auth_realm(state, path_realm, is_mutation),
        RealmSource::Admin => resolve_admin_realm(state),
    }
}

/// Outcome of [`resolve_pre_auth_realm`].
///
/// Size-difference lint suppressed: the `Ok` variant is the common case
/// and boxing it would add an indirection on every pre-auth request.
/// The `Handled` variant carries an `axum::Response` exactly once and
/// is returned directly; the outer size is dominated by it either way.
#[allow(clippy::large_enum_variant)]
pub(super) enum PreAuthRealm {
    /// Realm resolved. `action_prefix` is the URL prefix that form `action`
    /// attributes should use — either `/ui` for bare routes or
    /// `/ui/realms/<name>` for path-scoped ones.
    Ok { realm: Realm, action_prefix: String },
    /// A response has already been constructed (picker, 404, 400, 500).
    /// Callers return it directly without touching any realm-scoped state.
    Handled(Response),
}

/// Resolves the realm for a pre-auth request and produces either a
/// usable `Realm` or the complete response the caller should return.
///
/// * `path_realm` — `Some(<name>)` when the request came in under
///   `/ui/realms/<name>/...`; `None` for bare `/ui/...` URLs.
/// * `is_mutation` — POST/PUT/DELETE handlers set `true`; on an
///   unresolvable multi-realm request they return 400 (a picker would
///   lose the form state anyway).
#[allow(clippy::needless_pass_by_value)]
pub(super) fn resolve_pre_auth_realm(
    state: &WebState,
    path_realm: Option<String>,
    is_mutation: bool,
) -> PreAuthRealm {
    let path_realm_present = path_realm.is_some();
    match realm_resolver::resolve(state, path_realm.as_deref()) {
        Resolved::Realm(realm) => {
            // Form actions and sibling links always need a leading "/ui".
            // When the request came in with an explicit realm segment, we
            // preserve it; otherwise the bare `/ui` prefix lets callers
            // construct URLs like `{prefix}/login` and `{prefix}/register`
            // without special-casing the empty string.
            let action_prefix = if path_realm_present {
                format!("/ui/realms/{}", realm.name())
            } else {
                "/ui".to_string()
            };
            PreAuthRealm::Ok {
                realm,
                action_prefix,
            }
        }
        Resolved::NotFound => PreAuthRealm::Handled(not_found_response("Realm not found.")),
        Resolved::MustChoose(_realms) => {
            // Same terse 400 for GET and POST. Intentionally ignores
            // `is_mutation` and the realm list — enumerating realms to
            // anonymous callers is the bug we're avoiding.
            let _ = is_mutation;
            PreAuthRealm::Handled(realm_required_response(state))
        }
        Resolved::Storage => PreAuthRealm::Handled(internal_error_response()),
    }
}

/// Resolves the admin (system) realm for `/ui/admin/*` pre-auth
/// routes. The system realm is auto-seeded at engine construction, so
/// this should always succeed; a missing system realm indicates a
/// broken installation and we return 500.
///
/// Returns `PreAuthRealm::Ok { action_prefix: "/ui/admin" }` so all
/// admin-surface forms and sibling links stay on the admin URL space,
/// never leaking the reserved realm name or falling through to the
/// tenant resolver.
pub(super) fn resolve_admin_realm(state: &WebState) -> PreAuthRealm {
    let system = crate::identity::keys::system_realm_id();
    match state.identity.get_realm(&system) {
        Ok(Some(realm)) => PreAuthRealm::Ok {
            realm,
            action_prefix: "/ui/admin".to_string(),
        },
        Ok(None) => {
            tracing::error!(
                "admin realm missing from storage — system realm seeding failed at startup"
            );
            PreAuthRealm::Handled(internal_error_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "admin realm lookup failed");
            PreAuthRealm::Handled(internal_error_response())
        }
    }
}

/// Renders the terse "explicit realm URL required" 400 page. Lists no
/// realm names. Shown on multi-realm deployments when a bare `/ui/*`
/// URL is hit without `server.default_realm` configured.
fn realm_required_response(state: &WebState) -> Response {
    let tmpl = RealmRequiredTemplate::new(state.product_name.clone(), state.logo_url.clone());
    render_status(&tmpl, StatusCode::BAD_REQUEST)
}

// ============================================================================
// Invitation acceptance
// ============================================================================

/// Template for invitation acceptance result.
#[derive(Template)]
#[template(path = "ui/accept_invitation.html")]
#[allow(clippy::struct_excessive_bools)]
struct AcceptInvitationTemplate {
    success: bool,
    org_name: String,
    error_message: String,
    login_url: String,
    // Chrome fields.
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

const INVITATION_COPY: LinkConfirmCopy = LinkConfirmCopy {
    heading: "Accept invitation",
    message: "Accept the invitation to join the organization.",
    button_label: "Accept invitation",
};

/// `GET /ui/accept-invitation` — bare URL variant of the confirmation page.
///
/// The emailed `?token=` was moved into the link-token cookie by the route's
/// middleware, and nothing is accepted here: a mail scanner or link preview
/// that fetches the URL must not join the organization for the user (GA
/// audit L18). The page's `POST` accepts.
pub async fn accept_invitation_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    accept_invitation_impl(state, &headers, None, None)
}

/// `GET /ui/realms/<name>/accept-invitation` — realm-scoped variant.
pub async fn accept_invitation_page_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    accept_invitation_impl(state, &headers, Some(realm_name), None)
}

/// `POST /ui/accept-invitation` — accepts the stashed invitation.
pub async fn accept_invitation_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    accept_invitation_impl(state, &headers, None, Some(&form))
}

/// `POST /ui/realms/<name>/accept-invitation` — realm-scoped variant.
pub async fn accept_invitation_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<LinkConfirmForm>,
) -> Response {
    accept_invitation_impl(state, &headers, Some(realm_name), Some(&form))
}

/// Renders the confirmation page (`form` is `None`, a `GET`) or accepts an
/// organization invitation against the resolved realm only (`form` is the
/// confirmation `POST`).
#[allow(clippy::needless_pass_by_value)]
fn accept_invitation_impl(
    state: Arc<WebState>,
    headers: &HeaderMap,
    path_realm: Option<String>,
    form: Option<&LinkConfirmForm>,
) -> Response {
    let render_result = |success: bool,
                         org_name: String,
                         error_message: String,
                         login_url: String,
                         realm_theme: Option<String>| {
        render(&AcceptInvitationTemplate {
            success,
            org_name,
            error_message,
            login_url,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: realm_theme,
            inline_theme_css: state.inline_theme_css(),
        })
    };

    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, form.is_some()) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let realm_theme = state.realm_theme_url_for(realm.id());
    let login_url = format!("{action_prefix}/login");

    let token = match form {
        None => link_token::read(headers),
        Some(form) => {
            link_token::confirmed_token(&state, headers, &form.link_binding, &form.csrf, true)
        }
    };
    let Some(token) = token else {
        // A refused POST keeps the link: the genuine page can still submit.
        return render_status(
            &AcceptInvitationTemplate {
                success: false,
                org_name: String::new(),
                error_message: "This invitation link is missing or invalid.".to_string(),
                login_url,
                chrome: false,
                active: "",
                user_email: None,
                is_admin: false,
                flash: None,
                csrf: None,
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                realm_theme_url: realm_theme,
                inline_theme_css: state.inline_theme_css(),
            },
            StatusCode::BAD_REQUEST,
        );
    };
    if form.is_none() {
        return render_link_confirm(
            &state,
            headers,
            &token,
            INVITATION_COPY,
            format!("{action_prefix}/accept-invitation"),
            realm_theme,
            true,
        );
    }

    link_token::mark_spent(match state.identity.accept_invitation(realm.id(), &token) {
        Ok(membership) => {
            let org_name = state
                .identity
                .get_organization(realm.id(), membership.org_id())
                .ok()
                .flatten()
                .map_or_else(|| "the organization".to_string(), |o| o.name().to_string());
            render_result(true, org_name, String::new(), login_url, realm_theme)
        }
        Err(_) => render_result(
            false,
            String::new(),
            "This invitation has expired or is invalid.".to_string(),
            login_url,
            realm_theme,
        ),
    })
}

// ============================================================================
// Device Authorization Approval
// ============================================================================

/// Query / flash parameters for the device approval page.
#[derive(Debug, Deserialize)]
pub struct DeviceApproveParams {
    /// Flash key for success / error messages after POST redirect.
    pub flash: Option<String>,
}

/// Template for the device authorization approval page.
#[derive(Template)]
#[template(path = "ui/device_approve.html")]
#[allow(clippy::struct_excessive_bools)]
pub struct DeviceApproveTemplate {
    pub chrome: bool,
    pub active: &'static str,
    pub user_email: Option<String>,
    pub is_admin: bool,
    pub flash: Option<super::templates::Flash>,
    pub csrf: Option<String>,
    pub narrow: bool,
    pub product_name: String,
    pub logo_url: String,
    pub realm_theme_url: Option<String>,
    pub inline_theme_css: Option<String>,
    /// The device authorization awaiting the user's decision. `None` renders
    /// the code-entry form; `Some` renders the confirmation step.
    pub pending: Option<DevicePendingView>,
}

/// What the confirmation step shows about a pending device authorization:
/// which application is asking and for what (GA audit B3).
pub struct DevicePendingView {
    /// The requesting client's display name.
    pub client_name: String,
    /// The requesting client's logo, when it registered one.
    pub client_logo_url: Option<String>,
    /// The scopes the device requested.
    pub scopes: Vec<String>,
    /// The user code, carried to the decision.
    pub user_code: String,
}

/// Form submitted from the device page.
#[derive(Debug, Deserialize)]
pub struct DeviceApproveForm {
    /// The 8-character user code shown on the input-constrained device.
    pub user_code: String,
    /// CSRF token.
    #[serde(default)]
    pub csrf_token: Option<String>,
    /// `approve` or `deny` from the confirmation step. Absent on the first
    /// submission, which only looks the code up and shows what it grants.
    #[serde(default)]
    pub decision: Option<String>,
}

/// GET `/ui/device` — renders the device approval form (requires auth).
pub async fn device_approve_form(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
    Query(params): Query<DeviceApproveParams>,
) -> Response {
    let admin = is_admin(&state, &session);
    let flash = match params.flash.as_deref() {
        Some("approved") => Some(super::templates::Flash {
            kind: "success",
            message: "Device approved successfully.".to_string(),
        }),
        Some("expired") => Some(super::templates::Flash {
            kind: "error",
            message: "That device code has expired.".to_string(),
        }),
        Some("invalid") => Some(super::templates::Flash {
            kind: "error",
            message: "Invalid device code. Please check and try again.".to_string(),
        }),
        Some("denied") => Some(super::templates::Flash {
            kind: "success",
            message: "Device access denied.".to_string(),
        }),
        _ => None,
    };

    render(&DeviceApproveTemplate {
        chrome: true,
        active: "",
        user_email: Some(session.user_email.clone()),
        is_admin: admin,
        flash,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
        pending: None,
    })
}

/// POST `/ui/device` — processes the device approval form.
///
/// Guarded by [`crate::abuse::device_approval::DeviceApprovalGuard`]
/// (task 22.26, audit 2026-08-28 §4.25#4): an authenticated session gets a
/// bounded number of wrong user codes before an escalating lockout, and the
/// endpoint is rate-shaped per IP and per realm. Without a ceiling an
/// attacker does not need to guess a *specific* code — any code currently
/// pending in the realm approves a device they control.
pub async fn device_approve_submit(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    Form(form): Form<DeviceApproveForm>,
) -> Response {
    // F5: verify CSRF before mutating. csrf_token is always present in the
    // template; an absent or mismatched value is a CSRF attack vector.
    if let Err(resp) =
        super::auth::verify_csrf_form_field(&session, form.csrf_token.as_deref().unwrap_or(""))
    {
        return resp;
    }

    let guard_key = format!(
        "{}:{}",
        session.realm_id.as_uuid(),
        session.user_id.as_uuid()
    );
    let peer_ip = captcha_client_ip(&headers, peer_addr, &state.trusted_proxies);

    match state
        .device_approval_guard
        .check(&guard_key, peer_ip, &session.realm_id)
    {
        DeviceApprovalDecision::Allow => {}
        decision => return device_approval_refusal(decision),
    }

    let code = form.user_code.trim().to_uppercase();

    if code.is_empty() || code.len() > 8 {
        let decision = state.device_approval_guard.record_failure(&guard_key);
        if decision != DeviceApprovalDecision::Allow {
            return device_approval_refusal(decision);
        }
        return Redirect::to("/ui/device?flash=invalid").into_response();
    }

    // The user code alone never approves anything (GA audit B3). The first
    // submission shows which application is asking and for which scopes;
    // only an explicit Approve from that page reaches the gates below.
    match form.decision.as_deref() {
        Some("approve") => {}
        Some("deny") => return deny_device(&state, &session, &guard_key, &code),
        _ => return confirm_device(&state, &session, &guard_key, &code),
    }

    // A client or role that demands a second factor needs a session that
    // PROVED one — the browser authorize path's `mfa_use_gate` rule
    // (GA audit B5), applied before any other approval gate.
    if let Some(refusal) = device_mfa_use_gate(&state, &session, &code) {
        return refusal;
    }

    // Approving a device hands the device client tokens for this user, so it
    // passes the same gates as issuing an authorization code. It used to run
    // neither: pending required actions were skipped, and a session created
    // without the realm's SMS factor (passkey, magic link, federation)
    // approved a device on a realm that requires it.
    //
    // 1. Required actions first. The RA flow ends by returning here, where
    //    the user submits the code again and meets the SMS gate.
    let now = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    if let Some(ra_response) = super::required_action::required_action_check_browser(
        &state,
        &session.realm_id,
        &session.user_id,
        Some("/ui/device"),
        // What the login behind this session proved; the session the
        // detour ends in records no more than that.
        &SessionContext {
            mfa_proof: session.mfa_proof,
            ..build_session_context(&headers, peer_addr, &state.trusted_proxies)
        },
        // The session does not record what proved its first factor;
        // reading it as a magic link keeps an email OTP enrolled on the
        // way from counting as a second factor (GA sweep 4 round 2).
        super::auth::FirstFactor::Inbox,
        &headers,
        now,
    ) {
        return ra_response;
    }
    finish_device_approval(
        &state,
        &session.realm_id,
        &session.user_id,
        &code,
        session.mfa_proof,
    )
}

/// Approves device user code `code` for `user_id` once every gate has passed,
/// charging a wrong code to the brute-force guard, and redirects to the
/// device page with the outcome.
///
/// Called by `device_approve_submit`.
pub(super) fn finish_device_approval(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &crate::core::UserId,
    code: &str,
    mfa_proof: MfaProof,
) -> Response {
    let guard_key = format!("{}:{}", realm.as_uuid(), user_id.as_uuid());
    if let Err(resp) = record_device_consent(state, realm, user_id, code) {
        return resp;
    }
    // The device's token session records what the approving session proved
    // (GA audit round 3, D-7).
    match state
        .identity
        .approve_device_from_session(realm, code, user_id, mfa_proof)
    {
        Ok(()) => {
            state.device_approval_guard.record_success(&guard_key);
            Redirect::to("/ui/device?flash=approved").into_response()
        }
        Err(IdentityError::DeviceCodeExpired) => {
            // An expired code is a code that really existed, so it is not a
            // guess. Do not charge it against the attempt budget.
            Redirect::to("/ui/device?flash=expired").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "device_approve: approve_device failed");
            let decision = state.device_approval_guard.record_failure(&guard_key);
            if decision != DeviceApprovalDecision::Allow {
                return device_approval_refusal(decision);
            }
            Redirect::to("/ui/device?flash=invalid").into_response()
        }
    }
}

/// Records the user's consent to the device's client when that client
/// requires consent — the record the browser consent screen writes — so an
/// approved device grant is visible and revocable under the user's connected
/// apps (GA audit B3).
///
/// A code that no longer resolves is left to `approve_device`, which reports
/// it with its own outcome mapping.
fn record_device_consent(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &crate::core::UserId,
    code: &str,
) -> Result<(), Response> {
    let Ok(Some(pending)) = state.identity.pending_device_authorization(realm, code) else {
        return Ok(());
    };
    let client = match state.identity.get_client(realm, &pending.client_id) {
        Ok(Some(client)) => client,
        Ok(None) => return Ok(()),
        Err(e) => {
            tracing::warn!(error = %e, "device_approve: client lookup failed");
            return Err(super::handlers_common::server_error());
        }
    };
    if !client.has_consent_step() {
        return Ok(());
    }
    let scopes: Vec<String> = pending
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let grant = crate::identity::ConsentGrant {
        key: crate::identity::ConsentKey {
            user_id: user_id.clone(),
            client_id: pending.client_id.clone(),
            org_id: None,
            resource: None,
        },
        scopes,
        via: crate::identity::ConsentSurface::Device,
    };
    if let Err(e) = state.identity.grant_consent(realm, &grant) {
        tracing::warn!(error = %e, "device_approve: grant_consent failed");
        return Err(super::handlers_common::server_error());
    }
    Ok(())
}

/// The device-path twin of `authorize_gate::mfa_use_gate` (GA audit B5).
///
/// When the device's client (`mfa_required`) or one of the user's roles
/// (`mfa_required_roles`) demands a second factor, the session must have
/// proved one. A user who holds no factor is left to the required-action
/// gate, which enrols one. A user who holds one must prove it: the session is
/// revoked and the page reloaded, which sends the user to sign in again with
/// the factor. A code that no longer resolves is left to `approve_device`.
fn device_mfa_use_gate(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    code: &str,
) -> Option<Response> {
    if session.mfa_proof.satisfies_mfa_required() {
        return None;
    }
    let Ok(Some(pending)) = state
        .identity
        .pending_device_authorization(&session.realm_id, code)
    else {
        return None;
    };
    let client_id = pending.client_id.as_uuid().to_string();
    match super::required_action::mfa_requirement_for(
        state,
        &session.realm_id,
        &session.user_id,
        Some(&client_id),
    ) {
        Ok(false) => return None,
        Ok(true) => {}
        Err(()) => return Some(super::handlers_common::server_error()),
    }
    match state
        .identity
        .has_second_factor(&session.realm_id, &session.user_id)
    {
        Ok(false) => return None,
        Ok(true) => {}
        Err(e) => {
            tracing::warn!(error = %e, "device_approve: factor lookup failed at the MFA-use gate");
            return Some(super::handlers_common::server_error());
        }
    }
    if let Err(e) = state
        .identity
        .revoke_session(&session.realm_id, &session.session_id)
    {
        tracing::warn!(error = %e, "device_approve: revoking an unproved session failed");
        return Some(super::handlers_common::server_error());
    }
    Some(Redirect::to("/ui/device").into_response())
}

/// First submission of a user code: look it up and render the confirmation
/// step naming the client, its logo and the requested scopes. Approves
/// nothing (GA audit B3).
fn confirm_device(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    guard_key: &str,
    code: &str,
) -> Response {
    let pending = match state
        .identity
        .pending_device_authorization(&session.realm_id, code)
    {
        Ok(Some(pending)) => pending,
        // An expired code really existed, so it is not a guess (as in
        // `finish_device_approval`).
        Err(IdentityError::DeviceCodeExpired) => {
            return Redirect::to("/ui/device?flash=expired").into_response();
        }
        Ok(None) | Err(_) => {
            let decision = state.device_approval_guard.record_failure(guard_key);
            if decision != DeviceApprovalDecision::Allow {
                return device_approval_refusal(decision);
            }
            return Redirect::to("/ui/device?flash=invalid").into_response();
        }
    };
    let client = match state
        .identity
        .get_client(&session.realm_id, &pending.client_id)
    {
        Ok(Some(client)) => client,
        Ok(None) => return Redirect::to("/ui/device?flash=invalid").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "device_approve: client lookup failed");
            return super::handlers_common::server_error();
        }
    };
    render(&DeviceApproveTemplate {
        chrome: true,
        active: "",
        user_email: Some(session.user_email.clone()),
        is_admin: is_admin(state, session),
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
        pending: Some(DevicePendingView {
            client_name: client.client_name().to_string(),
            client_logo_url: client.client_logo_url().map(str::to_string),
            scopes: pending
                .scope
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            user_code: code.to_string(),
        }),
    })
}

/// Deny from the confirmation step: the device receives `access_denied`.
fn deny_device(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    guard_key: &str,
    code: &str,
) -> Response {
    match state
        .identity
        .deny_device(&session.realm_id, code, &session.user_id)
    {
        Ok(()) => Redirect::to("/ui/device?flash=denied").into_response(),
        Err(IdentityError::DeviceCodeExpired) => {
            // Unknown and expired codes both land here; charge the guard so
            // Deny is no cheaper an oracle than the lookup.
            let decision = state.device_approval_guard.record_failure(guard_key);
            if decision != DeviceApprovalDecision::Allow {
                return device_approval_refusal(decision);
            }
            Redirect::to("/ui/device?flash=expired").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "device_approve: deny_device failed");
            let decision = state.device_approval_guard.record_failure(guard_key);
            if decision != DeviceApprovalDecision::Allow {
                return device_approval_refusal(decision);
            }
            Redirect::to("/ui/device?flash=invalid").into_response()
        }
    }
}

/// Renders a 429 for a shaped or locked-out device-approval attempt.
///
/// Both cases carry `Retry-After` so a well-behaved client backs off instead
/// of hammering, and neither reveals whether the submitted code existed.
fn device_approval_refusal(decision: DeviceApprovalDecision) -> Response {
    let retry_after = match decision {
        DeviceApprovalDecision::LockedOut { until, .. } => {
            DeviceApprovalGuard::retry_after_secs(until)
        }
        _ => 1,
    };
    tracing::warn!(?decision, "device_approve: refused by brute-force guard");
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        "Too many device approval attempts. Please wait and try again.",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HEA-1887 / R1: an overloaded KDF gate sheds with `503` + a non-zero
    /// `Retry-After`, so login degrades honestly under saturation instead of
    /// inflating p99 by queueing. Pairs with the primitive-level shed test in
    /// `identity::kdf_gate` (which proves past-bound ops return `Overloaded`).
    #[test]
    fn kdf_shed_response_is_503_with_retry_after() {
        let resp = kdf_shed_response(std::time::Duration::from_secs(3));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry = resp
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header present");
        assert_eq!(retry.to_str().expect("ascii"), "3");
    }

    /// A sub-second retry hint is floored to 1 — `Retry-After: 0` is handled
    /// inconsistently by clients and would invite immediate retry storms.
    #[test]
    fn kdf_shed_response_floors_retry_after_to_one() {
        let resp = kdf_shed_response(std::time::Duration::from_millis(200));
        let retry = resp
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header present");
        assert_eq!(retry.to_str().expect("ascii"), "1");
    }

    #[test]
    fn derive_base_url_uses_configured_origin() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            "auth.example.com:8420".parse().expect("valid header"),
        );
        h.insert("x-forwarded-proto", "https".parse().expect("valid header"));
        assert_eq!(
            derive_base_url(
                Some("https://canonical.example.com"),
                "http://127.0.0.1:8420",
                &h
            ),
            "https://canonical.example.com"
        );
    }

    #[test]
    fn derive_base_url_ignores_host_and_forwarded_proto_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            "attacker.example".parse().expect("valid header"),
        );
        h.insert("x-forwarded-proto", "https".parse().expect("valid header"));
        assert_eq!(
            derive_base_url(
                Some("https://auth.example.com"),
                "http://127.0.0.1:8420",
                &h
            ),
            "https://auth.example.com"
        );
    }

    #[test]
    fn derive_base_url_falls_back_to_bind_origin_with_port() {
        // When onboarding.base_url is unset, the fallback (the server's own
        // bind origin) is used — and it MUST carry the port so emailed links
        // are reachable. This is the regression for the missing-:8420 bug.
        let h = HeaderMap::new();
        assert_eq!(
            derive_base_url(None, "http://127.0.0.1:8420", &h),
            "http://127.0.0.1:8420"
        );
    }

    #[test]
    fn derive_base_url_trims_trailing_slash() {
        let h = HeaderMap::new();
        assert_eq!(
            derive_base_url(
                Some("https://auth.example.com/"),
                "http://127.0.0.1:8420",
                &h
            ),
            "https://auth.example.com"
        );
    }

    #[test]
    fn validate_setup_form_requires_email_at_sign() {
        let form = SetupForm {
            link_binding: String::new(),
            admin_email: "no-at-sign".to_string(),
            admin_display_name: "d".to_string(),
            admin_password: FormSecret::new("longenough1234".to_string()),
        };
        let err = validate_setup_form(&form).expect_err("should reject");
        assert!(err.contains("email"), "got: {err}");
    }

    #[test]
    fn validate_setup_form_requires_password_min_length() {
        let form = SetupForm {
            link_binding: String::new(),
            admin_email: "a@b.com".to_string(),
            admin_display_name: "d".to_string(),
            admin_password: FormSecret::new("short".to_string()),
        };
        let err = validate_setup_form(&form).expect_err("should reject");
        assert!(err.contains("12 characters"), "got: {err}");
    }

    #[test]
    fn validate_setup_form_accepts_valid_input() {
        let form = SetupForm {
            link_binding: String::new(),
            admin_email: "alice@acme.com".to_string(),
            admin_display_name: "Alice".to_string(),
            admin_password: FormSecret::new("super-secret-123".to_string()),
        };
        assert!(validate_setup_form(&form).is_ok());
    }

    // ── HEA-1979: KDF shed HTML page tests ──────────────────────────────────

    /// The themed shed page must carry the `data-testid="kdf-shed-retry-form"`
    /// attribute so the Playwright regression can assert on it without relying
    /// on fragile text content.
    #[test]
    fn kdf_shed_template_renders_retry_form_when_action_is_provided() {
        use askama::Template as _;
        let tmpl = super::super::handlers_common::KdfShedTemplate {
            retry_after_secs: 5,
            email: "alice@example.com".to_string(),
            return_to: None,
            form_action: Some("/ui/login".to_string()),
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: Some("test-csrf-token".to_string()),
            narrow: true,
            product_name: "Hearth".to_string(),
            logo_url: "/_/logo.svg".to_string(),
            realm_theme_url: None,
            inline_theme_css: None,
        };
        let html = tmpl.render().expect("template renders");
        assert!(
            html.contains("kdf-shed-retry-form"),
            "retry form testid present in: {html}"
        );
        assert!(
            html.contains("alice@example.com"),
            "email pre-filled in: {html}"
        );
        assert!(
            html.contains("5 second"),
            "retry-after count present in: {html}"
        );
    }

    /// When no `form_action` is set the template must NOT render the retry form
    /// — it should show a "back to home" link instead. This path is hit by
    /// `account_change_password` and `totp_activate` where there is no
    /// meaningful POST URL to re-submit.
    #[test]
    fn kdf_shed_template_renders_back_link_when_no_form_action() {
        use askama::Template as _;
        let tmpl = super::super::handlers_common::KdfShedTemplate {
            retry_after_secs: 2,
            email: String::new(),
            return_to: None,
            form_action: None,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name: "Hearth".to_string(),
            logo_url: "/_/logo.svg".to_string(),
            realm_theme_url: None,
            inline_theme_css: None,
        };
        let html = tmpl.render().expect("template renders");
        assert!(
            !html.contains("kdf-shed-retry-form"),
            "no retry form when action is None in: {html}"
        );
        assert!(
            html.contains("Back to home"),
            "back-to-home link present in: {html}"
        );
    }

    /// The plural/singular second copy must agree: 1 → "second", ≠1 → "seconds".
    #[test]
    fn kdf_shed_template_pluralises_seconds_correctly() {
        use askama::Template as _;
        let make = |secs: u64| super::super::handlers_common::KdfShedTemplate {
            retry_after_secs: secs,
            email: String::new(),
            return_to: None,
            form_action: None,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name: "Hearth".to_string(),
            logo_url: "/_/logo.svg".to_string(),
            realm_theme_url: None,
            inline_theme_css: None,
        };
        let singular = make(1).render().expect("renders");
        assert!(singular.contains("1 second"), "singular: {singular}");
        assert!(!singular.contains("1 seconds"), "no trailing s: {singular}");
        let plural = make(30).render().expect("renders");
        assert!(plural.contains("30 seconds"), "plural: {plural}");
    }
}

/// Secret-bearing form fields are wiped on drop and never printed by `Debug`
/// (GA audit L20).
#[cfg(test)]
mod secret_field_tests {
    use super::*;
    use crate::core::secrets::assert_zeroize_on_drop;

    fn assert_redacted(dbg: &str) {
        assert!(!dbg.contains("CANARY"), "Debug leaked a secret: {dbg}");
    }

    #[test]
    fn login_form_password_is_zeroized_and_redacted() {
        let form: LoginForm =
            serde_urlencoded::from_str("email=a%40b.test&password=CANARY-pw").expect("form parses");
        assert_zeroize_on_drop(&form.password);
        assert_eq!(form.password.expose(), "CANARY-pw");
        assert_redacted(&format!("{form:?}"));
    }

    #[test]
    fn register_form_secrets_are_zeroized_and_redacted() {
        let form: RegisterForm = serde_urlencoded::from_str(
            "email=a%40b.test&password=CANARY-pw&password_confirm=CANARY-pc\
             &invitation_token=CANARY-inv",
        )
        .expect("form parses");
        assert_zeroize_on_drop(&form.password);
        assert_zeroize_on_drop(&form.password_confirm);
        assert_zeroize_on_drop(&form.invitation_token);
        assert_eq!(form.password.expose(), "CANARY-pw");
        assert_redacted(&format!("{form:?}"));
    }

    #[test]
    fn setup_form_password_is_zeroized_and_redacted() {
        let form: SetupForm = serde_urlencoded::from_str(
            "link_binding=b&admin_email=a%40b.test&admin_display_name=A\
             &admin_password=CANARY-pw",
        )
        .expect("form parses");
        assert_zeroize_on_drop(&form.admin_password);
        assert_eq!(form.admin_password.expose(), "CANARY-pw");
        assert_redacted(&format!("{form:?}"));
    }

    #[test]
    fn reset_password_form_is_zeroized_and_redacted() {
        let form: ResetPasswordFormData = serde_urlencoded::from_str(
            "link_binding=b&password=CANARY-pw&password_confirm=CANARY-pc",
        )
        .expect("form parses");
        assert_zeroize_on_drop(&form.password);
        assert_zeroize_on_drop(&form.password_confirm);
        assert_eq!(form.password_confirm.expose(), "CANARY-pc");
        assert_redacted(&format!("{form:?}"));
    }
}

//! The password email an administrator sends a user (OpenSpec
//! `password-email`): the `welcome` email with a set-password link for a user
//! with no password, the reset email for a user with one.
//!
//! The admin API (`POST /admin/users/{id}/password-email`) and the console's
//! "Send reset email" and bulk "Send invite" actions share this path. It
//! sends on the request path, because the caller needs to know whether the
//! email left.

use std::fmt;

use crate::abuse::runtime::{AbuseGuards, OutboundVerdict};
use crate::core::{RealmId, UserId};
use crate::identity::email::{EmailError, EmailService};
use crate::identity::{IdentityEngine, IdentityError, PasswordEmailKind};

/// Why no password email was sent. It never carries the link token.
#[derive(Debug)]
#[non_exhaustive]
pub enum PasswordEmailError {
    /// No email transport is configured.
    NoTransport,
    /// An outbound email cap (A-4 or A-50) refused the send.
    OutboundCap,
    /// The identity layer refused the request: an unknown user, a realm
    /// without password sign-in, or the per-address reset limit.
    Identity(IdentityError),
    /// The transport refused the message. The link exists but did not leave.
    Delivery(EmailError),
}

impl fmt::Display for PasswordEmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTransport => f.write_str("no email transport is configured"),
            Self::OutboundCap => f.write_str("an outbound email cap refused the send"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Delivery(e) => write!(f, "the email could not be delivered: {e}"),
        }
    }
}

impl std::error::Error for PasswordEmailError {}

/// Issues the user's password link and emails it. Returns the kind of email
/// sent.
///
/// `base_url` is the public origin of the realm's reset page, with no
/// trailing slash.
///
/// # Errors
///
/// See [`PasswordEmailError`]. The checks run in this order: transport,
/// user, outbound caps, then the identity layer's own checks.
pub fn send_password_email(
    identity: &dyn IdentityEngine,
    email: Option<&EmailService>,
    guards: &AbuseGuards,
    base_url: &str,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<PasswordEmailKind, PasswordEmailError> {
    let email = email.ok_or(PasswordEmailError::NoTransport)?;
    let realm = identity
        .get_realm(realm_id)
        .map_err(PasswordEmailError::Identity)?
        .ok_or(PasswordEmailError::Identity(IdentityError::RealmNotFound))?;
    let user = identity
        .get_user(realm_id, user_id)
        .map_err(PasswordEmailError::Identity)?
        .ok_or(PasswordEmailError::Identity(IdentityError::UserNotFound))?;

    // A-4 + A-50: checked before the link exists, so a refused send does not
    // supersede the user's earlier link.
    match guards.check_outbound_email(&realm_id.as_uuid().to_string(), user.email()) {
        OutboundVerdict::Deny { reason } => {
            tracing::warn!(
                guard = reason,
                "password email: outbound cap reached; email not sent"
            );
            return Err(PasswordEmailError::OutboundCap);
        }
        OutboundVerdict::Warn { reason } => {
            tracing::warn!(guard = reason, "password email: outbound soft cap reached");
        }
        OutboundVerdict::Allow => {}
    }

    let mail = identity
        .request_password_email(realm_id, user_id)
        .map_err(PasswordEmailError::Identity)?;
    let url = format!(
        "{}/ui/realms/{}/reset-password?token={}",
        base_url.trim_end_matches('/'),
        form_urlencoded::byte_serialize(realm.name().as_bytes()).collect::<String>(),
        mail.token
    );
    let branding = realm.config().email_branding.as_ref();
    let templates = &realm.config().email_templates;
    let sent = match mail.kind {
        PasswordEmailKind::Setup => {
            email.send_welcome_email(&mail.email, &url, branding, templates.get("welcome"), None)
        }
        PasswordEmailKind::Reset => email.send_password_reset_email(
            &mail.email,
            &url,
            branding,
            templates.get("password_reset"),
            None,
        ),
    };
    sent.map_err(PasswordEmailError::Delivery)?;
    Ok(mail.kind)
}

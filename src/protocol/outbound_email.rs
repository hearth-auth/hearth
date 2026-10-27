//! The A-4 and A-50 outbound email caps, audited (#622).
//!
//! Every self-service email passes [`admit`] before it is sent. A send that a
//! cap stops or flags writes an `AbuseDetected` event in the sending realm,
//! which the A-7 security webhook delivers. At most one event is written per
//! guard and realm in the guard's window: a refused send writes nothing else,
//! so one event per request would let a caller fill the audit log.
//!
//! The event names the cap and the email flow. It never names the recipient,
//! and never the A-50 realm count, which the sending realm must not see.

use crate::abuse::runtime::{AbuseGuards, OutboundVerdict};
use crate::audit::{AuditAction, AuditEngine, CreateAuditEvent};
use crate::core::RealmId;

/// The email a caller is about to send, for the audit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmailFlow {
    /// The forgot-password form's reset link.
    PasswordReset,
    /// The registration form's email verification link.
    Verification,
    /// A magic sign-in link.
    MagicLink,
    /// An admin's set-password or reset email.
    PasswordEmail,
}

impl EmailFlow {
    /// The `flow` value written to the audit metadata.
    fn as_str(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::Verification => "verification",
            Self::MagicLink => "magic_link",
            Self::PasswordEmail => "password_email",
        }
    }
}

/// Runs the A-4 and A-50 checks for one recipient of `realm_id`, and audits a
/// send that a cap stops or flags. Returns whether the email may be sent.
pub(crate) fn admit(
    guards: &AbuseGuards,
    audit: &dyn AuditEngine,
    realm_id: &RealmId,
    recipient: &str,
    flow: EmailFlow,
) -> bool {
    let realm_key = realm_id.as_uuid().to_string();
    let (guard, sent) = match guards.check_outbound_email(&realm_key, recipient) {
        OutboundVerdict::Allow => return true,
        OutboundVerdict::Warn { reason } => (reason, true),
        OutboundVerdict::Deny { reason } => (reason, false),
    };
    if sent {
        tracing::warn!(
            guard,
            flow = flow.as_str(),
            "outbound email cap flagged a send"
        );
    } else {
        tracing::warn!(
            guard,
            flow = flow.as_str(),
            "outbound email cap reached; email not sent"
        );
    }
    if guards.should_audit_outbound(&realm_key, guard) {
        crate::protocol::audit_log::record(
            audit,
            &CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "system".to_string(),
                action: AuditAction::AbuseDetected,
                resource_type: "email".to_string(),
                resource_id: flow.as_str().to_string(),
                metadata: Some(serde_json::json!({
                    "guard": guard,
                    "flow": flow.as_str(),
                    "sent": sent,
                })),
            },
        );
    }
    sent
}

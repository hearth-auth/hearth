//! Short-lived system-realm tokens for operators (GA audit 3 DOC-2).
//!
//! Runbooks that call `/admin/realms` or `/admin/cluster/*` need a token for
//! the system realm (the nil UUID). Two surfaces mint one through
//! [`crate::identity::IdentityEngine::issue_operator_token`]:
//!
//! * the admin console (`/ui/admin/api-tokens`), for a signed-in operator
//!   after a fresh two-factor step-up — the path for a running server or
//!   cluster, because it writes through the normal storage path (Raft in
//!   cluster mode);
//! * `hearth admin token`, on the host, against a stopped node's data
//!   directory.
//!
//! Both bind the token to a new session that expires with it, and both record
//! the issuance in the system realm's audit trail before the token exists
//! anywhere else.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::core::{SessionId, Timestamp, UserId};

/// Shortest lifetime an operator token is issued for.
pub const OPERATOR_TOKEN_MIN_TTL: Duration = Duration::from_secs(60);

/// Longest lifetime an operator token is issued for.
pub const OPERATOR_TOKEN_MAX_TTL: Duration = Duration::from_secs(60 * 60);

/// Default lifetime offered by both surfaces.
pub const OPERATOR_TOKEN_DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);

/// Which surface asked for an operator token. Recorded in the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperatorTokenIssuer {
    /// `hearth admin token` on the host, against a stopped node's store.
    /// The audit actor is `system`: no one signed in.
    HostCli,
    /// The admin console, by the signed-in operator after a fresh step-up.
    /// The audit actor is the operator.
    Console {
        /// The console session the request came from.
        console_session_id: SessionId,
    },
}

impl OperatorTokenIssuer {
    /// The `issued_via` value in the issuance's audit metadata.
    #[must_use]
    pub fn issued_via(&self) -> &'static str {
        match self {
            Self::HostCli => "hearth admin token",
            Self::Console { .. } => "admin console",
        }
    }
}

/// A system-realm access token minted for an operator.
///
/// The token is a bearer credential: it is zeroed on drop and `Debug` does
/// not print it.
pub struct OperatorToken {
    access_token: Zeroizing<String>,
    jti: Option<String>,
    user_id: UserId,
    session_id: SessionId,
    expires_at: Timestamp,
}

impl OperatorToken {
    /// Assembles an issued token. Only the identity engine mints one.
    pub(crate) fn new(
        access_token: Zeroizing<String>,
        jti: Option<String>,
        user_id: UserId,
        session_id: SessionId,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            access_token,
            jti,
            user_id,
            session_id,
            expires_at,
        }
    }

    /// The signed access token (a JWT) — show it once, never log it.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The token's `jti`, as recorded in the audit trail.
    #[must_use]
    pub fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
    }

    /// The operator account the token was issued to.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The session the token is bound to. Revoking it revokes the token.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// When the token (and its session) stop validating.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl fmt::Debug for OperatorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorToken")
            .field("access_token", &"<redacted>")
            .field("jti", &self.jti)
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

use std::net::IpAddr;

use crate::core::RealmId;

/// Outcome returned by [`crate::abuse::AbusePolicy::check`].
///
/// Variants use `&'static str` for the reason field to avoid heap allocation
/// on the hot path — callers supply string literals from a static table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseDecision {
    /// Permit the request to proceed.
    Allow,

    /// Reject the request unconditionally.
    Block {
        /// Static reason string for internal logging. Never exposed to callers.
        reason: &'static str,
    },

    /// Challenge the caller (e.g. step-up auth, CAPTCHA).
    ///
    /// The transport layer treats this identically to `Block` until a
    /// challenge protocol is implemented in a later phase.
    Challenge {
        /// Static reason string for internal logging.
        reason: &'static str,
    },
}

/// Immutable request snapshot passed to [`crate::abuse::AbusePolicy::check`].
///
/// All fields borrow from request metadata so the guard constructs this
/// with zero heap allocations on the hot path.
#[derive(Debug, Clone, Copy)]
pub struct AbuseRequest<'a> {
    /// Realm being targeted by this request.
    pub realm_id: &'a RealmId,

    /// Client IP address (after trusted-proxy resolution if configured).
    pub client_ip: IpAddr,

    /// Short static endpoint label for telemetry (e.g. `"token"`, `"authorize"`).
    pub endpoint: &'static str,
}

/// Per-realm abuse-prevention policy configuration.
///
/// Sourced from `realms.<name>.abuse` in `hearth.yaml` and passed to the
/// `AbusePolicy` implementation at startup.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAbuseConfig {
    /// Enable abuse prevention checks for this realm.
    ///
    /// Defaults to `true` when the `abuse:` YAML block is explicitly present.
    /// Realms that omit the block entirely remain opt-in (backward-compatible).
    #[serde(default = "crate::abuse::types::default_enabled")]
    pub enabled: bool,

    /// When `true`, a policy evaluation error blocks the request.
    /// When `false` (default), errors allow the request through (fail-open).
    #[serde(default)]
    pub fail_closed: bool,
}

impl Default for RealmAbuseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_closed: false,
        }
    }
}

/// Private default used by serde for `RealmAbuseConfig::enabled`.
#[doc(hidden)]
pub(crate) fn default_enabled() -> bool {
    true
}

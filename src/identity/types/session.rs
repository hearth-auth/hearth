//! Session types.

use serde::{Deserialize, Serialize};

use crate::core::{SessionId, Timestamp, UserId};

/// Device and network context captured at session creation time.
///
/// All fields are optional — API-originated sessions (no browser) or
/// sessions created before this feature was added will have `None` values.
#[derive(Clone, Debug, Default)]
pub struct SessionContext {
    /// Client IP address (peer or extracted from `X-Forwarded-For`).
    pub ip_address: Option<String>,
    /// Raw `User-Agent` header value (stored for future re-parsing).
    pub user_agent_raw: Option<String>,
    /// Pre-parsed device label, e.g. `"Chrome, Mac OSX"`.
    pub device_label: Option<String>,
    /// Set to `true` only when the session originates from a WebAuthn
    /// (passkey) ceremony **that proved user verification** — the
    /// authenticator collected a PIN, a biometric, or an equivalent local
    /// check and set the UV flag.
    ///
    /// Such a ceremony is two factors (possession + the local check) and so
    /// satisfies a realm's `mfa_required` policy. A ceremony that proved user
    /// *presence* only is a touch: possession alone, one factor, and it must
    /// not set this (audit 2026-08-28 B10).
    pub satisfies_mfa_via_passkey: bool,
}

/// An authentication session bound to a user.
///
/// Sessions have a configurable TTL and can be refreshed or revoked.
/// Fields are private; access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    created_at: Timestamp,
    expires_at: Timestamp,
    last_refreshed_at: Timestamp,
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_agent_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_label: Option<String>,
    /// Deadline after which the session is idle-expired (A-18).
    /// Stored in the session record so `get_session` avoids a realm lookup on
    /// every access. Reset on each `refresh()`. `None` = no idle timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) idle_deadline: Option<Timestamp>,
    /// Hard absolute expiry deadline set at creation time (A-18).
    /// Never updated on refresh. `None` = no absolute timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) absolute_deadline: Option<Timestamp>,
}

impl Session {
    /// Creates a new session. Used internally by the identity engine.
    pub(crate) fn new(
        id: SessionId,
        user_id: UserId,
        created_at: Timestamp,
        expires_at: Timestamp,
        context: &SessionContext,
        idle_timeout_secs: Option<u32>,
        absolute_timeout_secs: Option<u32>,
    ) -> Self {
        let idle_deadline = idle_timeout_secs.map(|s| created_at.add_micros(s as i64 * 1_000_000));
        let absolute_deadline =
            absolute_timeout_secs.map(|s| created_at.add_micros(s as i64 * 1_000_000));
        Self {
            id,
            user_id,
            created_at,
            expires_at,
            last_refreshed_at: created_at,
            revoked: false,
            ip_address: context.ip_address.clone(),
            user_agent_raw: context.user_agent_raw.clone(),
            device_label: context.device_label.clone(),
            idle_deadline,
            absolute_deadline,
        }
    }

    /// Returns the session's unique identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the ID of the user this session belongs to.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns when the session was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the session expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns when the session was last refreshed (UTC microseconds).
    pub fn last_refreshed_at(&self) -> Timestamp {
        self.last_refreshed_at
    }

    /// Returns whether the session has been revoked.
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns whether the session is valid (not expired and not revoked).
    pub(crate) fn is_valid(&self, now: Timestamp) -> bool {
        !self.revoked && now < self.expires_at
    }

    /// Marks the session as revoked.
    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Refreshes the session by extending the TTL and resetting the idle deadline.
    pub(crate) fn refresh(&mut self, now: Timestamp, ttl_micros: i64) {
        // Recover idle window BEFORE overwriting last_refreshed_at.
        let new_idle = self.idle_deadline.map(|deadline| {
            let window = deadline.as_micros() - self.last_refreshed_at.as_micros();
            now.add_micros(window)
        });
        self.expires_at = now.add_micros(ttl_micros);
        self.last_refreshed_at = now;
        if let Some(d) = new_idle {
            self.idle_deadline = Some(d);
        }
        // absolute_deadline is intentionally NOT updated — it is a hard cap.
    }

    /// Returns `true` if the session has exceeded its idle or absolute timeout
    /// policy (A-18). Does NOT check the standard TTL (`is_valid`).
    pub(crate) fn is_policy_expired(&self, now: Timestamp) -> bool {
        self.idle_deadline.map_or(false, |d| now >= d)
            || self.absolute_deadline.map_or(false, |d| now >= d)
    }

    /// Returns the eviction reason string for audit metadata.
    pub(crate) fn policy_expiry_reason(&self, now: Timestamp) -> Option<&'static str> {
        if self.idle_deadline.map_or(false, |d| now >= d) {
            return Some("idle_timeout");
        }
        if self.absolute_deadline.map_or(false, |d| now >= d) {
            return Some("absolute_timeout");
        }
        None
    }

    /// Returns the client IP address captured at session creation, if available.
    pub fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    /// Returns the raw User-Agent header captured at session creation, if available.
    pub fn user_agent_raw(&self) -> Option<&str> {
        self.user_agent_raw.as_deref()
    }

    /// Returns the pre-parsed device label (e.g. "Chrome, Mac OSX"), if available.
    pub fn device_label(&self) -> Option<&str> {
        self.device_label.as_deref()
    }

    /// Converts to a flat storage record for binary (postcard) encoding.
    pub(crate) fn to_storage_record(&self) -> SessionStorageRecord {
        SessionStorageRecord {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_refreshed_at: self.last_refreshed_at,
            revoked: self.revoked,
            ip_address: self.ip_address.clone(),
            user_agent_raw: self.user_agent_raw.clone(),
            device_label: self.device_label.clone(),
            idle_deadline: self.idle_deadline,
            absolute_deadline: self.absolute_deadline,
        }
    }

    /// Reconstructs a [`Session`] from a [`SessionStorageRecord`] decoded by postcard.
    pub(crate) fn from_storage_record(r: SessionStorageRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            created_at: r.created_at,
            expires_at: r.expires_at,
            last_refreshed_at: r.last_refreshed_at,
            revoked: r.revoked,
            ip_address: r.ip_address,
            user_agent_raw: r.user_agent_raw,
            device_label: r.device_label,
            idle_deadline: r.idle_deadline,
            absolute_deadline: r.absolute_deadline,
        }
    }
}

/// Binary-storage mirror of [`Session`] without `skip_serializing_if` attributes.
///
/// All optional fields are always written as `Some`/`None` so postcard can
/// encode/decode the struct positionally without field-alignment drift.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SessionStorageRecord {
    pub(crate) id: SessionId,
    pub(crate) user_id: UserId,
    pub(crate) created_at: Timestamp,
    pub(crate) expires_at: Timestamp,
    pub(crate) last_refreshed_at: Timestamp,
    pub(crate) revoked: bool,
    pub(crate) ip_address: Option<String>,
    pub(crate) user_agent_raw: Option<String>,
    pub(crate) device_label: Option<String>,
    pub(crate) idle_deadline: Option<Timestamp>,
    pub(crate) absolute_deadline: Option<Timestamp>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{SessionId, UserId};
    use proptest::prelude::*;
    use uuid::Uuid;

    fn arb_uuid() -> impl Strategy<Value = Uuid> {
        any::<[u8; 16]>().prop_map(Uuid::from_bytes)
    }

    fn arb_timestamp() -> impl Strategy<Value = Timestamp> {
        any::<i64>().prop_map(Timestamp::from_micros)
    }

    fn arb_session_storage_record() -> impl Strategy<Value = SessionStorageRecord> {
        (
            arb_uuid(),
            arb_uuid(),
            arb_timestamp(),
            arb_timestamp(),
            arb_timestamp(),
            any::<bool>(),
            proptest::option::of(".*"),
            proptest::option::of(".*"),
            proptest::option::of(".*"),
            proptest::option::of(arb_timestamp()),
            proptest::option::of(arb_timestamp()),
        )
            .prop_map(
                |(
                    session_uuid,
                    user_uuid,
                    created_at,
                    expires_at,
                    last_refreshed_at,
                    revoked,
                    ip_address,
                    user_agent_raw,
                    device_label,
                    idle_deadline,
                    absolute_deadline,
                )| SessionStorageRecord {
                    id: SessionId::new(session_uuid),
                    user_id: UserId::new(user_uuid),
                    created_at,
                    expires_at,
                    last_refreshed_at,
                    revoked,
                    ip_address,
                    user_agent_raw,
                    device_label,
                    idle_deadline,
                    absolute_deadline,
                },
            )
    }

    proptest! {
        /// Property: `SessionStorageRecord` survives a postcard encode→decode round-trip.
        #[test]
        fn session_storage_record_roundtrip(rec in arb_session_storage_record()) {
            let bytes = crate::codec::encode(&rec).expect("encode");
            let decoded: SessionStorageRecord = crate::codec::decode(&bytes).expect("decode");
            prop_assert_eq!(rec, decoded);
        }
    }
}

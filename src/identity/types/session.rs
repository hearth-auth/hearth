//! Session types.

use serde::{Deserialize, Serialize};

use crate::core::{SessionId, Timestamp, UserId};

/// What the authentication behind a session can say about a second factor.
///
/// A realm's `mfa_required` policy gates factor **use**, not factor enrolment
/// (audit 2026-08-28 §4.18#3). The caller states what happened in this
/// ceremony; the engine decides. `MfaProof::None` is the default, so a login
/// path that says nothing is refused on an MFA-required realm.
///
/// The proof is also recorded on the [`Session`] it opened (GA audit B5), so a
/// later gate — a client that sets `mfa_required`, a role listed in the
/// realm's `mfa_required_roles` — can ask what the session *proved* rather
/// than what the account holds. Stored records encode the variant by its
/// position, so new variants MUST be appended, never inserted.
///
/// There is no "inherited" proof. A session derived from another one — the
/// session behind a completed required-action flow (GA audit round 3, D-1),
/// an authorization-code exchange or a device grant (D-7) — records the proof
/// the authentication behind it actually made. The `Inherited` variant that
/// satisfied every gate whatever had been proved is gone; a record written
/// with it decodes as [`MfaProof::PasskeyPossession`], and one written with
/// the old position of `PasskeyPossession` falls back to the legacy record
/// ([`MfaProof::None`]) — neither proves more than it did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaProof {
    /// No second factor was proved in this authentication.
    #[default]
    None,
    /// A second factor was proved in this authentication by a factor that is
    /// **not** phishing-resistant: a TOTP code, a recovery code, an SMS or an
    /// email OTP.
    ///
    /// This satisfies `mfa_required`. It does not satisfy `webauthn_required`
    /// — that key names a passkey specifically (audit 2026-08-28 §4.18#3).
    Proved,
    /// A WebAuthn (passkey) ceremony proved the second factor **and** proved
    /// user verification — the authenticator collected a PIN, a biometric, or
    /// an equivalent local check and set the UV flag.
    ///
    /// A passkey ceremony that proved user *presence* only is a touch:
    /// possession alone, one factor, and it must not set this (or
    /// [`MfaProof::Proved`]) — audit 2026-08-28 B10.
    ///
    /// This is the only proof a realm with `webauthn_required: true` accepts
    /// from a fresh authentication.
    ProvedWebAuthn,
    /// A WebAuthn (passkey) ceremony that proved user *presence* only.
    ///
    /// Possession of one enrolled passkey and nothing else: one factor. It
    /// satisfies neither `mfa_required` nor `webauthn_required`. It differs
    /// from [`MfaProof::None`] in one respect: the factor the account holds —
    /// the passkey — is the one this ceremony used, so a user whose only
    /// second factor is a passkey is not refused for "holding a factor they
    /// did not prove". A user who also holds TOTP, SMS or email OTP still owes
    /// that factor (GA audit B5).
    PasskeyPossession,
}

impl MfaProof {
    /// Returns whether this proof satisfies a realm's `mfa_required` policy.
    pub fn satisfies_mfa_required(self) -> bool {
        matches!(self, Self::Proved | Self::ProvedWebAuthn)
    }

    /// Returns whether this proof satisfies a realm's `webauthn_required`
    /// policy.
    ///
    /// `webauthn_required` was enforced only at *enrolment* — the user had to
    /// possess a passkey, but any factor could then satisfy the login
    /// (audit 2026-08-28 §4.18#3, task 25.26). Only a WebAuthn assertion that
    /// proved user verification counts here; a TOTP code, a recovery code or
    /// an OTP does not, however many passkeys the account holds.
    pub fn satisfies_webauthn_required(self) -> bool {
        matches!(self, Self::ProvedWebAuthn)
    }
}

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
    /// What this authentication can prove about a second factor. Read by the
    /// `mfa_required` gate in `create_session`.
    pub mfa_proof: MfaProof,
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
    /// What the authentication that opened this session proved about a second
    /// factor (GA audit B5). Records written before this field existed decode
    /// as [`MfaProof::None`]: an unknown proof is treated as no proof.
    #[serde(default)]
    mfa_proof: MfaProof,
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
            mfa_proof: context.mfa_proof,
        }
    }

    /// Returns what the authentication behind this session proved about a
    /// second factor.
    ///
    /// Gates that demand a second factor for a particular client or role read
    /// this — never the account's enrolled factors (GA audit B5).
    pub fn mfa_proof(&self) -> MfaProof {
        self.mfa_proof
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
            mfa_proof: self.mfa_proof,
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
            mfa_proof: r.mfa_proof,
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
    /// Appended last (GA audit B5): postcard is positional, so a record
    /// written before this field existed is one field short and is read by
    /// [`decode_session_record`] through [`LegacySessionStorageRecord`].
    pub(crate) mfa_proof: MfaProof,
}

/// [`SessionStorageRecord`] as written before sessions recorded their
/// [`MfaProof`]. Only ever decoded, never written.
#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct LegacySessionStorageRecord {
    id: SessionId,
    user_id: UserId,
    created_at: Timestamp,
    expires_at: Timestamp,
    last_refreshed_at: Timestamp,
    revoked: bool,
    ip_address: Option<String>,
    user_agent_raw: Option<String>,
    device_label: Option<String>,
    idle_deadline: Option<Timestamp>,
    absolute_deadline: Option<Timestamp>,
}

/// Decodes a stored session record, current layout first, then the layout
/// written before sessions recorded their MFA proof.
///
/// A pre-upgrade session carries no proof, so it decodes as
/// [`MfaProof::None`]: a gate that needs a proved factor treats it as
/// unproved and asks the user to authenticate again, rather than trusting a
/// proof nobody recorded.
///
/// # Errors
///
/// Returns the current layout's decode error when neither layout fits.
pub(crate) fn decode_session_record(bytes: &[u8]) -> Result<SessionStorageRecord, String> {
    match crate::codec::decode::<SessionStorageRecord>(bytes) {
        Ok(record) => Ok(record),
        Err(current_err) => crate::codec::decode::<LegacySessionStorageRecord>(bytes)
            .map(|r| SessionStorageRecord {
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
                mfa_proof: MfaProof::None,
            })
            .map_err(|_| current_err),
    }
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

    fn arb_mfa_proof() -> impl Strategy<Value = MfaProof> {
        prop_oneof![
            Just(MfaProof::None),
            Just(MfaProof::Proved),
            Just(MfaProof::ProvedWebAuthn),
            Just(MfaProof::PasskeyPossession),
        ]
    }

    fn arb_session_storage_record() -> impl Strategy<Value = SessionStorageRecord> {
        (
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
            ),
            arb_mfa_proof(),
        )
            .prop_map(
                |(
                    (
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
                    ),
                    mfa_proof,
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
                    mfa_proof,
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

        /// Property: the current layout also decodes through the
        /// upgrade-aware reader, proof intact.
        #[test]
        fn session_record_decoder_reads_the_current_layout(rec in arb_session_storage_record()) {
            let bytes = crate::codec::encode(&rec).expect("encode");
            let decoded = decode_session_record(&bytes).expect("decode");
            prop_assert_eq!(rec, decoded);
        }
    }

    /// A session written before sessions recorded their MFA proof must still
    /// load after the upgrade — and must load as *unproved*, never as a proof
    /// nobody recorded (GA audit B5).
    #[test]
    fn a_pre_upgrade_session_record_decodes_as_unproved() {
        let legacy = LegacySessionStorageRecord {
            id: SessionId::new(Uuid::new_v4()),
            user_id: UserId::new(Uuid::new_v4()),
            created_at: Timestamp::from_micros(1),
            expires_at: Timestamp::from_micros(2),
            last_refreshed_at: Timestamp::from_micros(1),
            revoked: false,
            ip_address: Some("192.0.2.1".to_string()),
            user_agent_raw: None,
            device_label: None,
            idle_deadline: None,
            absolute_deadline: Some(Timestamp::from_micros(3)),
        };
        let bytes = crate::codec::encode(&legacy).expect("encode legacy");
        let decoded = decode_session_record(&bytes).expect("a legacy record must decode");
        assert_eq!(decoded.id, legacy.id);
        assert_eq!(decoded.ip_address.as_deref(), Some("192.0.2.1"));
        assert_eq!(decoded.absolute_deadline, Some(Timestamp::from_micros(3)));
        assert_eq!(decoded.mfa_proof, MfaProof::None);
    }

    /// The proof a session was opened with is the proof it reports.
    #[test]
    fn a_session_reports_the_proof_it_was_opened_with() {
        let ctx = SessionContext {
            mfa_proof: MfaProof::ProvedWebAuthn,
            ..SessionContext::default()
        };
        let session = Session::new(
            SessionId::new(Uuid::new_v4()),
            UserId::new(Uuid::new_v4()),
            Timestamp::from_micros(1),
            Timestamp::from_micros(2),
            &ctx,
            None,
            None,
        );
        assert_eq!(session.mfa_proof(), MfaProof::ProvedWebAuthn);
        let round = Session::from_storage_record(
            decode_session_record(
                &crate::codec::encode(&session.to_storage_record()).expect("encode"),
            )
            .expect("decode"),
        );
        assert_eq!(round.mfa_proof(), MfaProof::ProvedWebAuthn);
    }
}

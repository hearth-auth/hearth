//! Domain types for SAML SP and IdP operation.
//!
//! All types are plain-data — no I/O, no crypto. Storage codecs live
//! alongside in their respective submodules.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::core::{IdpId, SessionId, Timestamp, UserId};

/// Attribute name mapping for SAML claim translation.
///
/// Keys are Hearth field names (e.g., `"email"`, `"display_name"`,
/// `"external_sub"`). Values are SAML `<Attribute Name="..."/>` URIs
/// (or the sentinel `"NameID"` to pull from `<NameID>` directly).
pub type AttributeMap = BTreeMap<String, String>;

/// SAML `<NameID>` format.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamlNameIdFormat {
    /// `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
    #[default]
    EmailAddress,
    /// `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
    Persistent,
    /// `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
    Transient,
    /// `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
    Unspecified,
}

impl SamlNameIdFormat {
    /// Returns the SAML-defined URI for this format.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            Self::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        }
    }

    /// Parses a `Format` URI into a known variant, defaulting to
    /// `Unspecified` for unknown URIs.
    pub fn from_uri(uri: &str) -> Self {
        match uri {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => Self::EmailAddress,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => Self::Persistent,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => Self::Transient,
            _ => Self::Unspecified,
        }
    }
}

/// Configuration for an upstream SAML IdP that this realm consumes from.
///
/// This is the SP-side view: everything needed for Hearth to initiate a
/// SAML login with the IdP and validate the returned `<Response>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    /// Deterministic ID derived from (realm, idp_name).
    pub idp_id: IdpId,
    /// Human-readable name, matches the YAML key (e.g., `"corp-okta"`).
    pub name: String,
    /// The upstream IdP's entity ID (SAML issuer).
    pub entity_id: String,
    /// The upstream IdP's SingleSignOnService URL (HTTP-Redirect binding).
    pub sso_url: String,
    /// The upstream IdP's SingleLogoutService URL (optional).
    pub slo_url: Option<String>,
    /// IdP's signing certificate(s) PEM. First is primary; additional
    /// entries support key rollover.
    pub idp_certificates_pem: Vec<String>,
    /// If true, Hearth signs outbound `<AuthnRequest>`s with the realm's
    /// SAML key. Many IdPs don't require signed AuthnRequests; when
    /// required (enterprise deployments), flip this on.
    pub sign_authn_requests: bool,
    /// If true, reject assertions whose `<Assertion>` element is not
    /// individually signed. Recommended on.
    pub want_assertions_signed: bool,
    /// Attribute map: Hearth field → SAML attribute URI.
    pub attribute_map: AttributeMap,
}

/// Configuration for a downstream SAML SP that this realm issues to.
///
/// IdP-side view: everything Hearth needs to validate a `<AuthnRequest>`
/// from the SP and issue a signed `<Response>` back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProvider {
    /// Realm-stable slug (matches YAML key).
    pub sp_key: String,
    /// SP's entity ID (what they sign assertions' `AudienceRestriction` with).
    pub entity_id: String,
    /// SP's Assertion Consumer Service URL — where signed `<Response>`s go.
    pub acs_url: String,
    /// SP's SingleLogoutService URL (optional).
    pub slo_url: Option<String>,
    /// SP's signing certificate PEM. Verifies signed `<AuthnRequest>`s and
    /// `<LogoutRequest>`s from this SP.
    ///
    /// Required when `want_authn_requests_signed` is true — config validation
    /// refuses the pairing without it, and the SSO endpoint fails closed if a
    /// runtime registration reaches that state anyway.
    pub sp_certificate_pem: Option<String>,
    /// Sign individual `<Assertion>` elements.
    pub sign_assertions: bool,
    /// Sign the outer `<Response>` envelope.
    pub sign_responses: bool,
    /// If true, reject incoming `<AuthnRequest>`s that do not carry a
    /// signature verifiable against `sp_certificate_pem`.
    ///
    /// The HTTP-Redirect binding carries its signature in query parameters,
    /// not in the XML, so an SP with this flag set must use the HTTP-POST
    /// binding.
    pub want_authn_requests_signed: bool,
    /// NameID format to use in issued assertions.
    pub nameid_format: SamlNameIdFormat,
    /// Attribute map: Hearth field → SAML attribute URI for outbound claims.
    pub attribute_map: AttributeMap,
}

/// How long an SP-side SAML request-state bag stays valid, in seconds.
///
/// A browser round-trip to the IdP and back; ten minutes is generous. The
/// read path refuses an older bag and the periodic cleanup sweeper deletes it
/// (audit 2026-08-28 §4.10#9).
pub const SAML_STATE_TTL_SECS: i64 = 600;

/// Hard cap on live `saml:state:` rows in one realm.
///
/// `GET …/federation/saml/begin` is unauthenticated, so without a ceiling the
/// key space is an anonymous write amplifier: one row per request, reclaimed
/// only by a matching ACS POST that an attacker never sends. Writes past this
/// cap are refused with [`crate::identity::IdentityError::RateLimited`] once
/// the expired rows have been purged.
///
/// Ten thousand concurrent in-flight logins per realm is far above any real
/// browser-driven rate and far below anything that threatens the store.
pub const SAML_STATE_MAX_PER_REALM: usize = 10_000;

/// Extra seconds a SAML assertion replay sentinel outlives the assertion's own
/// `NotOnOrAfter`.
///
/// The sentinel only has to cover the window in which the assertion would
/// still validate. Matching the SP's clock-skew tolerance keeps it correct
/// without keeping it forever (audit 2026-08-28 §4.10#9).
pub const SAML_ASSERTION_SENTINEL_SKEW_SECS: i64 = 300;

/// Short-lived state bag persisted while an SP-initiated login is in
/// flight. Echoed as `RelayState` on the callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStateBag {
    /// Opaque echo token (also the storage key suffix).
    pub token: String,
    /// The AuthnRequest ID we issued upstream (matched in
    /// `<Response InResponseTo="…"/>`).
    pub request_id: String,
    /// Realm this login belongs to.
    pub realm_id: crate::core::RealmId,
    /// IdP connector id.
    pub idp_id: IdpId,
    /// Optional post-login destination (e.g., `/ui/account`).
    pub return_to: Option<String>,
    /// Issued-at — used to enforce the 10-minute TTL.
    pub created_at: Timestamp,
}

/// Session↔SP registration for SLO fan-out on the IdP side.
///
/// Written when Hearth (acting as IdP) issues a `<Response>` to an SP.
/// Looked up at logout time to find all SPs that share this session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSessionRegistration {
    /// The user session this registration belongs to.
    pub session_id: SessionId,
    /// The user behind the session.
    pub user_id: UserId,
    /// The SP the assertion was issued to.
    pub sp_key: String,
    /// The NameID emitted to the SP (for `<LogoutRequest>` construction).
    pub name_id: String,
    /// NameID format used.
    pub name_id_format: SamlNameIdFormat,
    /// Created timestamp.
    pub created_at: Timestamp,
}

/// In-flight logout state (tracks a LogoutRequest we sent or received).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlLogoutStateBag {
    /// Opaque token (also the storage key suffix).
    pub token: String,
    /// Logout request ID we issued (matched in `<LogoutResponse InResponseTo="…"/>`).
    pub request_id: String,
    /// Realm.
    pub realm_id: crate::core::RealmId,
    /// Whether we initiated as IdP (true) or as SP (false).
    pub initiated_as_idp: bool,
    /// Session we're logging out.
    pub session_id: Option<SessionId>,
    /// SP / IdP counterparty key.
    pub counterparty_key: String,
    /// Created timestamp.
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameid_format_roundtrip() {
        for f in [
            SamlNameIdFormat::EmailAddress,
            SamlNameIdFormat::Persistent,
            SamlNameIdFormat::Transient,
            SamlNameIdFormat::Unspecified,
        ] {
            assert_eq!(SamlNameIdFormat::from_uri(f.as_uri()), f);
        }
    }

    #[test]
    fn nameid_format_unknown_uri_defaults_unspecified() {
        assert_eq!(
            SamlNameIdFormat::from_uri("urn:nonsense"),
            SamlNameIdFormat::Unspecified
        );
    }
}

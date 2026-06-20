//! SAML-specific error type.
//!
//! Internal callers in the SAML module return `SamlError`; a `From` impl in
//! `identity::error` converts it to `IdentityError` at the boundary.

use std::fmt;

/// Errors from SAML XML parsing, signature verification, and assertion validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum SamlError {
    /// SAML XML parsing failed. Generic by design — never leaks parser
    /// internals (XXE vectors, entity expansion attempts) to the caller.
    Parse {
        /// Short sanitized description. Safe to log and return.
        reason: String,
    },
    /// SAML XML-DSIG signature verification failed. Covers:
    /// missing `<Signature>`, invalid digest, invalid signature value,
    /// wrong signing cert, signature-wrapping attack. Intentionally
    /// conflated — the caller MUST NOT learn which check failed.
    Signature,
    /// A SAML assertion's `NotBefore`/`NotOnOrAfter` bounds place it
    /// outside the clock-skew tolerance window.
    Expired,
    /// A SAML assertion with this ID has already been consumed for this
    /// IdP. Replay attack (or a confused client retrying a consumed
    /// assertion). Rejected.
    Replay,
    /// A SAML assertion's `AudienceRestriction` list does not include
    /// this SP's entity ID.
    AudienceMismatch,
    /// A SAML `<Response>` or `<LogoutRequest>` names an issuer that does
    /// not match the expected IdP / SP entity ID.
    IssuerMismatch,
    /// A SAML `<Response>` names a `Destination` that does not match this
    /// SP's ACS URL. Defense against cookie-less CSRF.
    DestinationMismatch,
    /// A SAML XML-DSIG element uses an algorithm not supported by Hearth
    /// (SHA-1 digests, RSA-SHA1 signatures, inclusive C14N). Algorithm
    /// downgrade is rejected by design.
    UnsupportedAlgorithm,
    /// Fetching SAML IdP metadata from the configured URL failed.
    MetadataFetch {
        /// Sanitized reason — never contains full URL or upstream body.
        reason: String,
    },
    /// A SAML `<AuthnRequest>` referenced an SP entity ID that is not
    /// registered for this realm.
    UnknownSp,
    /// A SAML callback referenced an IdP that is not registered for
    /// this realm.
    UnknownIdp,
    /// A SAML `<AuthnRequest>` failed validation (malformed, bad signature
    /// when required, missing required attributes).
    InvalidAuthnRequest {
        /// Short sanitized description.
        reason: String,
    },
}

impl SamlError {
    /// Short category string for error-page rendering (e.g. in `saml.rs` templates).
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::Parse { .. } => "parse",
            Self::Signature => "signature",
            Self::Expired => "expired",
            Self::Replay => "replay",
            Self::AudienceMismatch => "audience",
            Self::IssuerMismatch => "issuer",
            Self::DestinationMismatch => "destination",
            Self::UnsupportedAlgorithm => "algorithm",
            Self::MetadataFetch { .. } => "metadata_fetch",
            Self::UnknownSp => "unknown_sp",
            Self::UnknownIdp => "unknown_idp",
            Self::InvalidAuthnRequest { .. } => "invalid_authn_request",
        }
    }

    /// Returns the stable wire error code for this SAML error.
    #[must_use]
    pub fn wire_error_code(&self) -> Option<&'static str> {
        match self {
            Self::Parse { .. }
            | Self::Signature
            | Self::Expired
            | Self::Replay
            | Self::AudienceMismatch
            | Self::IssuerMismatch
            | Self::DestinationMismatch
            | Self::UnsupportedAlgorithm
            | Self::InvalidAuthnRequest { .. } => Some("HEARTH_SAML_INVALID"),
            Self::MetadataFetch { .. } => Some("HEARTH_SAML_METADATA_FETCH_FAILED"),
            Self::UnknownSp | Self::UnknownIdp => Some("HEARTH_SAML_ENTITY_NOT_FOUND"),
        }
    }
}

impl fmt::Display for SamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { reason } => write!(f, "SAML parse error: {reason}"),
            Self::Signature => write!(f, "SAML signature verification failed"),
            Self::Expired => write!(f, "SAML assertion expired or not yet valid"),
            Self::Replay => write!(f, "SAML assertion replay detected"),
            Self::AudienceMismatch => write!(f, "SAML audience mismatch"),
            Self::IssuerMismatch => write!(f, "SAML issuer mismatch"),
            Self::DestinationMismatch => write!(f, "SAML destination mismatch"),
            Self::UnsupportedAlgorithm => write!(f, "SAML unsupported algorithm"),
            Self::MetadataFetch { reason } => {
                write!(f, "SAML metadata fetch failed: {reason}")
            }
            Self::UnknownSp => write!(f, "unknown SAML service provider"),
            Self::UnknownIdp => write!(f, "unknown SAML identity provider"),
            Self::InvalidAuthnRequest { reason } => {
                write!(f, "invalid SAML AuthnRequest: {reason}")
            }
        }
    }
}

impl std::error::Error for SamlError {}

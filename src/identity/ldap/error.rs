//! Error types for the LDAP connector.

use std::fmt;

/// Errors originating from LDAP operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum LdapError {
    /// The LDAP URL is invalid or uses a disallowed scheme.
    InvalidUrl {
        /// Why the URL was rejected.
        reason: String,
    },
    /// A network or TLS error occurred while connecting to the LDAP server.
    ///
    /// Message is sanitized — never contains bind credentials.
    ConnectionFailed {
        /// Sanitized description (no credentials, no internal stack traces).
        reason: String,
    },
    /// The service-account bind failed (wrong DN or password).
    ///
    /// Intentionally vague — callers must not distinguish wrong-DN from
    /// wrong-password to avoid information leakage.
    BindFailed,
    /// A user password-bind authentication attempt failed.
    ///
    /// Covers: wrong password, account disabled, DN not found. Vague by design.
    AuthenticationFailed,
    /// The LDAP search operation returned an unexpected result code.
    SearchFailed {
        /// LDAP result code.
        result_code: u32,
        /// Short sanitized description.
        reason: String,
    },
    /// A required attribute was missing from an LDAP entry.
    MissingAttribute {
        /// Name of the missing attribute.
        attribute: String,
    },
    /// An attribute value could not be decoded as UTF-8.
    AttributeEncoding {
        /// Name of the attribute that failed to decode.
        attribute: String,
    },
    /// The LDAP filter string is syntactically invalid.
    InvalidFilter {
        /// The filter string that was rejected.
        filter: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The delta sync checkpoint stored in WAL is corrupt.
    CorruptCheckpoint {
        /// Description of the corruption.
        reason: String,
    },
    /// A storage engine error while reading or writing the sync checkpoint.
    Storage(Box<dyn std::error::Error + Send + Sync>),
    /// An internal connector error with no more specific variant.
    Internal {
        /// Sanitized description.
        reason: String,
    },
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { reason } => write!(f, "LDAP URL invalid: {reason}"),
            Self::ConnectionFailed { reason } => write!(f, "LDAP connection failed: {reason}"),
            Self::BindFailed => write!(f, "LDAP service-account bind failed"),
            Self::AuthenticationFailed => write!(f, "LDAP authentication failed"),
            Self::SearchFailed {
                result_code,
                reason,
            } => {
                write!(f, "LDAP search failed (rc={result_code}): {reason}")
            }
            Self::MissingAttribute { attribute } => {
                write!(f, "LDAP entry missing required attribute: {attribute}")
            }
            Self::AttributeEncoding { attribute } => {
                write!(f, "LDAP attribute '{attribute}' is not valid UTF-8")
            }
            Self::InvalidFilter { filter, reason } => {
                write!(f, "LDAP filter '{filter}' is invalid: {reason}")
            }
            Self::CorruptCheckpoint { reason } => {
                write!(f, "LDAP sync checkpoint is corrupt: {reason}")
            }
            Self::Storage(err) => write!(f, "LDAP storage error: {err}"),
            Self::Internal { reason } => write!(f, "LDAP internal error: {reason}"),
        }
    }
}

impl std::error::Error for LdapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_invalid_url() {
        let e = LdapError::InvalidUrl {
            reason: "scheme must be ldaps://".to_string(),
        };
        assert!(format!("{e}").contains("LDAP URL invalid"));
        assert!(format!("{e}").contains("ldaps://"));
    }

    #[test]
    fn display_connection_failed() {
        let e = LdapError::ConnectionFailed {
            reason: "TLS handshake timed out".to_string(),
        };
        assert!(format!("{e}").contains("connection failed"));
        assert!(format!("{e}").contains("TLS handshake timed out"));
    }

    #[test]
    fn display_bind_failed() {
        let e = LdapError::BindFailed;
        assert!(format!("{e}").contains("bind failed"));
    }

    #[test]
    fn display_authentication_failed() {
        let e = LdapError::AuthenticationFailed;
        assert!(format!("{e}").contains("authentication failed"));
    }

    #[test]
    fn display_search_failed() {
        let e = LdapError::SearchFailed {
            result_code: 32,
            reason: "no such object".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("LDAP search failed"));
        assert!(s.contains("32"));
    }

    #[test]
    fn display_missing_attribute() {
        let e = LdapError::MissingAttribute {
            attribute: "mail".to_string(),
        };
        assert!(format!("{e}").contains("mail"));
    }

    #[test]
    fn display_invalid_filter() {
        let e = LdapError::InvalidFilter {
            filter: "(objectClass=".to_string(),
            reason: "unclosed parenthesis".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("filter"));
        assert!(s.contains("unclosed"));
    }

    #[test]
    fn storage_variant_has_source() {
        let io = std::io::Error::other("disk full");
        let e = LdapError::Storage(Box::new(io));
        assert!(e.source().is_some());
    }

    #[test]
    fn other_variants_have_no_source() {
        assert!(LdapError::BindFailed.source().is_none());
        assert!(LdapError::AuthenticationFailed.source().is_none());
    }
}

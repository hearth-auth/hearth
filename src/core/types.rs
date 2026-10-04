//! Entity ID newtypes for type-safe identification.
//!
//! Each ID type wraps a UUID and provides a prefixed Display format.
//! No `Deref` to inner type — access via `.as_uuid()` only.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Outcome of importing a single record during a backup restore.
///
/// Distinguishes the three ways a per-record import can resolve so the restore
/// report can surface accurate per-member counts (rather than a boolean). Used
/// by the backup importer and the engine `import_*` methods it drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    /// The record did not exist and was written.
    Created,
    /// The record already existed and was left untouched (Skip / Merge mode).
    Skipped,
    /// The record already existed and was replaced (Overwrite mode).
    Overwritten,
}

/// Generates a newtype ID wrapper around `Uuid` with consistent behavior.
///
/// Each generated type gets:
/// - `new(Uuid)` and `generate()` constructors
/// - `as_uuid()` accessor (no `Deref`)
/// - Prefixed `Display` implementation
/// - Standard derives: `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`
macro_rules! define_id_type {
    (
        $(#[$meta:meta])*
        $name:ident, $prefix:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new ID from an existing UUID.
            pub fn new(id: Uuid) -> Self {
                Self(id)
            }

            /// Generates a new random ID.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns a reference to the inner UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid_part = s.strip_prefix($prefix).unwrap_or(s);
                Uuid::parse_str(uuid_part).map(Self)
            }
        }
    };
}

define_id_type!(
    /// Unique identifier for a realm. All storage operations require this.
    RealmId, "realm_"
);

define_id_type!(
    /// Unique identifier for a user within a realm.
    UserId, "user_"
);

define_id_type!(
    /// Unique identifier for an authentication session.
    SessionId, "session_"
);

define_id_type!(
    /// Unique identifier for an OAuth 2.0 client registration.
    ClientId, "client_"
);

define_id_type!(
    /// Unique identifier for an audit log event.
    AuditEventId, "audit_"
);

define_id_type!(
    /// Unique identifier for an organization within a realm.
    OrganizationId, "org_"
);

define_id_type!(
    /// Unique identifier for an organization invitation.
    InvitationId, "inv_"
);

define_id_type!(
    /// Unique identifier for an external Identity Provider (IdP) connector
    /// registered against a realm for social login / federated sign-in.
    ///
    /// Scoped to a single realm via the containing `RealmId`; the same
    /// `IdpId` value would not appear across realms in practice because
    /// each `register_idp` call generates a fresh UUID.
    IdpId, "idp_"
);

define_id_type!(
    /// Unique identifier for a webhook subscription within a realm.
    WebhookId, "wh_"
);

define_id_type!(
    /// Unique identifier for an autonomous agent registered within a realm.
    ///
    /// Agents are distinct from users and OAuth clients — they are autonomous
    /// actors with their own identity lifecycle, credential set, and delegation
    /// chain support. See `openspec/specs/agent-identity/spec.md` for the full specification.
    AgentId, "agt_"
);

define_id_type!(
    /// Unique identifier for a single agent credential (API key, Ed25519 key, or mTLS cert).
    ///
    /// Scoped to a specific agent; the same `AgentCredentialId` does not appear
    /// across agents.
    AgentCredentialId, "acred_"
);

define_id_type!(
    /// Unique identifier for a single webhook delivery attempt.
    WebhookDeliveryId, "whd_"
);

define_id_type!(
    /// Unique identifier for a protected resource (MCP server) registered in a realm.
    ///
    /// Used as the primary key for protected resource records. See openspec/specs/mcp-authorization/spec.md
    /// and RFC 9728 for the Protected Resource Metadata discovery specification.
    ResourceServerId, "rs_"
);

/// Validated RFC 8707 resource indicator, held in its one canonical form.
///
/// Construction (and deserialization) validates and canonicalizes, so every
/// `Uri` compares canonical-to-canonical and every spelling of one resource is
/// the same value. The rule (RFC 3986 §6.2.2 syntax- and §6.2.3
/// scheme-based normalization, restricted to what is unambiguous):
///
/// - surrounding whitespace is trimmed;
/// - it must be absolute (`scheme://authority...`), with a non-empty scheme
///   and host, no userinfo and no fragment;
/// - scheme and authority are lowercased; path and query keep their case;
/// - the scheme's default port is dropped (`:443` for `https`, `:80` for
///   `http`);
/// - trailing slashes are dropped from the path, so the root is the bare
///   authority (`https://api.example.com`) and `/v1/` is `/v1`;
/// - the query is kept verbatim (two URIs differing only by query are
///   different resources).
///
/// This is the form stored in the protected-resource registry, hashed for
/// RBAC's resource scope keys, and minted into `aud`.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Uri(String);

/// Error returned when a URI fails validation.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum UriError {
    #[error("invalid resource URI: {0}")]
    InvalidUri(String),
}

impl Uri {
    /// The canonical URI string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SHA-256 first 12 hex characters of the canonical form.
    pub(crate) fn storage_hash(&self) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        hex::encode(&digest[..6])
    }

    /// Canonicalizes `raw` per the type-level rule, or `None` when it is not
    /// a valid resource indicator.
    fn canonicalize(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.contains('#') {
            return None;
        }
        let (scheme, rest) = trimmed.split_once("://")?;
        let mut scheme_chars = scheme.chars();
        let scheme_ok = scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if !scheme_ok {
            return None;
        }
        let scheme = scheme.to_ascii_lowercase();
        let (hier, query) = match rest.split_once('?') {
            Some((hier, query)) => (hier, Some(query)),
            None => (rest, None),
        };
        let (authority, path) = match hier.find('/') {
            Some(pos) => hier.split_at(pos),
            None => (hier, ""),
        };
        if authority.contains('@') {
            return None;
        }
        let mut authority = authority.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => Some(":443"),
            "http" => Some(":80"),
            _ => None,
        };
        if let Some(port) = default_port {
            if let Some(stripped) = authority.strip_suffix(port) {
                authority.truncate(stripped.len());
            }
        }
        if let Some(stripped) = authority.strip_suffix(':') {
            authority.truncate(stripped.len());
        }
        if authority.is_empty() {
            return None;
        }
        let path = path.trim_end_matches('/');
        let mut out = format!("{scheme}://{authority}{path}");
        if let Some(query) = query.filter(|q| !q.is_empty()) {
            out.push('?');
            out.push_str(query);
        }
        Some(out)
    }
}

impl TryFrom<String> for Uri {
    type Error = UriError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match Self::canonicalize(&s) {
            Some(canonical) => Ok(Self(canonical)),
            None => Err(UriError::InvalidUri(s)),
        }
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn realm_id_creation_and_accessor() {
        let uuid = Uuid::new_v4();
        let id = RealmId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn realm_id_equality_and_hashing() {
        let uuid = Uuid::new_v4();
        let id1 = RealmId::new(uuid);
        let id2 = RealmId::new(uuid);
        assert_eq!(id1, id2);

        let mut set = HashSet::new();
        set.insert(id1.clone());
        assert!(set.contains(&id2));

        let other = RealmId::generate();
        assert!(!set.contains(&other));
    }

    #[test]
    fn realm_id_display_shows_prefix() {
        let id = RealmId::generate();
        let display = format!("{id}");
        assert!(display.starts_with("realm_"), "got: {display}");
    }

    #[test]
    fn realm_id_serde_round_trip() {
        let id = RealmId::generate();
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: RealmId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn user_id_basics() {
        let uuid = Uuid::new_v4();
        let id = UserId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("user_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: UserId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn session_id_basics() {
        let uuid = Uuid::new_v4();
        let id = SessionId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("session_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: SessionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn organization_id_basics() {
        let uuid = Uuid::new_v4();
        let id = OrganizationId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("org_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: OrganizationId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn invitation_id_basics() {
        let uuid = Uuid::new_v4();
        let id = InvitationId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("inv_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: InvitationId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn idp_id_basics() {
        let uuid = Uuid::new_v4();
        let id = IdpId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("idp_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: IdpId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn idp_id_generate_is_unique() {
        let id1 = IdpId::generate();
        let id2 = IdpId::generate();
        assert_ne!(id1, id2);
    }

    // ===== Uri tests =====

    #[test]
    fn uri_valid_construction() {
        let uri = Uri::try_from("https://api.example.com/resource".to_string())
            .expect("valid URI should parse");
        assert_eq!(uri.as_str(), "https://api.example.com/resource");
    }

    #[test]
    fn uri_rejects_empty() {
        assert!(Uri::try_from("".to_string()).is_err());
    }

    #[test]
    fn uri_rejects_relative() {
        assert!(Uri::try_from("/relative/path".to_string()).is_err());
    }

    #[test]
    fn uri_rejects_fragment() {
        assert!(Uri::try_from("https://api.example.com#admin".to_string()).is_err());
    }

    /// One canonical form for every resource indicator (RFC 3986 §6.2.2 /
    /// §6.2.3): scheme and host lowercased, the scheme's default port
    /// dropped, no trailing slash, path case and query kept. Both the
    /// token-exchange allowlist and RBAC's resource scope lookup compare this
    /// form, so every spelling of one URI behaves identically.
    #[test]
    fn uri_is_canonical_at_construction() {
        for (raw, canonical) in [
            (
                "HTTPS://API.Example.COM/Path",
                "https://api.example.com/Path",
            ),
            (
                "https://api.example.com:443/data",
                "https://api.example.com/data",
            ),
            (
                "http://api.example.com:80/data",
                "http://api.example.com/data",
            ),
            (
                "http://api.example.com:443/data",
                "http://api.example.com:443/data",
            ),
            (
                "https://api.example.com:80/data",
                "https://api.example.com:80/data",
            ),
            ("https://api.example.com/v1/", "https://api.example.com/v1"),
            ("https://api.example.com/", "https://api.example.com"),
            ("https://api.example.com", "https://api.example.com"),
            (
                "https://api.example.com/MyFiles",
                "https://api.example.com/MyFiles",
            ),
            (
                "https://Api.Example.com/v1/?b=2&a=1",
                "https://api.example.com/v1?b=2&a=1",
            ),
            ("  https://api.example.com/x  ", "https://api.example.com/x"),
        ] {
            let uri = Uri::try_from(raw.to_string()).expect("valid URI");
            assert_eq!(uri.as_str(), canonical, "{raw:?}");
        }
    }

    #[test]
    fn uri_spelling_variants_share_a_storage_hash_and_a_query_does_not() {
        let hash = |s: &str| Uri::try_from(s.to_string()).expect("valid").storage_hash();
        assert_eq!(
            hash("https://api.example.com/v1"),
            hash("HTTPS://API.EXAMPLE.COM:443/v1/")
        );
        assert_ne!(
            hash("https://api.example.com/v1?tenant=a"),
            hash("https://api.example.com/v1?tenant=b")
        );
        assert_ne!(
            hash("https://api.example.com/v1"),
            hash("http://api.example.com/v1")
        );
    }

    #[test]
    fn uri_rejects_missing_scheme_host_or_userinfo() {
        for bad in [
            "://api.example.com",
            "https://",
            "https:///path",
            "https://user@api.example.com",
        ] {
            assert!(Uri::try_from(bad.to_string()).is_err(), "{bad:?}");
        }
    }

    /// A stored URI re-canonicalizes on load, so a value persisted in another
    /// spelling cannot defeat a canonical comparison.
    #[test]
    fn uri_deserialize_canonicalizes_and_validates() {
        let uri: Uri = serde_json::from_str("\"HTTPS://API.example.com:443/\"").expect("valid");
        assert_eq!(uri.as_str(), "https://api.example.com");
        assert!(serde_json::from_str::<Uri>("\"/relative\"").is_err());
    }

    #[test]
    fn uri_storage_hash_is_stable() {
        let uri = Uri::try_from("https://api.example.com/data".to_string()).expect("valid URI");
        let hash1 = uri.storage_hash();
        let hash2 = uri.storage_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 12);
    }

    #[test]
    fn uri_serde_round_trip() {
        let uri = Uri::try_from("https://api.example.com".to_string()).expect("valid URI");
        let json = serde_json::to_string(&uri).expect("serialize");
        let deserialized: Uri = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(uri, deserialized);
    }
}

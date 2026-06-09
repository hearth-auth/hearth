//! Domain types for the LDAP connector.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// LDAP attribute-to-Hearth-field mapping configuration.
///
/// Each field specifies which LDAP attribute name maps to that Hearth `User`
/// property. Defaults match common Active Directory / `inetOrgPerson` schemas.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LdapAttributeMap {
    /// Attribute containing the user's primary email address.
    /// Defaults to `"mail"`.
    pub email: String,
    /// Attribute containing the display name.
    /// Defaults to `"cn"` (common name).
    pub display_name: String,
    /// Attribute containing the given (first) name.
    /// Defaults to `"givenName"`.
    pub given_name: String,
    /// Attribute containing the family (last) name.
    /// Defaults to `"sn"` (surname).
    pub family_name: String,
    /// Attribute used as the unique external identifier for the user within
    /// the directory. For Active Directory this is typically `objectGUID`;
    /// for generic LDAP use `entryUUID`.
    /// Defaults to `"entryUUID"`.
    pub external_id: String,
    /// Attribute containing the login name / username.
    /// Defaults to `"uid"`; for AD use `"sAMAccountName"`.
    pub username: String,
    /// Attribute used for delta sync.
    ///
    /// For Active Directory: `"uSNChanged"` (numeric, monotonically increasing).
    /// For generic LDAP (RFC 3673): `"modifyTimestamp"` (generalized-time string).
    /// Defaults to `"modifyTimestamp"`.
    pub sync_attribute: String,
    /// Additional LDAP attributes to pass through as Hearth user `attributes`.
    ///
    /// Each entry maps LDAP attribute name → Hearth attribute key.
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl Default for LdapAttributeMap {
    fn default() -> Self {
        Self {
            email: "mail".to_string(),
            display_name: "cn".to_string(),
            given_name: "givenName".to_string(),
            family_name: "sn".to_string(),
            external_id: "entryUUID".to_string(),
            username: "uid".to_string(),
            sync_attribute: "modifyTimestamp".to_string(),
            extra: HashMap::new(),
        }
    }
}

/// Delta-sync strategy, driven by the directory's change-tracking attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyncStrategy {
    /// Poll `modifyTimestamp` (RFC 3672 generalised-time string).
    ///
    /// Suitable for any RFC 4519-compliant LDAPv3 directory.
    #[default]
    ModifyTimestamp,
    /// Poll `uSNChanged` (unsigned integer, Active Directory–only).
    ///
    /// Supports more granular incremental sync on AD but is not portable
    /// to other directories.
    UsnChanged,
}

/// LDAP connector configuration.
///
/// Bound to a Hearth realm — all sync'd users land in that realm.
/// Corresponds to `hearth.yaml` block: `ldap.` or per-realm `realms.<name>.ldap.`.
#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    /// Connection URL. **MUST** start with `ldaps://` in production.
    ///
    /// `ldap://` is only accepted when `allow_insecure = true` (test
    /// environments only). The connector rejects non-LDAPS URLs at
    /// construction time.
    pub url: String,

    /// Allow plain `ldap://` connections (default: `false`).
    ///
    /// Set `allow_insecure = true` only in test environments controlled
    /// by `hearth.yaml`. Must never be `true` in production deployments.
    #[serde(default)]
    pub allow_insecure: bool,

    /// Service-account bind DN.
    /// Example: `"cn=hearth,ou=serviceaccounts,dc=example,dc=com"`.
    pub bind_dn: String,

    /// Service-account password, zeroized on drop.
    pub bind_password: LdapBindPassword,

    /// Search base DN.
    /// Example: `"ou=users,dc=example,dc=com"`.
    pub base_dn: String,

    /// LDAP search filter for user objects.
    ///
    /// The filter MUST be syntactically valid per RFC 4515.
    /// Defaults to `"(objectClass=person)"`.
    #[serde(default = "LdapConfig::default_user_filter")]
    pub user_filter: String,

    /// Maximum number of entries per Simple Paged Results page.
    ///
    /// 0 disables paging (returns all results in one response).
    /// Defaults to 500.
    #[serde(default = "LdapConfig::default_page_size")]
    pub page_size: u32,

    /// Attribute mapping configuration.
    #[serde(default)]
    pub attribute_map: LdapAttributeMap,

    /// Delta sync strategy.
    #[serde(default)]
    pub sync_strategy: SyncStrategy,

    /// How often (in seconds) to poll for delta changes.
    ///
    /// Defaults to 300 (5 minutes).
    #[serde(default = "LdapConfig::default_sync_interval_secs")]
    pub sync_interval_secs: u64,
}

impl LdapConfig {
    fn default_user_filter() -> String {
        "(objectClass=person)".to_string()
    }

    fn default_page_size() -> u32 {
        500
    }

    fn default_sync_interval_secs() -> u64 {
        300
    }
}

/// Bind password wrapper — zeroized on drop, never logs or serializes contents.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Deserialize)]
pub struct LdapBindPassword(pub String);

impl std::fmt::Debug for LdapBindPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LdapBindPassword([REDACTED])")
    }
}

impl LdapBindPassword {
    /// Returns the raw password value for use in LDAP bind calls.
    ///
    /// Callers MUST NOT log, cache, or copy this value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A user entry returned from LDAP search or attribute mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUser {
    /// Full distinguished name of the LDAP entry.
    pub dn: String,
    /// Value of the `external_id` attribute (e.g., `entryUUID` or `objectGUID`).
    pub external_id: String,
    /// Email address.
    pub email: String,
    /// Display name.
    pub display_name: String,
    /// Given name.
    pub given_name: Option<String>,
    /// Family name.
    pub family_name: Option<String>,
    /// Login name.
    pub username: Option<String>,
    /// Value of the sync attribute for delta tracking (`modifyTimestamp` or `uSNChanged`).
    pub sync_cursor: String,
    /// Extra attributes mapped to Hearth user `attributes` keys.
    pub extra: HashMap<String, String>,
}

/// Stored delta-sync checkpoint for a realm.
///
/// Persisted under key `ldap:cp:{realm_uuid}` in WAL storage.
/// Tracks the high-watermark sync cursor so only entries modified since the
/// last successful sync are fetched on the next run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LdapSyncCheckpoint {
    /// The last seen sync cursor value (ISO-8601 timestamp for
    /// `modifyTimestamp`; decimal integer string for `uSNChanged`).
    ///
    /// `None` indicates no sync has completed — triggers a full initial load.
    pub cursor: Option<String>,
    /// Unix timestamp of the last successful sync run.
    pub last_sync_at: Option<u64>,
    /// Count of users upserted in the last sync run.
    pub last_sync_count: u64,
}

/// Result of a delta sync run.
#[derive(Debug, Clone)]
pub struct DeltaSyncResult {
    /// Users that were inserted or updated in Hearth.
    pub upserted: Vec<LdapUser>,
    /// Number of entries skipped (mapping failures, filtered out, etc.).
    pub skipped: u64,
    /// The new checkpoint after this run.
    pub checkpoint: LdapSyncCheckpoint,
}

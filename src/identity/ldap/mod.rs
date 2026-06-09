//! LDAP / Active Directory user federation connector.
//!
//! Provides user-search, password-bind authentication, attribute mapping,
//! and delta sync for LDAP directories.
//!
//! # Modules
//!
//! - [`connector`] — [`EmbeddedLdapConnector`], the concrete implementation
//! - [`error`] — [`LdapError`] enum
//! - [`filter`] — RFC 4515-safe filter builders
//! - [`keys`] — storage key encoding for checkpoints
//! - [`mapping`] — attribute → [`LdapUser`] mapping
//! - [`types`] — config + domain types
//!
//! # Security notes
//!
//! - **LDAPS required** in production. The connector rejects plain `ldap://`
//!   URLs at construction time unless `allow_insecure = true` is explicitly
//!   set in config (intended for CI environments only).
//! - **Bind password** is wrapped in [`types::LdapBindPassword`], a
//!   `Zeroize`-on-drop newtype that never implements `Debug`, `Display`,
//!   or `Serialize` in ways that reveal its contents.
//! - **Password-bind authentication** passes the user credential directly to
//!   the LDAP server as a plain bind; the credential is never cached,
//!   stored, or logged by Hearth.
//! - **Filter injection** is prevented by [`filter::escape_assertion_value`],
//!   which RFC 4515-escapes special characters in any user-controlled input
//!   embedded in search filters.

pub mod connector;
pub mod error;
pub(crate) mod filter;
pub(crate) mod keys;
pub(crate) mod mapping;
pub mod types;

pub use connector::EmbeddedLdapConnector;
pub use error::LdapError;
pub use types::{
    DeltaSyncResult, LdapAttributeMap, LdapBindPassword, LdapConfig, LdapSyncCheckpoint, LdapUser,
    SyncStrategy,
};

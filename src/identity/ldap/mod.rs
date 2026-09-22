//! LDAP / Active Directory user federation connector.
//!
//! Provides user-search, password-bind authentication, attribute mapping,
//! and delta sync for LDAP directories.
//!
//! # Status: NOT operator-reachable (task 26.6 / finding L-1)
//!
//! **Nothing in a running Hearth server calls this module.** The only
//! reference to it anywhere outside `src/identity/ldap/` is the `pub mod ldap;`
//! declaration at `src/identity/mod.rs:22` — measured at HEAD, and it is
//! exactly one. There is no `ldap:` block in `hearth.yaml` (`LdapConfig` is
//! not reachable from `src/config/`), no admin API route, no gRPC RPC, no CLI
//! subcommand and no background task. `EmbeddedLdapConnector::new`,
//! `search_users`, `authenticate_user` and `delta_sync` have no callers except
//! this module's own tests and `tests/ldap_federation.rs`.
//!
//! The connector itself is complete and is exercised against a real OpenLDAP
//! container by the `ldap-integration` CI job, so this is an *unshipped
//! feature*, not dead code. `docs/STATUS.md` claimed it was shipped; that row
//! now reads "⚠️ Not operator-reachable", and
//! `docs/specs/READINESS_AUDIT_1_0.md` § C-2 lists the four wiring steps.
//!
//! Two consequences worth stating where a reader will see them:
//!
//! 1. Every security property documented below is **latent**. It is asserted
//!    by tests, not by a deployment. Wiring this module up turns each of them
//!    from latent into live, so findings L-3 through L-5 were closed first.
//! 2. `ldap3` and its rustls/ring stack are linked into every production
//!    binary to serve code no deployment can call. Gating the module behind a
//!    cargo feature would remove that, and is a change to `Cargo.toml` and
//!    `src/identity/mod.rs` rather than to this module.
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
//! - **Filter injection** is prevented by three different guards, because
//!   three different kinds of string reach a search filter and escaping is
//!   correct for only one of them (task 26.7 / finding L-4 — the previous
//!   wording here claimed `escape_assertion_value` covered "any
//!   user-controlled input", while the values actually concatenated into the
//!   filter skeleton were not checked at all):
//!   - *Assertion values* — [`filter::escape_assertion_value`] RFC 4515-escapes
//!     them. The one such value in the module is the delta-sync cursor, and it
//!     is **not** a Hearth-authored string: it is the directory's own
//!     `modifyTimestamp` / `uSNChanged` value, read out of a search response
//!     by [`mapping::map_entry`], persisted to the checkpoint, and then
//!     concatenated back into the next query. Escaping it is load-bearing.
//!   - *Attribute descriptors* (`external_id`, `sync_attribute`, and every
//!     other name in [`types::LdapAttributeMap`]) —
//!     [`filter::validate_attribute_descriptor`] requires RFC 4512 § 2.5 form.
//!     Escaping them would be wrong: an escaped descriptor names no attribute
//!     and yields a silent empty result instead of a refusal.
//!   - *The configured `user_filter`* — [`filter::validate_user_filter`]
//!     requires one balanced, parenthesised RFC 4515 expression, so a fragment
//!     cannot close the `(&…)` it is embedded in and append a clause. It is a
//!     filter fragment, so it cannot be escaped at all.
//!
//!   Both validators run at the configuration edge
//!   ([`EmbeddedLdapConnector::new`]) *and* at the sink (the three builders in
//!   [`filter`]), because [`types::LdapConfig`] has public fields and can be
//!   assembled without the constructor.
//! - **Distinguished names** (`base_dn`, `bind_dn`, a user's DN) are never
//!   concatenated into a filter. `ldap3` sends them as BER-encoded protocol
//!   parameters, so there is no string-injection sink to guard; what they need
//!   instead is provenance, which
//!   [`EmbeddedLdapConnector::authenticate_user`] documents as a hard
//!   requirement.

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

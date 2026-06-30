//! Migration and credential import types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::core::{RealmId, UserId};

use super::user::UserStatus;

/// A credential record exported from a realm for backup purposes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialExport {
    /// The user this credential belongs to.
    pub user_id: UserId,
    /// PHC-formatted hash string (e.g. `$argon2id$...`).
    pub phc_string: String,
    /// Creation timestamp in Unix microseconds.
    pub created_at_micros: i64,
}

/// A pre-hashed credential to attach to an imported user.
///
/// Unlike `CreateUserRequest` + `set_password`, imports preserve the
/// source system's hash verbatim so users can authenticate with their
/// existing passwords. New hashes (via `change_password` or `set_password`)
/// are always Argon2id; successful verification against a legacy hash
/// auto-upgrades it in place.
#[derive(Clone, Debug)]
pub struct RawCredential {
    /// The PHC-formatted hash string (e.g. `$pbkdf2-sha256$i=27500$salt$hash`).
    pub phc_string: String,
    /// Unix-microseconds timestamp of original credential creation, if known.
    pub created_at_micros: Option<i64>,
}

/// Request to import a user from an external identity provider.
///
/// `id` allows preserving the source system's user ID so that in-flight
/// tokens and application-level references remain valid; leave `None`
/// to let the engine generate a fresh `UserId`. `credential` may be
/// `None` — e.g. for users whose source hash used an unsupported KDF.
#[derive(Clone, Debug)]
pub struct ImportUserRequest {
    /// Preserved source-system UUID, or `None` to generate a new one.
    pub id: Option<UserId>,
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized). If empty, the
    /// engine synthesizes `"{first_name} {last_name}"`.
    pub display_name: String,
    /// User's first (given) name. Empty string allowed.
    pub first_name: String,
    /// User's last (family) name. Empty string allowed.
    pub last_name: String,
    /// Account status.
    pub status: UserStatus,
    /// Pre-hashed credential. `None` imports the user with no password.
    pub credential: Option<RawCredential>,
    /// Custom attribute key-value pairs.
    pub attributes: BTreeMap<String, String>,
}

/// Request to import an OAuth 2.0 client from an external provider.
///
/// Unlike `RegisterClientRequest`, this allows preserving the client's
/// source-system identifier. The secret (if any) is hashed with Argon2id
/// at import time — the source system's hashed secret is not reusable
/// because Hearth's storage format requires Argon2id.
#[derive(Clone, Debug)]
pub struct ImportClientRequest {
    /// Preserved source-system client UUID, or `None` to generate.
    pub id: Option<crate::core::ClientId>,
    /// Display name.
    pub client_name: String,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Plaintext client secret — hashed with Argon2id before storage.
    /// `None` creates a public client.
    pub client_secret: Option<String>,
    /// Allowed OAuth 2.0 grant types (defaults to `authorization_code`).
    pub grant_types: Vec<String>,
    /// Stable client slug.
    pub slug: Option<String>,
    /// Client trust posture.
    pub trust_level: crate::identity::ClientTrustLevel,
    /// Declared scope allowlist.
    pub declared_scopes: Vec<String>,
    /// Whether a realm-level consent spans org contexts.
    pub consent_spans_orgs: bool,
}

/// Parameters for the large-scale demo seeder ([`IdentityEngine::seed_demo_users`]).
///
/// Drives generation of synthetic accounts named
/// `user0000001@<email_domain>`, `user0000002@<email_domain>`, …. The shared
/// password is supplied separately (as a `CleartextPassword`) so it can be
/// hashed once and reused for every account.
///
/// [`IdentityEngine::seed_demo_users`]: crate::identity::IdentityEngine::seed_demo_users
#[derive(Clone, Debug)]
pub struct DemoSeedSpec {
    /// Target total number of seeded users for the realm. The seeder creates
    /// only the users above the realm's recorded sentinel count.
    pub target_count: u64,
    /// Email domain for generated addresses. Should be lowercase.
    pub email_domain: String,
    /// Display-name prefix; the user index is appended (e.g. `"Demo User 42"`).
    pub display_name_prefix: String,
    /// Whether generated accounts are pre-verified (and thus immediately able
    /// to authenticate without an email-verification step).
    pub email_verified: bool,
}

/// Outcome of a [`IdentityEngine::seed_demo_users`] call.
///
/// [`IdentityEngine::seed_demo_users`]: crate::identity::IdentityEngine::seed_demo_users
#[derive(Clone, Debug, Default)]
pub struct DemoSeedOutcome {
    /// Number of users created by this call (the delta above the prior count).
    pub created: u64,
    /// Total seeded users for the realm after this call.
    pub total: u64,
    /// `true` when the realm was already at (or above) the target and nothing
    /// was created.
    pub skipped: bool,
}

/// Summary returned by a successful migration.
///
/// Counts reflect what was actually written. `warnings` contains
/// human-readable notes about partial imports (e.g. users whose credential
/// used an unsupported KDF and was skipped).
#[derive(Clone, Debug, Default)]
pub struct MigrationReport {
    /// ID of the realm the migrated realm was imported into.
    pub realm_id: Option<RealmId>,
    /// Number of users written.
    pub users_imported: usize,
    /// Number of users whose credentials could not be imported
    /// (the user record itself was still created).
    pub users_with_skipped_credentials: usize,
    /// Number of OAuth clients written.
    pub clients_imported: usize,
    /// Number of RBAC role assignments written.
    pub role_assignments_written: usize,
    /// Non-fatal issues encountered during the import.
    pub warnings: Vec<String>,
}

//! The JSON seed-handle (HEA-1789).
//!
//! After seeding, the harness persists a handle describing the live corpus so
//! Goose users can draw from real realm/user/token IDs. The handle inherently
//! contains **live bearer tokens** (a validate-token journey against a
//! fabricated token only measures the reject path), so it is treated as a
//! secret:
//!
//! * [`SeededToken`] does not derive `Debug`/`Display` that reveals the token;
//!   the manual `Debug` impl redacts it.
//! * The admin bootstrap token and seeded passwords are **never** stored here.
//! * [`SeedHandle::write_to`] writes with `0600` permissions.
//!
//! See the README security section before pointing this at anything but a
//! loopback dev instance.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::params::SeedParams;

/// A live access token minted for the load run.
#[derive(Clone, Serialize, Deserialize)]
pub struct SeededToken {
    /// The user this token authenticates as.
    pub user_email: String,
    /// The live access token. SECRET — redacted in `Debug`.
    pub access_token: String,
    /// Whether this token was pre-revoked during seeding.
    pub revoked: bool,
}

// Manual Debug so a `{:?}` of the handle (e.g. in an error or a panic) never
// spills a live bearer token into logs.
impl std::fmt::Debug for SeededToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeededToken")
            .field("user_email", &self.user_email)
            .field("access_token", &"<redacted>")
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// One seeded user record (no credential material).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededUser {
    /// Server-assigned user ID.
    pub id: String,
    /// Deterministic email used to create the user.
    pub email: String,
}

/// One seeded realm and everything created under it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededRealm {
    /// Realm ID (UUID string).
    pub realm_id: String,
    /// OAuth client registered for the ROPC/revoke journeys (public client).
    pub client_id: String,
    /// User records created in this realm.
    pub users: Vec<SeededUser>,
    /// Live access tokens minted in this realm (a fraction pre-revoked).
    pub tokens: Vec<SeededToken>,
}

/// The persisted seed-handle. Serialized as JSON to `--seed-out`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeedHandle {
    /// Base URL the corpus was seeded against.
    pub target_host: String,
    /// Deterministic seed used to derive the corpus.
    pub seed: u64,
    /// Human-readable dataset shape (mirrors the report header).
    pub dataset_shape: String,
    /// Seeded realms.
    pub realms: Vec<SeededRealm>,
}

impl SeedHandle {
    /// Creates an empty handle stamped with the run's parameters.
    #[must_use]
    pub fn new(params: &SeedParams) -> Self {
        Self {
            target_host: params.target_host.clone(),
            seed: params.seed,
            dataset_shape: params.dataset_shape_summary(),
            realms: Vec::new(),
        }
    }

    /// Total live tokens across all realms.
    #[must_use]
    pub fn total_tokens(&self) -> usize {
        self.realms.iter().map(|r| r.tokens.len()).sum()
    }

    /// Total revoked tokens across all realms.
    #[must_use]
    pub fn total_revoked(&self) -> usize {
        self.realms
            .iter()
            .flat_map(|r| &r.tokens)
            .filter(|t| t.revoked)
            .count()
    }

    /// Serializes the handle to pretty JSON.
    ///
    /// # Errors
    /// Propagates any `serde_json` serialization error.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Writes the handle to `path` as JSON with `0600` permissions.
    ///
    /// The file contains live tokens, so it is created owner-read/write only.
    /// Any existing file is truncated.
    ///
    /// # Errors
    /// Returns an `io::Error` on directory-creation, write, or permission
    /// failure, or wraps a serialization error as [`io::ErrorKind::InvalidData`].
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = self
            .to_json()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)?;
        restrict_permissions(path)?;
        Ok(())
    }
}

/// Sets `0600` on the handle file (owner read/write only). No-op on non-Unix.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_handle() -> SeedHandle {
        SeedHandle {
            target_host: "http://127.0.0.1:8420".into(),
            seed: 1,
            dataset_shape: "realms=1 users/realm=2".into(),
            realms: vec![SeededRealm {
                realm_id: "realm-uuid".into(),
                client_id: "client-uuid".into(),
                users: vec![SeededUser {
                    id: "user-uuid".into(),
                    email: "loaduser@loadtest.test".into(),
                }],
                tokens: vec![
                    SeededToken {
                        user_email: "loaduser@loadtest.test".into(),
                        access_token: "SUPER-SECRET-TOKEN".into(),
                        revoked: false,
                    },
                    SeededToken {
                        user_email: "loaduser@loadtest.test".into(),
                        access_token: "ANOTHER-SECRET".into(),
                        revoked: true,
                    },
                ],
            }],
        }
    }

    #[test]
    fn token_debug_redacts_the_secret() {
        let t = SeededToken {
            user_email: "u@loadtest.test".into(),
            access_token: "SUPER-SECRET-TOKEN".into(),
            revoked: false,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(
            !dbg.contains("SUPER-SECRET-TOKEN"),
            "Debug must not reveal the token: {dbg}"
        );
    }

    #[test]
    fn handle_debug_does_not_leak_tokens() {
        let dbg = format!("{:?}", sample_handle());
        assert!(!dbg.contains("SUPER-SECRET-TOKEN"));
        assert!(!dbg.contains("ANOTHER-SECRET"));
    }

    #[test]
    fn json_roundtrips_and_counts_are_correct() {
        let h = sample_handle();
        assert_eq!(h.total_tokens(), 2);
        assert_eq!(h.total_revoked(), 1);
        let json = h.to_json().expect("serialize");
        let back: SeedHandle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.total_tokens(), 2);
        assert_eq!(back.realms[0].realm_id, "realm-uuid");
        // The JSON form intentionally carries the live token (Goose needs it).
        assert!(json.contains("SUPER-SECRET-TOKEN"));
    }

    #[test]
    fn write_to_creates_owner_only_file() {
        let dir = std::env::temp_dir().join(format!("hearth-loadtest-test-{}", std::process::id()));
        let path = dir.join("seed-handle.json");
        sample_handle().write_to(&path).expect("write handle");
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "handle must be 0600, got {:o}",
                mode & 0o777
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

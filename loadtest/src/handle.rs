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

/// A raw session record seeded via `POST /dev/seed-session` (HEA-1907).
///
/// Unlike [`SeededToken`], this carries no JWT — it is a storage-level session
/// ID used for the C0 per-session memory sweep and the T4 throughput
/// re-measurement after the Layer B (SkipMap) fix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededSession {
    /// The seeded user's ID (UUID string).
    pub user_id: String,
    /// The created session's ID (UUID string).
    pub session_id: String,
}

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
///
/// `Debug` is implemented manually to redact [`cc_client_secret`](Self::cc_client_secret).
#[derive(Clone, Serialize, Deserialize)]
pub struct SeededRealm {
    /// Realm ID (UUID string).
    pub realm_id: String,
    /// OAuth client registered for the ROPC/revoke journeys (public client).
    /// Empty string when ROPC is not used (HEA-1907: ROPC removed by HEA-1862).
    pub client_id: String,
    /// Confidential OAuth client that supports the `client_credentials` grant,
    /// registered for the issuance saturation plane (HEA-2003). Empty string
    /// when not seeded (older handles, or a corpus seeded before this field
    /// existed). The harness mints tokens over `POST /token`
    /// (`grant_type=client_credentials`) with these credentials — a production
    /// grant, so the issuance plane needs no dev-only endpoint at run time.
    #[serde(default)]
    pub cc_client_id: String,
    /// The confidential client's secret (SECRET — redacted in `Debug`). Carried
    /// in the handle exactly like the bearer tokens: the on-disk JSON holds the
    /// plaintext (the harness needs it to authenticate `POST /token`), the file
    /// is `0600`, and `Debug` never reveals it. Empty when not seeded.
    #[serde(default)]
    pub cc_client_secret: String,
    /// User records created in this realm.
    pub users: Vec<SeededUser>,
    /// Live access tokens minted in this realm (a fraction pre-revoked).
    /// Empty when sessions are seeded via `sessions` instead (HEA-1907).
    pub tokens: Vec<SeededToken>,
    /// Raw sessions seeded via `POST /dev/seed-session` (HEA-1907).
    /// One entry per user when `--sessions-frac > 0`.
    #[serde(default)]
    pub sessions: Vec<SeededSession>,
}

// Manual Debug so a `{:?}` of a realm (or the enclosing handle) never spills the
// confidential client's secret into logs — the same discipline as `SeededToken`.
impl std::fmt::Debug for SeededRealm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeededRealm")
            .field("realm_id", &self.realm_id)
            .field("client_id", &self.client_id)
            .field("cc_client_id", &self.cc_client_id)
            .field("cc_client_secret", &"<redacted>")
            .field("users", &self.users)
            .field("tokens", &self.tokens)
            .field("sessions", &self.sessions)
            .finish()
    }
}

/// The persisted seed-handle. Serialized as JSON to `--seed-out`.
///
/// `Debug` is implemented manually to redact `admin_token`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SeedHandle {
    /// Base URL the corpus was seeded against.
    pub target_host: String,
    /// Deterministic seed used to derive the corpus.
    pub seed: u64,
    /// Human-readable dataset shape (mirrors the report header).
    pub dataset_shape: String,
    /// Bootstrap admin bearer token (SECRET). Stored here (0600 file) so the
    /// load run's `user_lookup` journey can authenticate admin endpoints.
    /// Defaults to empty string when loading pre-HEA-1995 handles; re-seed to
    /// populate.
    #[serde(default)]
    pub admin_token: String,
    /// Seeded realms.
    pub realms: Vec<SeededRealm>,
}

impl std::fmt::Debug for SeedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedHandle")
            .field("target_host", &self.target_host)
            .field("seed", &self.seed)
            .field("dataset_shape", &self.dataset_shape)
            .field("admin_token", &"<redacted>")
            .field("realms", &self.realms)
            .finish()
    }
}

impl SeedHandle {
    /// Creates an empty handle stamped with the run's parameters.
    #[must_use]
    pub fn new(params: &SeedParams) -> Self {
        Self {
            target_host: params.target_host.clone(),
            seed: params.seed,
            dataset_shape: params.dataset_shape_summary(),
            admin_token: String::new(),
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

    /// Total raw sessions seeded via `POST /dev/seed-session` across all realms.
    #[must_use]
    pub fn total_sessions(&self) -> usize {
        self.realms.iter().map(|r| r.sessions.len()).sum()
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
        write_owner_only(path, &json)?;
        restrict_permissions(path)?;
        Ok(())
    }
}

/// Creates (or truncates) the file with `0600` set at open time, so the handle
/// never exists on disk with umask-default permissions — not even between
/// create and chmod. On non-Unix this is a plain write; see
/// [`restrict_permissions`].
#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &str) -> io::Result<()> {
    std::fs::write(path, contents)
}

/// Sets `0600` on the handle file (owner read/write only). `mode(0o600)` at
/// open time only applies to newly created files, so this fixes up a
/// pre-existing handle written with looser permissions. No-op on non-Unix.
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
            admin_token: "ADMIN-BOOTSTRAP-TOKEN".into(),
            realms: vec![SeededRealm {
                realm_id: "realm-uuid".into(),
                client_id: "client-uuid".into(),
                cc_client_id: "cc-client-uuid".into(),
                cc_client_secret: "SUPER-SECRET-CLIENT-SECRET".into(),
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
                sessions: vec![SeededSession {
                    user_id: "user-uuid".into(),
                    session_id: "session-uuid".into(),
                }],
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
        assert!(
            !dbg.contains("ADMIN-BOOTSTRAP-TOKEN"),
            "Debug must not reveal the admin token: {dbg}"
        );
        assert!(
            !dbg.contains("SUPER-SECRET-CLIENT-SECRET"),
            "Debug must not reveal the confidential client secret: {dbg}"
        );
    }

    #[test]
    fn client_credentials_secret_roundtrips_in_json_but_redacts_in_debug() {
        // The confidential client's secret must survive the on-disk JSON (the
        // harness authenticates POST /token with it) yet never appear in Debug —
        // the same contract as the bearer tokens (HEA-2003).
        let h = sample_handle();
        let json = h.to_json().expect("serialize");
        assert!(
            json.contains("SUPER-SECRET-CLIENT-SECRET"),
            "JSON must carry the plaintext client secret for the harness"
        );
        assert!(json.contains("cc-client-uuid"));
        let back: SeedHandle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.realms[0].cc_client_id, "cc-client-uuid");
        assert_eq!(
            back.realms[0].cc_client_secret,
            "SUPER-SECRET-CLIENT-SECRET"
        );
    }

    #[test]
    fn json_roundtrips_and_counts_are_correct() {
        let h = sample_handle();
        assert_eq!(h.total_tokens(), 2);
        assert_eq!(h.total_revoked(), 1);
        assert_eq!(h.total_sessions(), 1);
        let json = h.to_json().expect("serialize");
        let back: SeedHandle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.total_tokens(), 2);
        assert_eq!(back.total_sessions(), 1);
        assert_eq!(back.realms[0].realm_id, "realm-uuid");
        assert_eq!(back.realms[0].sessions[0].session_id, "session-uuid");
        assert_eq!(back.admin_token, "ADMIN-BOOTSTRAP-TOKEN");
        // The JSON form intentionally carries live tokens and the admin token
        // (Goose needs them for load journeys).
        assert!(json.contains("SUPER-SECRET-TOKEN"));
        assert!(json.contains("ADMIN-BOOTSTRAP-TOKEN"));
    }

    #[test]
    fn sessions_default_on_old_handle_deserialization() {
        // Old handle JSON without the `sessions` field must deserialize cleanly.
        let old_json = r#"{
            "target_host": "http://127.0.0.1:8420",
            "seed": 1,
            "dataset_shape": "realms=1 users/realm=1",
            "realms": [{
                "realm_id": "old-realm",
                "client_id": "old-client",
                "users": [],
                "tokens": []
            }]
        }"#;
        let h: SeedHandle = serde_json::from_str(old_json).expect("deserialize old handle");
        assert_eq!(h.total_sessions(), 0, "sessions defaults to empty");
        assert!(
            h.admin_token.is_empty(),
            "admin_token defaults to empty on old handles"
        );
        assert!(
            h.realms[0].cc_client_id.is_empty() && h.realms[0].cc_client_secret.is_empty(),
            "confidential-client fields default to empty on pre-HEA-2003 handles"
        );
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

    /// Regression (HEA-1794): a pre-existing handle with loose permissions must
    /// be tightened to `0600` on rewrite — `mode(0o600)` at open time only
    /// applies to newly created files.
    #[test]
    #[cfg(unix)]
    fn write_to_tightens_a_preexisting_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("hearth-loadtest-test-loose-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("seed-handle.json");
        std::fs::write(&path, "{}").expect("pre-create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen perms");

        sample_handle().write_to(&path).expect("rewrite handle");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "rewrite must tighten a loose pre-existing handle, got {:o}",
            mode & 0o777
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

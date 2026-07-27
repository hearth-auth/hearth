//! WAL format version migration table.
//!
//! Each entry transforms raw file bytes from one format version to the next.
//! Migrations are applied in sorted order when a legacy WAL file is opened.
//!
//! # Adding a migration
//!
//! 1. Bump `WAL_VERSION_CURRENT`.
//! 2. Push a new `WalMigration` to `MIGRATIONS` with `from = old` and `to = new`.
//! 3. Implement the transformation function and add a unit test.

use crate::storage::error::StorageError;

/// 4-byte magic identifying a versioned Hearth WAL file.
pub(crate) const WAL_MAGIC: [u8; 4] = *b"HWAL";

/// Current WAL format version written to new files.
pub(crate) const WAL_VERSION_CURRENT: u16 = 1;

/// Byte length of the version header prepended before the encryption header.
/// Layout: `[4B magic][2B version LE]`.
pub const WAL_VERSION_HEADER_SIZE: usize = 6;

/// A single WAL format migration step.
pub(crate) struct WalMigration {
    /// Source format version.
    pub from: u16,
    /// Target format version.
    pub to: u16,
    /// Pure byte-level transformation: takes old file bytes, returns new.
    pub apply: fn(&[u8]) -> Vec<u8>,
}

/// Sorted list of all WAL format migrations.
pub(crate) static MIGRATIONS: &[WalMigration] = &[WalMigration {
    from: 0,
    to: 1,
    apply: migrate_v0_to_v1,
}];

/// Applies all migrations from `from_version` up to (and including) `target_version`.
///
/// Returns the transformed file bytes. Returns `Err` when the migration chain
/// has a gap (which would indicate a bug in the migration table).
pub(crate) fn apply_migrations(
    content: &[u8],
    from_version: u16,
    target_version: u16,
) -> Result<Vec<u8>, StorageError> {
    apply_chain(MIGRATIONS, content, from_version, target_version)
}

/// Core migration walk, parameterised over the migration table so both the
/// gap and incomplete-chain error branches are exercisable in isolation.
/// Production always drives this with the static [`MIGRATIONS`] table via
/// [`apply_migrations`].
fn apply_chain(
    migrations: &[WalMigration],
    content: &[u8],
    from_version: u16,
    target_version: u16,
) -> Result<Vec<u8>, StorageError> {
    let mut data = content.to_vec();
    let mut ver = from_version;
    for m in migrations {
        if m.from < from_version || m.from >= target_version {
            continue;
        }
        if m.from != ver {
            return Err(StorageError::DeserializationFailed {
                reason: format!("no WAL migration step available from v{ver}"),
            });
        }
        data = (m.apply)(&data);
        ver = m.to;
    }
    if ver != target_version {
        return Err(StorageError::DeserializationFailed {
            reason: format!(
                "WAL migration incomplete: reached v{ver} but target is v{target_version}"
            ),
        });
    }
    Ok(data)
}

/// v0 → v1: prepend the 6-byte `[HWAL][0x0001 LE]` version header.
///
/// The encryption header and all records that follow are unchanged.
fn migrate_v0_to_v1(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WAL_VERSION_HEADER_SIZE + content.len());
    out.extend_from_slice(&WAL_MAGIC);
    out.extend_from_slice(&WAL_VERSION_CURRENT.to_le_bytes());
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_v0_to_v1_prepends_header() {
        let content = b"fake-enc-header-and-records";
        let result = migrate_v0_to_v1(content);
        assert_eq!(&result[..4], b"HWAL");
        assert_eq!(u16::from_le_bytes([result[4], result[5]]), 1);
        assert_eq!(&result[6..], content.as_ref());
    }

    #[test]
    fn apply_migrations_v0_to_v1() {
        let content = b"v0-content";
        let result = apply_migrations(content, 0, 1).expect("migration");
        assert!(result.starts_with(b"HWAL"));
        assert_eq!(&result[6..], content.as_ref());
    }

    #[test]
    fn apply_migrations_noop_when_already_at_target() {
        let content = b"already-v1";
        // from == target => no migrations run
        let result = apply_migrations(content, 1, 1).expect("noop migration");
        assert_eq!(result, content.as_ref());
    }

    /// Negative: the incomplete-chain branch. The real `MIGRATIONS` table tops
    /// out at v1, so a request to reach v2 leaves `ver` at 1 and must surface
    /// `DeserializationFailed` rather than silently returning under-migrated
    /// bytes.
    #[test]
    fn apply_migrations_errors_when_target_beyond_table() {
        let content = b"v0-content";
        let err = apply_migrations(content, 0, 2).expect_err("target beyond table must fail");
        match err {
            StorageError::DeserializationFailed { reason } => {
                assert!(
                    reason.contains("reached v1") && reason.contains("target is v2"),
                    "reason should name reached/target versions, got: {reason}"
                );
            }
            other => panic!("expected DeserializationFailed, got {other:?}"),
        }
    }

    /// Negative: the gap-in-chain branch. A table whose first applicable step
    /// starts at v1 while `from_version` is v0 has no way to reach v1, so
    /// `apply_chain` must reject with `DeserializationFailed` rather than
    /// applying a step out of order. This branch is unreachable through the
    /// single-step production table, hence the injected table here.
    #[test]
    fn apply_chain_errors_on_gap_in_migration_table() {
        static GAPPED: &[WalMigration] = &[WalMigration {
            from: 1,
            to: 2,
            apply: migrate_v0_to_v1,
        }];
        let content = b"v0-content";
        let err =
            apply_chain(GAPPED, content, 0, 2).expect_err("gap in migration chain must fail");
        match err {
            StorageError::DeserializationFailed { reason } => {
                assert!(
                    reason.contains("no WAL migration step available from v0"),
                    "reason should name the missing step, got: {reason}"
                );
            }
            other => panic!("expected DeserializationFailed, got {other:?}"),
        }
    }
}

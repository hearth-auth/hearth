//! The last-successful-backup markers in the data directory (#648).
//!
//! Each successful backup writes the time it completed to a small file in the
//! data directory: `POST /admin/backup` writes `backup-last-success-online`,
//! and the offline `hearth backup create` writes `backup-last-success-offline`.
//! The server reads both files at each `/metrics` scrape, so the
//! `hearth_backup_last_success_timestamp_seconds` gauge also covers a backup
//! that ran while the server was stopped.
//!
//! Each file holds the Unix time in seconds as decimal text and a newline.
//! A write goes to a temporary file first and is then renamed over the
//! marker, so a reader never sees a half-written time.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Which backup path completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupSource {
    /// `POST /admin/backup` on a running server.
    Online,
    /// `hearth backup create` against a stopped server's data directory.
    Offline,
}

impl BackupSource {
    /// Every source, in the order the metric exports them.
    pub const ALL: [Self; 2] = [Self::Online, Self::Offline];

    /// The `source` label value of the metric.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Online => "backup-last-success-online",
            Self::Offline => "backup-last-success-offline",
        }
    }
}

/// The marker file of `source` in `data_dir`.
#[must_use]
pub fn marker_path(data_dir: &Path, source: BackupSource) -> PathBuf {
    data_dir.join(source.file_name())
}

/// Records that a backup of `source` completed at `at`.
///
/// # Errors
///
/// Fails if the marker cannot be written or renamed into place. The caller
/// logs the error: the backup itself succeeded.
pub fn record_success(
    data_dir: &Path,
    source: BackupSource,
    at: SystemTime,
) -> std::io::Result<()> {
    let secs = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let target = marker_path(data_dir, source);
    // A unique temporary name, so two online backups that complete together
    // do not write the same temporary file.
    let tmp = data_dir.join(format!(
        ".{}.{}.{}.tmp",
        source.file_name(),
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&tmp, format!("{secs}\n"))?;
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// The Unix time in seconds of the last successful backup of `source`, or
/// `None` if no backup of that source completed or the marker is unreadable.
#[must_use]
pub fn last_success(data_dir: &Path, source: BackupSource) -> Option<u64> {
    std::fs::read_to_string(marker_path(data_dir, source))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_recorded_success_reads_back_per_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);

        assert_eq!(last_success(dir.path(), BackupSource::Online), None);
        record_success(dir.path(), BackupSource::Online, at).expect("record");

        assert_eq!(
            last_success(dir.path(), BackupSource::Online),
            Some(1_800_000_000)
        );
        assert_eq!(
            last_success(dir.path(), BackupSource::Offline),
            None,
            "an online backup must not set the offline marker"
        );
    }

    #[test]
    fn a_later_success_replaces_the_marker_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        for secs in [1_800_000_000, 1_800_086_400] {
            record_success(
                dir.path(),
                BackupSource::Offline,
                UNIX_EPOCH + Duration::from_secs(secs),
            )
            .expect("record");
        }
        assert_eq!(
            last_success(dir.path(), BackupSource::Offline),
            Some(1_800_086_400)
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["backup-last-success-offline"], "got {names:?}");
    }

    #[test]
    fn an_unreadable_marker_reads_as_no_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            marker_path(dir.path(), BackupSource::Online),
            "not a time\n",
        )
        .expect("write");
        assert_eq!(last_success(dir.path(), BackupSource::Online), None);
    }
}

//! The store format version of a data directory (#646).
//!
//! Records on disk are `postcard`-encoded and carry no per-record version
//! (`src/codec.rs`), so a build cannot tell from a record which layout wrote
//! it. Instead, the data directory as a whole carries one version, in the
//! file `FORMAT`. A build opens a data directory only when that version is
//! [`STORE_FORMAT_VERSION`]; any other version is refused before a record is
//! read, so a build never misreads data that another layout wrote.
//!
//! Bump [`STORE_FORMAT_VERSION`] in the same change as any change to how a
//! record, the WAL, an SST or the key file is laid out on disk. The fixture
//! test (`tests/store_format_fixture.rs`) fails until you do, and
//! `docs/guides/upgrading.md` describes what a bump means for operators.

use std::path::Path;

use super::error::StorageError;
use super::fs::Fs;

/// The store format this build reads and writes.
pub const STORE_FORMAT_VERSION: u32 = 1;

/// The name of the format file in the data directory.
pub const FORMAT_FILE: &str = "FORMAT";

/// The text before the version number in the format file.
const FORMAT_PREFIX: &str = "hearth-store-format ";

/// Checks the format version of `data_dir`, or writes it if the directory has
/// no format file yet.
///
/// A directory without a format file is a new store, or a store from a build
/// before #646; both get the current version.
///
/// # Errors
///
/// [`StorageError::UnsupportedStoreFormat`] if the format file holds another
/// version or cannot be parsed; [`StorageError::Io`] if it cannot be read or
/// written.
pub(crate) fn check_or_init(data_dir: &Path, fs: &dyn Fs) -> Result<(), StorageError> {
    let path = data_dir.join(FORMAT_FILE);
    match fs.read(&path) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            let text = text.trim();
            let version = text
                .strip_prefix(FORMAT_PREFIX)
                .and_then(|v| v.parse::<u32>().ok());
            if version == Some(STORE_FORMAT_VERSION) {
                return Ok(());
            }
            Err(StorageError::UnsupportedStoreFormat {
                data_dir: data_dir.to_path_buf(),
                found: text.chars().take(64).collect(),
                supported: STORE_FORMAT_VERSION,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_format(data_dir, fs),
        Err(e) => Err(StorageError::Io(e)),
    }
}

/// Writes the format file: temporary file, fsync, rename, directory fsync, so
/// a crash leaves either no format file or a complete one.
///
/// The temporary file is `FORMAT.new`, not `*.tmp` or `*.staging`: those
/// names belong to compaction and flush output. A crash can leave
/// `FORMAT.new` behind; the next open overwrites it.
fn write_format(data_dir: &Path, fs: &dyn Fs) -> Result<(), StorageError> {
    let tmp = data_dir.join(format!("{FORMAT_FILE}.new"));
    {
        let mut file = fs.create(&tmp)?;
        file.write_all(format!("{FORMAT_PREFIX}{STORE_FORMAT_VERSION}\n").as_bytes())?;
        file.sync_all()?;
    }
    fs.rename(&tmp, &data_dir.join(FORMAT_FILE))?;
    fs.sync_dir(data_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fs::RealFs;

    fn format_text(dir: &Path) -> String {
        std::fs::read_to_string(dir.join(FORMAT_FILE)).expect("read FORMAT")
    }

    #[test]
    fn a_new_data_directory_gets_the_current_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        check_or_init(dir.path(), &RealFs).expect("init");
        assert_eq!(
            format_text(dir.path()),
            format!("hearth-store-format {STORE_FORMAT_VERSION}\n")
        );
        // A second open reads the file it wrote.
        check_or_init(dir.path(), &RealFs).expect("reopen");
    }

    #[test]
    fn another_format_version_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let other = STORE_FORMAT_VERSION + 1;
        std::fs::write(
            dir.path().join(FORMAT_FILE),
            format!("hearth-store-format {other}\n"),
        )
        .expect("write");

        let err = check_or_init(dir.path(), &RealFs).expect_err("must refuse");
        let text = err.to_string();
        assert!(
            matches!(err, StorageError::UnsupportedStoreFormat { .. }),
            "got {err:?}"
        );
        assert!(
            text.contains(&format!("format {other}"))
                && text.contains(&format!("format {STORE_FORMAT_VERSION}"))
                && text.contains("upgrading.md"),
            "the error must name both versions and the upgrade guide: {text}"
        );
        assert_eq!(
            format_text(dir.path()),
            format!("hearth-store-format {other}\n"),
            "a refused directory must not be changed"
        );
    }

    #[test]
    fn an_unreadable_format_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(FORMAT_FILE), "something else\n").expect("write");
        let err = check_or_init(dir.path(), &RealFs).expect_err("must refuse");
        assert!(
            matches!(err, StorageError::UnsupportedStoreFormat { .. }),
            "got {err:?}"
        );
    }
}

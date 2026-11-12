//! The backup passphrase (#649).
//!
//! A backup archive's data key is wrapped with a passphrase. The passphrase
//! comes from `HEARTH_BACKUP_PASSPHRASE`, and it is not the storage master key
//! (`HEARTH_MASTER_KEY`): a lost or rotated master key must not lose the
//! backups, and a leaked backup passphrase must not open the data directory.

use secrecy::SecretString;

/// The environment variable that holds the backup passphrase.
pub const BACKUP_PASSPHRASE_ENV: &str = "HEARTH_BACKUP_PASSPHRASE";

/// Reads the backup passphrase from [`BACKUP_PASSPHRASE_ENV`].
///
/// Returns `Ok(None)` when the variable is not set.
///
/// # Errors
///
/// Returns an error message (which never holds the value) when the variable
/// is set but empty or not valid UTF-8.
pub fn passphrase_from_env() -> Result<Option<SecretString>, String> {
    parse(std::env::var(BACKUP_PASSPHRASE_ENV))
}

/// The passphrase from a read of [`BACKUP_PASSPHRASE_ENV`].
fn parse(read: Result<String, std::env::VarError>) -> Result<Option<SecretString>, String> {
    match read {
        Ok(value) if value.is_empty() => Err(format!("{BACKUP_PASSPHRASE_ENV} is set but empty")),
        Ok(value) => Ok(Some(SecretString::from(value))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{BACKUP_PASSPHRASE_ENV} is not valid UTF-8"))
        }
    }
}

/// The message of a server-side backup or restore without a passphrase.
fn missing() -> String {
    format!(
        "{BACKUP_PASSPHRASE_ENV} is not set: a backup archive is encrypted with the backup \
         passphrase, which is not HEARTH_MASTER_KEY"
    )
}

/// Reads the backup passphrase that a server-side backup or restore needs.
///
/// # Errors
///
/// Returns an error message that names [`BACKUP_PASSPHRASE_ENV`] when the
/// variable is not set, empty or not valid UTF-8.
pub fn required_passphrase_from_env() -> Result<SecretString, String> {
    passphrase_from_env()?.ok_or_else(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;
    use std::env::VarError;

    #[test]
    fn an_unset_passphrase_is_none_and_the_missing_message_names_the_variable() {
        assert!(matches!(parse(Err(VarError::NotPresent)), Ok(None)));
        assert!(missing().contains(BACKUP_PASSPHRASE_ENV));
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        let err = parse(Ok(String::new())).expect_err("empty");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn a_set_passphrase_is_returned() {
        let got = parse(Ok("correct horse".to_string()))
            .expect("set")
            .expect("some");
        assert_eq!(got.expose_secret(), "correct horse");
    }
}

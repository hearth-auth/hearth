//! LDAP filter construction helpers.
//!
//! Provides safe filter-building primitives that escape special characters per
//! RFC 4515 § 3, preventing LDAP filter injection from user-controlled values.

use crate::identity::ldap::error::LdapError;

/// RFC 4515 special characters that must be escaped in assertion values.
const RFC4515_SPECIAL: &[u8] = b"*()\\\x00";

/// Escapes an assertion value per RFC 4515 § 3.
///
/// The characters `*`, `(`, `)`, `\`, and NUL are replaced with their
/// `\xx` hex-escape form.
pub(crate) fn escape_assertion_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if RFC4515_SPECIAL.contains(&byte) {
            out.push('\\');
            out.push_str(&format!("{byte:02x}"));
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

/// Builds the LDAP search filter used for the initial full load.
///
/// Combines the configured base `user_filter` (e.g. `(objectClass=person)`)
/// with an `AND` clause requiring the presence of the `external_id` attribute.
/// Returns an `LdapError::InvalidFilter` if `user_filter` is empty.
pub(crate) fn build_full_sync_filter(
    user_filter: &str,
    external_id_attr: &str,
) -> Result<String, LdapError> {
    if user_filter.is_empty() {
        return Err(LdapError::InvalidFilter {
            filter: user_filter.to_string(),
            reason: "user_filter must not be empty".to_string(),
        });
    }
    // Ensure external_id attribute is present on every returned entry.
    Ok(format!("(&{user_filter}({external_id_attr}=*))"))
}

/// Builds the LDAP filter for delta sync using `modifyTimestamp`.
///
/// `cursor` is the last seen `generalizedTime` value, e.g. `"20240101120000Z"`.
/// Retrieves all entries where `modifyTimestamp >= cursor` AND the
/// `external_id` attribute is present.
pub(crate) fn build_modify_timestamp_filter(
    user_filter: &str,
    modify_ts_attr: &str,
    external_id_attr: &str,
    cursor: &str,
) -> Result<String, LdapError> {
    if user_filter.is_empty() {
        return Err(LdapError::InvalidFilter {
            filter: user_filter.to_string(),
            reason: "user_filter must not be empty".to_string(),
        });
    }
    let escaped_cursor = escape_assertion_value(cursor);
    Ok(format!(
        "(&{user_filter}({modify_ts_attr}>={escaped_cursor})({external_id_attr}=*))"
    ))
}

/// Builds the LDAP filter for delta sync using `uSNChanged` (Active Directory).
///
/// `last_usn` is the last seen USN as a decimal integer string.
/// Retrieves entries where `uSNChanged > last_usn`.
pub(crate) fn build_usn_changed_filter(
    user_filter: &str,
    usn_attr: &str,
    external_id_attr: &str,
    last_usn: &str,
) -> Result<String, LdapError> {
    if user_filter.is_empty() {
        return Err(LdapError::InvalidFilter {
            filter: user_filter.to_string(),
            reason: "user_filter must not be empty".to_string(),
        });
    }
    // For AD USN we use >= (last_usn + 1) to exclude the already-seen entry.
    let next_usn: u64 = last_usn.parse().map_err(|_| LdapError::InvalidFilter {
        filter: last_usn.to_string(),
        reason: "USN cursor must be a decimal integer".to_string(),
    })?;
    let escaped_next = escape_assertion_value(&(next_usn + 1).to_string());
    Ok(format!(
        "(&{user_filter}({usn_attr}>={escaped_next})({external_id_attr}=*))"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_plain_value() {
        assert_eq!(escape_assertion_value("johndoe"), "johndoe");
    }

    #[test]
    fn escape_special_chars() {
        let raw = "a*(b)c\\d\x00e";
        let escaped = escape_assertion_value(raw);
        assert_eq!(escaped, r"a\2a\28b\29c\5cd\00e");
    }

    #[test]
    fn escape_asterisk_prevents_wildcard_injection() {
        let injected = "admin*)(uid=*)";
        let escaped = escape_assertion_value(injected);
        assert!(
            !escaped.contains('*'),
            "unescaped * must not appear in output"
        );
        assert!(
            !escaped.contains(')'),
            "unescaped ) must not appear in output"
        );
        assert!(escaped.contains(r"\2a"), "* must be encoded as \\2a");
        assert!(escaped.contains(r"\29"), ") must be encoded as \\29");
    }

    #[test]
    fn build_full_sync_filter_basic() {
        let f = build_full_sync_filter("(objectClass=person)", "entryUUID")
            .expect("valid filter should build successfully");
        assert!(f.starts_with("(&(objectClass=person)"));
        assert!(f.contains("entryUUID=*"));
    }

    #[test]
    fn build_full_sync_filter_empty_base_is_error() {
        let err = build_full_sync_filter("", "entryUUID")
            .expect_err("empty base filter should be rejected");
        assert!(matches!(err, LdapError::InvalidFilter { .. }));
    }

    #[test]
    fn build_modify_timestamp_filter_basic() {
        let f = build_modify_timestamp_filter(
            "(objectClass=person)",
            "modifyTimestamp",
            "entryUUID",
            "20240101120000Z",
        )
        .expect("valid modify-timestamp filter should build successfully");
        assert!(f.contains("modifyTimestamp>=20240101120000Z"));
        assert!(f.contains("entryUUID=*"));
    }

    #[test]
    fn build_usn_changed_filter_increments_by_one() {
        let f =
            build_usn_changed_filter("(objectClass=person)", "uSNChanged", "objectGUID", "1000")
                .expect("valid USN filter should build successfully");
        // Should filter for >= 1001
        assert!(f.contains("uSNChanged>=1001"));
    }

    #[test]
    fn build_usn_changed_filter_non_numeric_cursor_is_error() {
        let err = build_usn_changed_filter(
            "(objectClass=person)",
            "uSNChanged",
            "objectGUID",
            "not-a-number",
        )
        .expect_err("non-numeric USN cursor should be rejected");
        assert!(matches!(err, LdapError::InvalidFilter { .. }));
    }

    #[test]
    fn build_usn_changed_filter_zero_cursor() {
        let f = build_usn_changed_filter("(objectClass=person)", "uSNChanged", "objectGUID", "0")
            .expect("zero USN cursor should build successfully");
        assert!(f.contains("uSNChanged>=1"));
    }
}

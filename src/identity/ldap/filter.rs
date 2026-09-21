//! LDAP filter construction helpers.
//!
//! Three different kinds of string reach a search filter, and exactly one of
//! them is made safe by escaping. Conflating them is finding L-4 (task 26.7):
//! the module doc claimed escaping covered "any user-controlled input", while
//! the only two values it was applied to were assertion values and the values
//! that are *string-concatenated* into the filter skeleton were not checked at
//! all.
//!
//! | Kind | Example | Guard |
//! |---|---|---|
//! | Assertion value | the delta-sync cursor | [`escape_assertion_value`] — RFC 4515 § 3 |
//! | Attribute descriptor | `entryUUID`, `uSNChanged` | [`validate_attribute_descriptor`] — RFC 4512 § 2.5 |
//! | Filter fragment | the configured `user_filter` | [`validate_user_filter`] — must be one balanced expression |
//! | Distinguished name | `base_dn`, a user's DN | none needed here: `ldap3` sends a DN as a protocol parameter, BER-encoded, never concatenated into a filter |
//!
//! Escaping is *wrong* for the middle two: an escaped attribute descriptor
//! names no attribute, and an escaped `user_filter` is a literal string rather
//! than a filter. They have to be validated instead, and rejected outright
//! when they are not well-formed.

use crate::identity::ldap::error::LdapError;

/// RFC 4515 special characters that must be escaped in assertion values.
const RFC4515_SPECIAL: &[u8] = b"*()\\\x00";

/// Escapes an assertion value per RFC 4515 § 3.
///
/// The characters `*`, `(`, `)`, `\`, and NUL are replaced with their
/// `\xx` hex-escape form.
///
/// Every byte outside printable ASCII is hex-escaped too. RFC 4515 § 3 permits
/// `ESC HEX HEX` for *any* octet, and the alternative is wrong: the previous
/// implementation rebuilt each non-special byte with `char::from(byte)`, which
/// is a Latin-1 decode. Re-encoding that `char` as UTF-8 doubled every byte
/// above 0x7F, so `José` left this function as `JosÃ©` and the directory was
/// asked about an identifier nobody has. Hex-escaping keeps the octets the
/// caller actually supplied, and makes the output pure ASCII by construction.
pub(crate) fn escape_assertion_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if RFC4515_SPECIAL.contains(&byte) || !(0x20..0x7f).contains(&byte) {
            out.push('\\');
            out.push_str(&format!("{byte:02x}"));
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

/// True for an RFC 4512 § 1.4 `keychar`: `ALPHA / DIGIT / HYPHEN`.
fn is_keychar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

/// True for an RFC 4512 § 1.4 `keystring`: `leadkeychar *keychar`, where
/// `leadkeychar` is an `ALPHA`.
fn is_keystring(value: &str) -> bool {
    let mut bytes = value.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(is_keychar)
}

/// True for an RFC 4512 § 1.4 `numericoid`: `number 1*( DOT number )`, where a
/// `number` is a single digit or a non-zero-leading digit run.
fn is_numericoid(value: &str) -> bool {
    let mut count = 0usize;
    for arc in value.split('.') {
        count += 1;
        let ok = !arc.is_empty()
            && arc.bytes().all(|b| b.is_ascii_digit())
            && (arc.len() == 1 || !arc.starts_with('0'));
        if !ok {
            return false;
        }
    }
    count >= 2
}

/// Validates an attribute descriptor before it is concatenated into a filter.
///
/// An attribute descriptor is `attributetype *( SEMI option )` (RFC 4512
/// § 2.5), where `attributetype` is a `keystring` or a `numericoid` and each
/// option is `1*keychar`. None of those alphabets contains `(`, `)`, `*`, `\`,
/// `=` or whitespace, so a descriptor that passes this check cannot close the
/// parenthesis it was interpolated into or start a new assertion.
///
/// This is deliberately *not* [`escape_assertion_value`]: escaping a
/// descriptor would produce a name that matches no attribute in the directory,
/// which is a silent empty result rather than a refusal. The only safe
/// handling for a malformed descriptor is to reject it.
pub(crate) fn validate_attribute_descriptor(name: &str) -> Result<(), LdapError> {
    let mut parts = name.split(';');
    let base = parts.next().unwrap_or("");
    if !(is_keystring(base) || is_numericoid(base)) {
        return Err(LdapError::InvalidAttributeName {
            attribute: name.to_string(),
            reason: "attribute type must be an RFC 4512 keystring \
                     (ALPHA *(ALPHA / DIGIT / HYPHEN)) or a numeric OID"
                .to_string(),
        });
    }
    for option in parts {
        if option.is_empty() || !option.bytes().all(is_keychar) {
            return Err(LdapError::InvalidAttributeName {
                attribute: name.to_string(),
                reason: "each ';' option must be a non-empty run of \
                         ALPHA / DIGIT / HYPHEN"
                    .to_string(),
            });
        }
    }
    Ok(())
}

/// Validates the operator-configured `user_filter` before it is concatenated
/// into a larger filter.
///
/// The configured value is a filter *fragment*, so it cannot be escaped — it
/// has to parse as one balanced, parenthesised RFC 4515 expression. Requiring
/// a single top-level expression is what stops a fragment from closing the
/// `(&…)` it is embedded in and appending a clause of its own: `(a=b))(cn=*` is
/// rejected here rather than becoming `(&(a=b))(cn=*(entryUUID=*))` at the
/// call site.
///
/// Counting raw parentheses is sound because RFC 4515 § 3 requires a literal
/// parenthesis inside an assertion value to appear in `\28` / `\29` hex form,
/// so every unescaped `(` or `)` in a well-formed filter is structural.
pub(crate) fn validate_user_filter(user_filter: &str) -> Result<(), LdapError> {
    let reject = |reason: &str| {
        Err(LdapError::InvalidFilter {
            filter: user_filter.to_string(),
            reason: reason.to_string(),
        })
    };

    if user_filter.is_empty() {
        return reject("user_filter must not be empty");
    }
    if user_filter.contains('\0') {
        return reject("user_filter must not contain a NUL byte");
    }
    if !user_filter.starts_with('(') || !user_filter.ends_with(')') {
        return reject("user_filter must be a single parenthesised RFC 4515 expression");
    }

    let mut depth: i32 = 0;
    for (index, byte) in user_filter.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth < 0 {
                    return reject("user_filter closes a parenthesis it never opened");
                }
                if depth == 0 && index + 1 != user_filter.len() {
                    return reject(
                        "user_filter must be a single expression, not several \
                         concatenated ones",
                    );
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return reject("user_filter has an unclosed parenthesis");
    }
    Ok(())
}

/// Builds the LDAP search filter used for the initial full load.
///
/// Combines the configured base `user_filter` (e.g. `(objectClass=person)`)
/// with an `AND` clause requiring the presence of the `external_id` attribute.
/// Both concatenated values are validated first — see
/// [`validate_user_filter`] and [`validate_attribute_descriptor`].
pub(crate) fn build_full_sync_filter(
    user_filter: &str,
    external_id_attr: &str,
) -> Result<String, LdapError> {
    validate_user_filter(user_filter)?;
    validate_attribute_descriptor(external_id_attr)?;
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
    validate_user_filter(user_filter)?;
    validate_attribute_descriptor(modify_ts_attr)?;
    validate_attribute_descriptor(external_id_attr)?;
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
    validate_user_filter(user_filter)?;
    validate_attribute_descriptor(usn_attr)?;
    validate_attribute_descriptor(external_id_attr)?;
    // For AD USN we use >= (last_usn + 1) to exclude the already-seen entry.
    let next_usn: u64 = last_usn.parse().map_err(|_| LdapError::InvalidFilter {
        filter: last_usn.to_string(),
        reason: "USN cursor must be a decimal integer".to_string(),
    })?;
    // `saturating_add`, not `+` (task 26.38). `last_usn` is the directory's own
    // `uSNChanged` value read back from a checkpoint, so it is directory-
    // supplied, and `u64::MAX + 1` panics in a debug build. Saturating leaves
    // the filter asking for entries at or above `u64::MAX`, which is the
    // correct meaning of "everything after the last possible USN": nothing.
    let escaped_next = escape_assertion_value(&next_usn.saturating_add(1).to_string());
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

    // 23.8: the escaper rebuilt every non-special byte with `char::from`,
    // a Latin-1 decode. Re-encoding as UTF-8 doubled every byte above 0x7F,
    // so a non-ASCII assertion value reached the directory corrupted.
    #[test]
    fn escape_preserves_non_ascii_octets_exactly() {
        // "José" — the é is U+00E9, whose UTF-8 encoding is 0xC3 0xA9.
        let escaped = escape_assertion_value("José");
        assert_eq!(
            escaped, r"Jos\c3\a9",
            "non-ASCII octets must be hex-escaped, not Latin-1 round-tripped"
        );
        assert!(
            escaped.is_ascii(),
            "an RFC 4515 assertion value must leave this function as ASCII"
        );
    }

    #[test]
    fn escape_hex_escapes_control_characters() {
        let escaped = escape_assertion_value("a\tb\u{7f}");
        assert_eq!(escaped, r"a\09b\7f");
    }

    // ── 26.7 / finding L-4 ────────────────────────────────────────────────
    //
    // The escaper had no user-controlled call site while the values that ARE
    // concatenated into the filter skeleton — the configured `user_filter` and
    // every attribute descriptor — were interpolated with no check at all.
    // Escaping is the wrong guard for both; these are the right ones.

    #[test]
    fn attribute_descriptor_accepts_the_shapes_directories_actually_use() {
        for name in [
            "cn",
            "entryUUID",
            "uSNChanged",
            "sAMAccountName",
            "x-custom-attr",
            "userCertificate;binary",
            "description;lang-en;x-alt",
            "2.5.4.3",
        ] {
            validate_attribute_descriptor(name)
                .unwrap_or_else(|e| panic!("{name} must be accepted: {e}"));
        }
    }

    #[test]
    fn attribute_descriptor_rejects_a_name_that_can_close_the_filter() {
        // The break-out the module doc's claim was supposed to prevent:
        // `(&(objectClass=person)(entryUUID)(uid=*)=*))` if this were let through.
        let err = validate_attribute_descriptor("entryUUID)(uid=*")
            .expect_err("a ')' in an attribute name must be refused");
        assert!(matches!(err, LdapError::InvalidAttributeName { .. }));
    }

    #[test]
    fn attribute_descriptor_rejects_malformed_names() {
        for name in [
            "",              // empty
            "1cn",           // must not start with a digit
            "cn mail",       // whitespace
            "cn=*",          // an assertion, not a descriptor
            "cn*",           // wildcard
            "cn;",           // empty option
            "cn;bad option", // whitespace in the option
            "2.5.",          // trailing dot
            "2",             // a numeric OID needs at least two arcs
            "2.05.4",        // leading zero in an arc
            "cn\u{0}",       // NUL
        ] {
            assert!(
                validate_attribute_descriptor(name).is_err(),
                "{name:?} must be refused as an attribute descriptor"
            );
        }
    }

    #[test]
    fn user_filter_accepts_a_single_balanced_expression() {
        for filter in [
            "(objectClass=person)",
            "(&(objectClass=person)(!(memberOf=cn=disabled,dc=x)))",
            "(|(uid=a)(uid=b))",
        ] {
            validate_user_filter(filter)
                .unwrap_or_else(|e| panic!("{filter} must be accepted: {e}"));
        }
    }

    #[test]
    fn user_filter_rejects_a_fragment_that_escapes_its_enclosing_expression() {
        // Embedded in `(&{user_filter}(entryUUID=*))` this would produce
        // `(&(objectClass=*))(uid=admin)(entryUUID=*))` — a filter matching
        // everything, followed by a trailing clause the server may ignore.
        let err = validate_user_filter("(objectClass=*))(uid=admin")
            .expect_err("a fragment that closes its own parenthesis must be refused");
        assert!(matches!(err, LdapError::InvalidFilter { .. }));
    }

    #[test]
    fn user_filter_rejects_concatenated_expressions_and_unbalanced_parens() {
        for filter in [
            "(a=b)(c=d)",         // two top-level expressions
            "(objectClass=",      // unclosed
            "objectClass=person", // not parenthesised
            "(a=b))",             // closes one it never opened
            "((a=b)",             // unclosed outer
            "(a=b\u{0})",         // NUL
            "",                   // empty
        ] {
            assert!(
                validate_user_filter(filter).is_err(),
                "{filter:?} must be refused as a user_filter"
            );
        }
    }

    #[test]
    fn builders_refuse_a_malformed_attribute_descriptor() {
        let err = build_full_sync_filter("(objectClass=person)", "entryUUID)(uid=*")
            .expect_err("full-sync builder must refuse a malformed descriptor");
        assert!(matches!(err, LdapError::InvalidAttributeName { .. }));

        let err = build_modify_timestamp_filter(
            "(objectClass=person)",
            "modifyTimestamp)(uid=*",
            "entryUUID",
            "20240101120000Z",
        )
        .expect_err("delta builder must refuse a malformed sync attribute");
        assert!(matches!(err, LdapError::InvalidAttributeName { .. }));

        let err = build_usn_changed_filter(
            "(objectClass=person)",
            "uSNChanged",
            "objectGUID)(uid=*",
            "1",
        )
        .expect_err("USN builder must refuse a malformed external-id attribute");
        assert!(matches!(err, LdapError::InvalidAttributeName { .. }));
    }

    #[test]
    fn builders_refuse_a_user_filter_that_breaks_out() {
        let broken = "(objectClass=*))(uid=admin";
        assert!(build_full_sync_filter(broken, "entryUUID").is_err());
        assert!(
            build_modify_timestamp_filter(broken, "modifyTimestamp", "entryUUID", "2024").is_err()
        );
        assert!(build_usn_changed_filter(broken, "uSNChanged", "objectGUID", "1").is_err());
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

    /// Task 26.38 — a directory-supplied cursor must not be able to panic us.
    ///
    /// `last_usn` is the directory's own `uSNChanged`, read back from a
    /// checkpoint, so it is not a value Hearth chose. `next_usn + 1` panics in
    /// a debug build at `u64::MAX`; saturating leaves the filter asking for
    /// entries at or above `u64::MAX`, which is the right meaning of
    /// "everything after the last possible USN".
    #[test]
    fn build_usn_changed_filter_saturates_at_the_maximum_cursor() {
        let f = build_usn_changed_filter(
            "(objectClass=user)",
            "uSNChanged",
            "objectGUID",
            &u64::MAX.to_string(),
        )
        .expect("a maximum cursor must build a filter, not panic");
        assert!(
            f.contains(&format!("uSNChanged>={}", u64::MAX)),
            "the saturated cursor must appear in the filter; got: {f}"
        );
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

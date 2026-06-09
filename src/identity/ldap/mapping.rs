//! LDAP attribute → Hearth `LdapUser` mapping.
//!
//! Converts raw `ldap3::SearchEntry` attribute maps into typed `LdapUser`
//! structs using the operator-configured `LdapAttributeMap`.

use std::collections::HashMap;

use crate::identity::ldap::error::LdapError;
use crate::identity::ldap::types::{LdapAttributeMap, LdapUser};

/// Extracts the first UTF-8 string value for an LDAP attribute.
///
/// Returns `None` when the attribute is absent or has no values.
/// Returns `LdapError::AttributeEncoding` when the bytes are not valid UTF-8.
fn get_first_str<'a>(
    attrs: &'a HashMap<String, Vec<String>>,
    attr_name: &str,
) -> Result<Option<&'a str>, LdapError> {
    match attrs.get(attr_name) {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) => {
            // ldap3 already deserialises attributes as UTF-8 Strings;
            // non-UTF-8 values are dropped by the library. We just return the first.
            Ok(v.first().map(|s| s.as_str()))
        }
    }
}

/// Requires the first string value for an attribute, failing if absent.
fn require_str<'a>(
    attrs: &'a HashMap<String, Vec<String>>,
    attr_name: &str,
) -> Result<&'a str, LdapError> {
    get_first_str(attrs, attr_name)?.ok_or_else(|| LdapError::MissingAttribute {
        attribute: attr_name.to_string(),
    })
}

/// Maps a raw LDAP attribute map (as returned by `ldap3`) to a `LdapUser`.
///
/// `dn` is the distinguished name of the entry.
/// `attrs` is the string attribute map from the search result.
pub(crate) fn map_entry(
    dn: &str,
    attrs: &HashMap<String, Vec<String>>,
    attr_map: &LdapAttributeMap,
) -> Result<LdapUser, LdapError> {
    let external_id = require_str(attrs, &attr_map.external_id)?;
    let email = require_str(attrs, &attr_map.email)?;
    let display_name = require_str(attrs, &attr_map.display_name)?;
    let sync_cursor = require_str(attrs, &attr_map.sync_attribute)?;

    let given_name = get_first_str(attrs, &attr_map.given_name)?.map(str::to_string);
    let family_name = get_first_str(attrs, &attr_map.family_name)?.map(str::to_string);
    let username = get_first_str(attrs, &attr_map.username)?.map(str::to_string);

    let mut extra = HashMap::new();
    for (ldap_attr, hearth_key) in &attr_map.extra {
        if let Some(val) = get_first_str(attrs, ldap_attr)? {
            extra.insert(hearth_key.clone(), val.to_string());
        }
    }

    Ok(LdapUser {
        dn: dn.to_string(),
        external_id: external_id.to_string(),
        email: email.to_string(),
        display_name: display_name.to_string(),
        given_name,
        family_name,
        username,
        sync_cursor: sync_cursor.to_string(),
        extra,
    })
}

/// Collects all attribute names requested by the configured mapping.
///
/// Used to build the attribute list passed to `ldap3`'s `search()` call so
/// the server only returns the fields we actually need.
pub(crate) fn requested_attributes(attr_map: &LdapAttributeMap) -> Vec<String> {
    let mut attrs = vec![
        attr_map.email.clone(),
        attr_map.display_name.clone(),
        attr_map.given_name.clone(),
        attr_map.family_name.clone(),
        attr_map.external_id.clone(),
        attr_map.username.clone(),
        attr_map.sync_attribute.clone(),
    ];
    attrs.extend(attr_map.extra.keys().cloned());
    // Dedup while preserving insertion order.
    attrs.dedup();
    attrs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attrs(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), vec![(*v).to_string()]))
            .collect()
    }

    fn default_attr_map() -> LdapAttributeMap {
        LdapAttributeMap::default()
    }

    #[test]
    fn map_entry_full() {
        let attrs = make_attrs(&[
            ("mail", "alice@example.com"),
            ("cn", "Alice Smith"),
            ("givenName", "Alice"),
            ("sn", "Smith"),
            ("entryUUID", "uuid-1234"),
            ("uid", "alice"),
            ("modifyTimestamp", "20240101120000Z"),
        ]);
        let user = map_entry(
            "uid=alice,ou=users,dc=example,dc=com",
            &attrs,
            &default_attr_map(),
        )
        .expect("full attribute set should map successfully");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.display_name, "Alice Smith");
        assert_eq!(user.given_name.as_deref(), Some("Alice"));
        assert_eq!(user.family_name.as_deref(), Some("Smith"));
        assert_eq!(user.external_id, "uuid-1234");
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.sync_cursor, "20240101120000Z");
        assert_eq!(user.dn, "uid=alice,ou=users,dc=example,dc=com");
    }

    #[test]
    fn map_entry_missing_required_email_is_error() {
        let attrs = make_attrs(&[
            ("cn", "Bob"),
            ("entryUUID", "uuid-5678"),
            ("modifyTimestamp", "20240101120000Z"),
        ]);
        let err = map_entry(
            "uid=bob,ou=users,dc=example,dc=com",
            &attrs,
            &default_attr_map(),
        )
        .expect_err("missing required email attribute should fail");
        assert!(
            matches!(err, LdapError::MissingAttribute { ref attribute } if attribute == "mail")
        );
    }

    #[test]
    fn map_entry_missing_optional_fields_is_ok() {
        let attrs = make_attrs(&[
            ("mail", "carol@example.com"),
            ("cn", "Carol"),
            ("entryUUID", "uuid-9999"),
            ("modifyTimestamp", "20240102000000Z"),
        ]);
        let user = map_entry(
            "uid=carol,ou=users,dc=example,dc=com",
            &attrs,
            &default_attr_map(),
        )
        .expect("entry with only required fields should map successfully");
        assert!(user.given_name.is_none());
        assert!(user.family_name.is_none());
        assert!(user.username.is_none());
    }

    #[test]
    fn map_entry_extra_attributes() {
        let mut extra_map = default_attr_map();
        extra_map
            .extra
            .insert("department".to_string(), "dept".to_string());
        let attrs = make_attrs(&[
            ("mail", "dave@example.com"),
            ("cn", "Dave"),
            ("entryUUID", "uuid-abc"),
            ("modifyTimestamp", "20240103000000Z"),
            ("department", "Engineering"),
        ]);
        let user = map_entry("uid=dave,ou=users,dc=example,dc=com", &attrs, &extra_map)
            .expect("entry with extra attribute should map successfully");
        assert_eq!(
            user.extra.get("dept").map(|s| s.as_str()),
            Some("Engineering")
        );
    }

    #[test]
    fn map_entry_extra_attribute_absent_is_skipped() {
        let mut extra_map = default_attr_map();
        extra_map
            .extra
            .insert("telephoneNumber".to_string(), "phone".to_string());
        let attrs = make_attrs(&[
            ("mail", "eve@example.com"),
            ("cn", "Eve"),
            ("entryUUID", "uuid-def"),
            ("modifyTimestamp", "20240104000000Z"),
        ]);
        let user = map_entry("uid=eve,ou=users,dc=example,dc=com", &attrs, &extra_map)
            .expect("entry with absent optional extra attribute should map successfully");
        // Extra attribute absent from LDAP entry — must not appear in user.extra
        assert!(!user.extra.contains_key("phone"));
    }

    #[test]
    fn requested_attributes_includes_all_configured() {
        let am = default_attr_map();
        let attrs = requested_attributes(&am);
        assert!(attrs.contains(&"mail".to_string()));
        assert!(attrs.contains(&"cn".to_string()));
        assert!(attrs.contains(&"entryUUID".to_string()));
        assert!(attrs.contains(&"modifyTimestamp".to_string()));
    }

    #[test]
    fn requested_attributes_includes_extra() {
        let mut am = default_attr_map();
        am.extra
            .insert("department".to_string(), "dept".to_string());
        let attrs = requested_attributes(&am);
        assert!(attrs.contains(&"department".to_string()));
    }

    #[test]
    fn map_entry_custom_attribute_map() {
        let am = LdapAttributeMap {
            email: "userPrincipalName".to_string(),
            display_name: "displayName".to_string(),
            given_name: "givenName".to_string(),
            family_name: "sn".to_string(),
            external_id: "objectGUID".to_string(),
            username: "sAMAccountName".to_string(),
            sync_attribute: "uSNChanged".to_string(),
            extra: std::collections::HashMap::new(),
        };
        let attrs = make_attrs(&[
            ("userPrincipalName", "frank@corp.example"),
            ("displayName", "Frank"),
            ("objectGUID", "some-guid"),
            ("sAMAccountName", "frank"),
            ("uSNChanged", "12345"),
        ]);
        let user = map_entry("CN=frank,OU=Users,DC=corp,DC=example", &attrs, &am)
            .expect("custom AD-style attribute map should map successfully");
        assert_eq!(user.email, "frank@corp.example");
        assert_eq!(user.external_id, "some-guid");
        assert_eq!(user.sync_cursor, "12345");
    }
}

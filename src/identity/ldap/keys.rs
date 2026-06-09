//! Storage key encoding for LDAP connector records.

use crate::core::RealmId;

/// Key for the LDAP delta-sync checkpoint for a realm.
///
/// Format: `ldap:cp:{realm_uuid}` — JSON-serialised `LdapSyncCheckpoint`.
/// Stored in WAL under the realm's own namespace.
const LDAP_CHECKPOINT_PREFIX: &str = "ldap:cp:";

/// Encodes the LDAP sync checkpoint key for the given realm.
pub(crate) fn encode_ldap_checkpoint(realm_id: &RealmId) -> Vec<u8> {
    let mut key = LDAP_CHECKPOINT_PREFIX.as_bytes().to_vec();
    key.extend_from_slice(realm_id.as_uuid().as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn checkpoint_key_is_deterministic() {
        let id = RealmId::new(Uuid::nil());
        let k1 = encode_ldap_checkpoint(&id);
        let k2 = encode_ldap_checkpoint(&id);
        assert_eq!(k1, k2);
    }

    #[test]
    fn checkpoint_key_starts_with_prefix() {
        let id = RealmId::new(Uuid::nil());
        let key = encode_ldap_checkpoint(&id);
        assert!(key.starts_with(b"ldap:cp:"));
    }

    #[test]
    fn different_realms_produce_different_keys() {
        let r1 = RealmId::new(Uuid::nil());
        let r2 = RealmId::new(Uuid::new_v4());
        assert_ne!(encode_ldap_checkpoint(&r1), encode_ldap_checkpoint(&r2));
    }
}

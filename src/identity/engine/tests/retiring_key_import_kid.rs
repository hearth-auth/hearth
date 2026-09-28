//! A restore checks a retiring key against the realm's retired records by the
//! kid its key material produces, never by the label the archive gives it
//! (PR #358 follow-up to the GA audit 2026-09-28).
//!
//! `import_retiring_signing_key` refused a key the realm had purged — the
//! remedy for a leaked key — by looking its archive `key_id` up in the retired
//! records. The label is just a string in the archive: the same key material
//! under another label passed the check and was reinstated.

use super::*;

use crate::identity::tokens::SigningKey;

/// Far beyond the test clock, so the grace window is still open.
const DEADLINE_SECS: u64 = 10_000_000_000;

#[test]
fn a_purged_signing_key_is_refused_under_any_archive_label() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let leaked = engine
        .export_realm_signing_key_pkcs8(&realm)
        .expect("export the signing key");
    let leaked_kid = SigningKey::from_pkcs8(&leaked)
        .expect("parse the key")
        .key_id()
        .to_string();

    // A revoking rotation: the key is retired with no grace, and recorded.
    engine
        .rotate_realm_signing_key(&realm, 0)
        .expect("revoking rotation");

    let genuine = RetiringSigningKeyExport {
        key_id: leaked_kid,
        deadline_secs: DEADLINE_SECS,
        pkcs8: leaked.clone(),
    };
    assert!(
        engine
            .import_retiring_signing_key(&realm, &genuine, false)
            .is_err(),
        "precondition: the purged key under its own kid is refused"
    );

    let relabelled = RetiringSigningKeyExport {
        key_id: "relabelled-kid".to_string(),
        ..genuine
    };
    let outcome = engine.import_retiring_signing_key(&realm, &relabelled, false);
    assert!(
        outcome.is_err(),
        "the purged key's material under another archive label was reinstated ({outcome:?})"
    );
}

#[test]
fn a_retiring_key_whose_label_does_not_match_its_material_is_refused() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let material = SigningKey::generate().expect("generate a key");

    let mislabelled = RetiringSigningKeyExport {
        key_id: "not-this-keys-kid".to_string(),
        deadline_secs: DEADLINE_SECS,
        pkcs8: material.pkcs8_bytes().to_vec(),
    };
    let outcome = engine.import_retiring_signing_key(&realm, &mislabelled, false);
    assert!(
        outcome.is_err(),
        "a retiring key stored under a kid its material does not produce can never verify \
         the tokens it is restored for ({outcome:?})"
    );

    let labelled = RetiringSigningKeyExport {
        key_id: material.key_id().to_string(),
        ..mislabelled
    };
    assert_eq!(
        engine
            .import_retiring_signing_key(&realm, &labelled, false)
            .expect("a correctly labelled key imports"),
        ImportOutcome::Created
    );
}

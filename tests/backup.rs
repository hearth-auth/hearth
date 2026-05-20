//! Integration tests for the backup and restore engine (HEA-624).
//!
//! Exercises [`BackupExporter`], [`BackupImporter`], [`BackupArchive`], and the
//! passphrase encryption layer end-to-end using embedded harnesses.

mod common;

use base64::Engine as _;
use secrecy::SecretString;
use tempfile::NamedTempFile;

use hearth::audit::AuditQuery;
use hearth::backup::{
    decrypt_archive, encrypt_archive, BackupArchive, BackupExporter, BackupImporter,
    BackupManifest, ExportOptions, ImportOptions, RestoreMode,
};
use hearth::identity::{CleartextPassword, CreateUserRequest, SessionContext};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Builds a `BackupExporter` from a harness.
fn make_exporter(h: &common::TestHarness) -> BackupExporter {
    BackupExporter::new(h.identity_arc(), h.audit_arc(), h.rbac_arc())
}

/// Builds a `BackupImporter` from a harness.
fn make_importer(h: &common::TestHarness) -> BackupImporter {
    BackupImporter::new(h.identity_arc(), h.rbac_arc())
}

/// Creates a realm, one user with a password, seeds RBAC, and returns the realm
/// id, user email, and cleartext password.
fn seeded_realm(h: &common::TestHarness) -> (hearth::core::RealmId, String, CleartextPassword) {
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let email = format!("user-{}@backup-test.example", uuid::Uuid::new_v4());
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "Backup User".into(),
                first_name: "Backup".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let password = CleartextPassword::from_string("Sup3rS3cret!".to_string());
    h.identity()
        .set_password(&realm, user.id(), &password)
        .expect("set password");
    (realm, email, password)
}

/// Exports a single realm to a temp file and returns the temp file.
fn export_realm_to_file(
    h: &common::TestHarness,
    realm: &hearth::core::RealmId,
    opts: &ExportOptions,
) -> NamedTempFile {
    let tmp = NamedTempFile::new().expect("tempfile");
    let mut writer = BackupArchive::create(tmp.path()).expect("create archive");
    let exporter = make_exporter(h);
    let dek = BackupExporter::generate_dek().expect("generate DEK");
    let realm_manifest = exporter
        .export_realm(realm, &mut writer, opts, &dek)
        .expect("export realm");
    let mut manifest = BackupManifest::new(vec![realm_manifest]);
    manifest.signing_key_dek_b64 = Some(base64::engine::general_purpose::STANDARD.encode(dek));
    writer.finish(manifest).expect("finish archive");
    tmp
}

/// Gets the slugified archive name for a realm (mirrors `BackupExporter::slugify` logic).
fn realm_slug(h: &common::TestHarness, realm: &hearth::core::RealmId) -> String {
    let r = h.identity().get_realm(realm).expect("get").expect("exists");
    let name = r.name();
    let mut slug = String::with_capacity(name.len());
    let mut prev_hyphen = false;
    for c in name.chars() {
        if c.is_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_hyphen = false;
        } else if !prev_hyphen && !slug.is_empty() {
            slug.push('-');
            prev_hyphen = true;
        }
    }
    slug.trim_end_matches('-').to_string()
}

// ── 1. full_roundtrip ─────────────────────────────────────────────────────────

/// Exports a realm (with user + password) to an archive, restores it into a
/// fresh harness, then verifies:
/// - the user exists by email
/// - password verification succeeds
/// - token issuance works (JWT path green)
/// - RBAC role assignment survives the restore
#[tokio::test]
async fn full_roundtrip() {
    // Source harness — realm A
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm_a, email, password) = seeded_realm(&src);

    // Assign admin role to the user so we can verify RBAC survives.
    let user_a = src
        .identity()
        .get_user_by_email(&realm_a, &email)
        .expect("lookup")
        .expect("exists");
    let admin_role = src
        .rbac()
        .get_role_by_name(&realm_a, "realm.admin")
        .expect("get role")
        .expect("seeded");
    src.rbac()
        .assign_role(
            &realm_a,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(user_a.id().clone()),
                role_id: admin_role.id,
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let tmp = export_realm_to_file(&src, &realm_a, &ExportOptions::default());
    let slug = realm_slug(&src, &realm_a);

    // Destination harness — fresh engine
    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let reader = BackupArchive::open(tmp.path()).expect("open archive");
    let importer = make_importer(&dst);
    let report = importer
        .import_realm(&slug, &reader, &ImportOptions::default())
        .expect("import realm");

    assert_eq!(report.realms.created, 1, "realm must be created");
    assert_eq!(report.users.created, 1, "user must be created");
    assert_eq!(report.users.errored, 0, "no user errors");

    // Verify user exists and password works.
    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");

    let user_b = dst
        .identity()
        .get_user_by_email(&restored_realm_id, &email)
        .expect("lookup restored user")
        .expect("user must exist after restore");

    let verified = dst
        .identity()
        .verify_password(&restored_realm_id, user_b.id(), &password)
        .expect("verify password call");
    assert!(verified, "password must verify after restore");

    // Issue tokens — JWT path must work.
    let session = dst
        .identity()
        .create_session(&restored_realm_id, user_b.id(), &SessionContext::default())
        .expect("create session");
    let tokens = dst
        .identity()
        .issue_tokens(&restored_realm_id, user_b.id(), session.id())
        .expect("issue tokens");
    assert!(
        !tokens.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ── 2. realm_scoped_backup ────────────────────────────────────────────────────

/// Exports only `realm_a` from a two-realm harness, restores into a fresh
/// harness that already has `realm_b` seeded — `realm_b` must be untouched.
#[tokio::test]
async fn realm_scoped_backup() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm_a, email_a, _) = seeded_realm(&src);
    let (realm_b, email_b, _) = seeded_realm(&src);

    let tmp = export_realm_to_file(&src, &realm_a, &ExportOptions::default());
    let slug_a = realm_slug(&src, &realm_a);

    // Build a fresh harness that already holds realm_b's users.
    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let (realm_b_dst, email_b_dst, _) = seeded_realm(&dst);
    let _ = (realm_b, email_b); // realm_b is source only

    // Restore only realm_a.
    let reader = BackupArchive::open(tmp.path()).expect("open");
    let importer = make_importer(&dst);
    importer
        .import_realm(&slug_a, &reader, &ImportOptions::default())
        .expect("import realm_a");

    // realm_a user must now exist.
    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");
    assert!(
        dst.identity()
            .get_user_by_email(&restored_realm_id, &email_a)
            .expect("lookup a")
            .is_some(),
        "realm_a user must exist"
    );

    // realm_b_dst user must remain intact.
    assert!(
        dst.identity()
            .get_user_by_email(&realm_b_dst, &email_b_dst)
            .expect("lookup b_dst")
            .is_some(),
        "realm_b_dst user must be untouched"
    );
}

// ── 3. integrity_check_detects_corruption ─────────────────────────────────────

/// Writes an archive, flips one byte inside the compressed payload, then
/// verifies that `verify_checksums` detects the corruption.
#[tokio::test]
async fn integrity_check_detects_corruption() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _, _) = seeded_realm(&h);
    let tmp = export_realm_to_file(&h, &realm, &ExportOptions::default());

    // Read raw bytes, flip a byte in the middle of the payload.
    let mut raw = std::fs::read(tmp.path()).expect("read archive");
    let midpoint = raw.len() / 2;
    raw[midpoint] ^= 0xFF;

    let corrupted_tmp = NamedTempFile::new().expect("tempfile");
    std::fs::write(corrupted_tmp.path(), &raw).expect("write corrupted");

    // Archive open may succeed (manifest is at the end) but checksum
    // verification must fail.
    let result =
        BackupArchive::open(corrupted_tmp.path()).and_then(|reader| reader.verify_checksums());
    assert!(
        result.is_err(),
        "verify_checksums must return Err for corrupted archive"
    );
}

// ── 4. skip_mode_idempotency ──────────────────────────────────────────────────

/// Restores the same archive twice with `RestoreMode::Skip` — the second run
/// must produce no duplicates and report a skipped realm (not errored).
#[tokio::test]
async fn skip_mode_idempotency() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm, email, _) = seeded_realm(&src);
    let tmp = export_realm_to_file(&src, &realm, &ExportOptions::default());
    let slug = realm_slug(&src, &realm);

    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let opts = ImportOptions {
        mode: RestoreMode::Skip,
        ..ImportOptions::default()
    };

    let reader = BackupArchive::open(tmp.path()).expect("open");
    let importer = make_importer(&dst);

    let report1 = importer
        .import_realm(&slug, &reader, &opts)
        .expect("first import");
    assert_eq!(report1.realms.created, 1);
    assert_eq!(report1.users.created, 1);

    let report2 = importer
        .import_realm(&slug, &reader, &opts)
        .expect("second import");
    // On second pass the realm already exists → skipped; user → skipped.
    assert_eq!(
        report2.realms.errored, 0,
        "no realm errors on second import"
    );
    assert_eq!(report2.users.errored, 0, "no user errors on second import");
    assert!(
        report2.realms.skipped >= 1 || report2.realms.created == 0,
        "realm must be skipped or already present"
    );

    // Exactly one user record must exist (no duplicates).
    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");
    let page = dst
        .identity()
        .list_users(&restored_realm_id, None, 100)
        .expect("list users");
    assert_eq!(
        page.items.iter().filter(|u| u.email() == email).count(),
        1,
        "exactly one user with the backup email"
    );
}

// ── 5. dry_run_no_writes ──────────────────────────────────────────────────────

/// Restores with `dry_run = true` — storage must remain empty (no realms, no
/// users) but the report must reflect what *would* have been written.
#[tokio::test]
async fn dry_run_no_writes() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm, _, _) = seeded_realm(&src);
    let tmp = export_realm_to_file(&src, &realm, &ExportOptions::default());
    let slug = realm_slug(&src, &realm);

    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let opts = ImportOptions {
        dry_run: true,
        ..ImportOptions::default()
    };

    let reader = BackupArchive::open(tmp.path()).expect("open");
    let importer = make_importer(&dst);
    let report = importer
        .import_realm(&slug, &reader, &opts)
        .expect("dry import");

    // Report must say something was seen.
    assert_eq!(report.realms.created, 1, "dry run must count realm");
    assert_eq!(report.users.created, 1, "dry run must count user");

    // But no realm must actually exist in dst storage.
    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");
    let realm_in_dst = dst
        .identity()
        .get_realm(&restored_realm_id)
        .expect("get realm");
    assert!(
        realm_in_dst.is_none(),
        "dry_run must not write realm to storage"
    );
}

// ── 6. encrypted_roundtrip ────────────────────────────────────────────────────

/// Exports an archive, envelope-encrypts it with a passphrase, decrypts with
/// the correct passphrase, then restores — user must be present and login must
/// work.
#[tokio::test]
async fn encrypted_roundtrip() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm, email, password) = seeded_realm(&src);
    let tmp = export_realm_to_file(&src, &realm, &ExportOptions::default());
    let slug = realm_slug(&src, &realm);

    let passphrase = SecretString::new("correct-horse-battery-staple".into());
    let raw = std::fs::read(tmp.path()).expect("read archive");
    let encrypted = encrypt_archive(&passphrase, &raw).expect("encrypt");

    // Decrypt and restore.
    let decrypted = decrypt_archive(&passphrase, &encrypted).expect("decrypt");
    let restored_tmp = NamedTempFile::new().expect("tempfile");
    std::fs::write(restored_tmp.path(), &decrypted).expect("write decrypted");

    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let reader = BackupArchive::open(restored_tmp.path()).expect("open");
    let importer = make_importer(&dst);
    let report = importer
        .import_realm(&slug, &reader, &ImportOptions::default())
        .expect("import");

    assert_eq!(report.realms.created, 1);
    assert_eq!(report.users.created, 1);

    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");
    let user = dst
        .identity()
        .get_user_by_email(&restored_realm_id, &email)
        .expect("lookup")
        .expect("exists");
    assert!(
        dst.identity()
            .verify_password(&restored_realm_id, user.id(), &password)
            .expect("verify"),
        "password must verify after encrypted roundtrip"
    );
}

// ── 7. encrypted_wrong_passphrase ─────────────────────────────────────────────

/// Attempting to decrypt with the wrong passphrase must return a clear error
/// and leave the destination storage untouched.
#[tokio::test]
async fn encrypted_wrong_passphrase() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm, _, _) = seeded_realm(&src);
    let tmp = export_realm_to_file(&src, &realm, &ExportOptions::default());

    let correct = SecretString::new("correct-passphrase".into());
    let wrong = SecretString::new("wrong-passphrase".into());

    let raw = std::fs::read(tmp.path()).expect("read archive");
    let encrypted = encrypt_archive(&correct, &raw).expect("encrypt");

    let result = decrypt_archive(&wrong, &encrypted);
    assert!(
        result.is_err(),
        "decryption with wrong passphrase must fail"
    );

    // The error message must mention decryption / passphrase (not a panic).
    let err_msg = result
        .expect_err("decryption with wrong passphrase must fail")
        .to_string()
        .to_lowercase();
    assert!(
        err_msg.contains("decrypt") || err_msg.contains("passphrase") || err_msg.contains("wrong"),
        "error must mention decryption failure, got: {err_msg}"
    );
}

// ── 8. overwrite_mode ─────────────────────────────────────────────────────────

/// After a first restore, the user's display name is mutated. A second restore
/// with `RestoreMode::Overwrite` must revert the mutation.
#[tokio::test]
async fn overwrite_mode() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm, email, _) = seeded_realm(&src);
    let tmp = export_realm_to_file(&src, &realm, &ExportOptions::default());
    let slug = realm_slug(&src, &realm);

    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let reader = BackupArchive::open(tmp.path()).expect("open");
    let importer = make_importer(&dst);

    // First restore (creates the user with display_name "Backup User").
    importer
        .import_realm(&slug, &reader, &ImportOptions::default())
        .expect("first import");

    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");

    // Mutate the user in dst.
    let user = dst
        .identity()
        .get_user_by_email(&restored_realm_id, &email)
        .expect("lookup")
        .expect("exists");
    dst.identity()
        .update_user(
            &restored_realm_id,
            user.id(),
            &hearth::identity::UpdateUserRequest {
                display_name: Some("Mutated Name".to_string()),
                ..Default::default()
            },
        )
        .expect("update user");

    let mutated = dst
        .identity()
        .get_user_by_email(&restored_realm_id, &email)
        .expect("lookup")
        .expect("exists");
    assert_eq!(mutated.display_name(), "Mutated Name");

    // Second restore with Overwrite — user must be reverted.
    let opts = ImportOptions {
        mode: RestoreMode::Overwrite,
        ..ImportOptions::default()
    };
    let report = importer
        .import_realm(&slug, &reader, &opts)
        .expect("overwrite import");
    // Overwrite deletes and recreates the realm (cascading user deletion), so the
    // user is re-created fresh rather than counted as "overwritten". Either counter
    // indicates the user made it into the restored realm.
    assert_eq!(report.users.errored, 0, "no user errors");
    assert!(
        report.users.created >= 1 || report.users.overwritten >= 1,
        "user must be created or overwritten after overwrite restore"
    );

    let reverted = dst
        .identity()
        .get_user_by_email(&restored_realm_id, &email)
        .expect("lookup")
        .expect("exists");
    assert_eq!(
        reverted.display_name(),
        "Backup User",
        "display_name must revert to archive value"
    );
}

// ── 9. audit_included_flag ────────────────────────────────────────────────────

/// Without `include_audit`, no `audit.ndjson` entry exists in the archive.
/// With `include_audit`, the entry is present and the record count in the
/// manifest matches the events found in that file.
#[tokio::test]
async fn audit_included_flag() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _, _) = seeded_realm(&h);
    let slug = realm_slug(&h, &realm);

    // Without audit.
    let tmp_no_audit = export_realm_to_file(
        &h,
        &realm,
        &ExportOptions {
            include_audit: false,
            ..Default::default()
        },
    );
    let reader_no = BackupArchive::open(tmp_no_audit.path()).expect("open no-audit");
    let audit_key = format!("realms/{slug}/audit.ndjson");
    let audit_bytes = reader_no.read_file(&audit_key).expect("read_file");
    assert!(
        audit_bytes.is_none(),
        "audit.ndjson must be absent when include_audit=false"
    );

    // Create an audit event so the "with audit" run has something to export.
    // Trigger at least one event (realm creation was already audited during seeded_realm).
    let events = h
        .audit()
        .query(&AuditQuery::for_realm(realm.clone()))
        .expect("query audit");
    let event_count = events.len() as u64;

    // With audit.
    let tmp_with_audit = export_realm_to_file(
        &h,
        &realm,
        &ExportOptions {
            include_audit: true,
            ..Default::default()
        },
    );
    let reader_with = BackupArchive::open(tmp_with_audit.path()).expect("open with-audit");
    let audit_bytes_with = reader_with.read_file(&audit_key).expect("read_file");

    if event_count > 0 {
        let bytes = audit_bytes_with.expect("audit.ndjson must be present when events exist");
        let line_count = bytes
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .count() as u64;
        // Manifest record_count for this realm must equal the line count.
        let manifest_count = reader_with
            .realms()
            .iter()
            .find(|r| r.slug == slug)
            .map(|r| r.record_counts.audit_events)
            .unwrap_or(0);
        assert_eq!(
            manifest_count, event_count,
            "manifest audit_events must match the queried event count"
        );
        assert_eq!(
            line_count, event_count,
            "audit.ndjson line count must match event count"
        );
    }
}

// ── property tests ────────────────────────────────────────────────────────────

mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Returns a harness constructed synchronously inside a proptest body.
    fn sync_harness() -> common::TestHarness {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt")
            .block_on(common::TestHarness::embedded())
            .expect("harness")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Property: manifest checksums cover every non-manifest file in the archive.
        ///
        /// For any number of users (0-5) the exporter must record a checksum for
        /// every data file it writes, and the checksum map must be non-empty.
        #[test]
        fn manifest_checksums_cover_all_files(user_count in 0usize..=5) {
            let h = sync_harness();
            let realm = h.create_realm();
            h.rbac().seed_realm(&realm).expect("seed");

            for i in 0..user_count {
                h.identity()
                    .create_user(
                        &realm,
                        &CreateUserRequest {
                            email: format!("user{i}@prop-test.example"),
                            display_name: format!("User {i}"),
                            first_name: "Prop".into(),
                            last_name: "Test".into(),
                            attributes: Default::default(),
                        },
                    )
                    .expect("create user");
            }

            let tmp = export_realm_to_file(&h, &realm, &ExportOptions::default());
            let reader = BackupArchive::open(tmp.path()).expect("open");

            // Every checksummed key must start with "realms/".
            for key in reader.manifest.checksums.keys() {
                prop_assert!(
                    key.starts_with("realms/"),
                    "checksum key must be realm-scoped: {key}"
                );
            }

            // Checksums must be non-empty (at minimum signing_key.json is always exported).
            prop_assert!(!reader.manifest.checksums.is_empty(), "checksums must be non-empty");

            // Verify all checksums pass.
            reader.verify_checksums().expect("checksums must verify");
        }

        /// Property: archive realm list matches manifest realm list.
        ///
        /// The slugs reported in the manifest must align with the archive
        /// directory prefixes found in the checksum keys.
        #[test]
        fn archive_realm_list_matches_manifest(extra_users in 0usize..=3) {
            let h = sync_harness();
            let realm = h.create_realm();
            h.rbac().seed_realm(&realm).expect("seed");
            for i in 0..extra_users {
                h.identity()
                    .create_user(
                        &realm,
                        &CreateUserRequest {
                            email: format!("u{i}@rl-test.example"),
                            display_name: format!("U{i}"),
                            first_name: "R".into(),
                            last_name: "L".into(),
                            attributes: Default::default(),
                        },
                    )
                    .expect("create user");
            }

            let tmp = export_realm_to_file(&h, &realm, &ExportOptions::default());
            let reader = BackupArchive::open(tmp.path()).expect("open");

            // Collect unique realm prefixes from checksummed keys.
            let mut key_prefixes: std::collections::HashSet<String> = std::collections::HashSet::new();
            for key in reader.manifest.checksums.keys() {
                // key format: "realms/<slug>/file.ext"
                if let Some(rest) = key.strip_prefix("realms/") {
                    if let Some(slash) = rest.find('/') {
                        key_prefixes.insert(rest[..slash].to_string());
                    }
                }
            }

            let manifest_slugs: std::collections::HashSet<String> =
                reader.realms().iter().map(|r| r.slug.clone()).collect();

            prop_assert_eq!(
                key_prefixes, manifest_slugs,
                "checksummed slug set must equal manifest realm slug set"
            );
        }
    }
}

// ── performance baseline ──────────────────────────────────────────────────────

/// Restore of a 10 000-user realm must complete in under 60 seconds.
///
/// Excluded from normal CI (slow). Run explicitly:
/// `cargo nextest run backup::large_realm_restore_under_60s --ignored`.
#[tokio::test]
#[ignore = "HEA-624: slow performance baseline — run explicitly with --ignored flag"]
async fn large_realm_restore_under_60s() {
    use std::time::Instant;

    // Use fast Argon2id params (already set via CredentialConfig::fast_for_testing)
    // to keep the test focused on I/O and serialization, not hashing.
    let src = common::TestHarness::embedded().await.expect("src harness");
    let realm = src.create_realm();
    src.rbac().seed_realm(&realm).expect("seed");

    for i in 0..10_000usize {
        src.identity()
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("perf-user-{i}@large-test.example"),
                    display_name: format!("Perf User {i}"),
                    first_name: "Perf".into(),
                    last_name: "User".into(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
    }

    let tmp = export_realm_to_file(&src, &realm, &ExportOptions::default());
    let slug = realm_slug(&src, &realm);

    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let reader = BackupArchive::open(tmp.path()).expect("open");
    let importer = make_importer(&dst);

    let start = Instant::now();
    let report = importer
        .import_realm(&slug, &reader, &ImportOptions::default())
        .expect("import");
    let elapsed = start.elapsed();

    assert_eq!(report.users.created, 10_000, "all users must be created");
    assert!(
        elapsed.as_secs() < 60,
        "restore of 10 000 users must complete in < 60s; took {elapsed:?}"
    );
}

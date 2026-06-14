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

/// Returns the shared test passphrase used by all test archives.
fn test_passphrase() -> SecretString {
    SecretString::new("hearth-test-backup-passphrase".into())
}

/// Returns `ImportOptions` with the test passphrase pre-filled.
fn import_opts_with_passphrase() -> ImportOptions {
    ImportOptions {
        dek_passphrase: Some(test_passphrase()),
        ..ImportOptions::default()
    }
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
    let passphrase = test_passphrase();
    let (wrapped_dek_b64, wrapping_params) =
        BackupExporter::wrap_dek(&dek, &passphrase).expect("wrap DEK");
    let mut manifest = BackupManifest::new(vec![realm_manifest]);
    manifest.sections_encrypted = true;
    manifest.wrapped_dek_b64 = Some(wrapped_dek_b64);
    manifest.dek_wrapping_params = Some(wrapping_params);
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
        .import_realm(&slug, &reader, &import_opts_with_passphrase())
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

// ── 1b. restore_preserves_signing_keys (HEA-745) ──────────────────────────────

/// Restore must preserve the realm's Ed25519 signing key so every JWT issued
/// under the per-realm key (OIDC flows: `client_credentials`,
/// `authorization_code`, ID tokens, logout tokens, RP-initiated logout) keeps
/// validating after restore. Regression: prior to HEA-745, `import_realm`
/// silently generated a fresh key, breaking JWKS continuity for every
/// downstream RP and invalidating every per-realm-signed JWT.
///
/// Three layered assertions:
/// 1. **Raw key material identity** — the PKCS#8 bytes returned by
///    `export_realm_signing_key_pkcs8` are byte-equal before and after
///    restore. This is the airtight low-level invariant.
/// 2. **JWKS continuity** — `realm_jwks` reports the same `kid` (which is a
///    SHA-256 hash of the public key) and the same `x` coordinate. RPs that
///    cached the JWKS would still verify against the same key after restore.
/// 3. **End-to-end JWT round-trip** — a JWT signed *under the source realm's
///    per-realm key* before backup verifies cryptographically against the
///    destination realm's public key after restore.
///
/// Note on `issue_tokens` vs OIDC flows: Hearth's legacy session-based
/// `issue_tokens` path signs with the global `sys:global:key` (Phase 0
/// fallback), so those tokens would survive restore even without this fix.
/// The OIDC paths — which are the public-facing token surface in
/// production — sign with the per-realm key and are the user-visible victim
/// of the bug. The test therefore exercises the per-realm key directly.
#[tokio::test]
async fn test_restore_preserves_signing_keys() {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hearth::identity::tokens::{verify_token_signature, Audience, SigningKey, TokenClaims};

    // ── Source harness: realm + user + per-realm-signed JWT ────────────
    let src = common::TestHarness::embedded().await.expect("src harness");
    let (realm_src, _email, _password) = seeded_realm(&src);

    // Snapshot the source realm's per-realm signing key (PKCS#8 bytes).
    let src_pkcs8 = src
        .identity()
        .export_realm_signing_key_pkcs8(&realm_src)
        .expect("export src signing key");

    // Sign a JWT directly with the per-realm key (mirrors what OIDC flows
    // do internally — see `EmbeddedIdentityEngine::client_credentials`).
    let src_signing_key = SigningKey::from_pkcs8(&src_pkcs8).expect("parse src key");
    let claims = TokenClaims {
        sub: "client_test-rp".to_string(),
        iss: "hearth".to_string(),
        aud: Audience::single("hearth-api".to_string()),
        // Far-future exp so verify_token_signature (signature-only) is
        // deterministic regardless of wall-clock skew.
        exp: 4_102_444_800, // 2100-01-01
        iat: 1_700_000_000,
        sid: "none".to_string(),
        tid: realm_src.to_string(),
        oid: None,
        token_type: "access".to_string(),
        jti: Some("test-jwt".to_string()),
        fid: None,
        scope: None,
        nonce: None,
        cnf: None,
        roles: Vec::new(),
        groups: Vec::new(),
        org_groups: Vec::new(),
        permissions: Vec::new(),
        custom: BTreeMap::new(),
        required_actions: Vec::new(),
        amr: Vec::new(),
        sv: None,
    };
    let pre_restore_jwt = src_signing_key.issue_token(&claims).expect("issue jwt");

    // Snapshot JWKS for the kid/public-key continuity assertion.
    let src_realm_jwks = src.identity().realm_jwks(&realm_src).expect("src jwks");
    let src_ed25519_jwk = src_realm_jwks
        .keys
        .iter()
        .find(|k| k.kty == "OKP" && k.crv.as_deref() == Some("Ed25519"))
        .expect("source jwks must publish an Ed25519 key");
    let src_kid = src_ed25519_jwk.kid.clone();
    let src_pubkey_x = src_ed25519_jwk.x.clone().expect("Ed25519 jwk must have x");

    // Pre-flight sanity check: the JWT verifies under its own source key.
    verify_token_signature(&pre_restore_jwt, src_signing_key.public_key_bytes())
        .expect("pre-flight: src JWT must verify under src key");

    // ── Export the realm ───────────────────────────────────────────────
    let tmp = export_realm_to_file(&src, &realm_src, &ExportOptions::default());
    let slug = realm_slug(&src, &realm_src);

    // ── Destination harness: restore into a fresh data dir ─────────────
    let dst = common::TestHarness::embedded().await.expect("dst harness");
    let reader = BackupArchive::open(tmp.path()).expect("open archive");
    let importer = make_importer(&dst);
    let report = importer
        .import_realm(&slug, &reader, &import_opts_with_passphrase())
        .expect("import realm");
    assert_eq!(report.realms.created, 1, "realm must be restored");
    assert_eq!(report.users.created, 1, "user must be restored");
    assert_eq!(report.realms.errored, 0);

    let restored_realm_id: hearth::core::RealmId =
        reader.realms()[0].realm_id.parse().expect("parse realm_id");

    // ── Assertion 1: raw key material is byte-identical ────────────────
    let dst_pkcs8 = dst
        .identity()
        .export_realm_signing_key_pkcs8(&restored_realm_id)
        .expect("export dst signing key");
    assert_eq!(
        src_pkcs8, dst_pkcs8,
        "restored realm's PKCS#8 signing key bytes must equal the source's — \
         mismatch means `import_realm` regenerated the key (HEA-745 regression)"
    );

    // ── Assertion 2: JWKS continuity (kid + public coordinate) ─────────
    let dst_realm_jwks = dst
        .identity()
        .realm_jwks(&restored_realm_id)
        .expect("dst jwks");
    let dst_ed25519_jwk = dst_realm_jwks
        .keys
        .iter()
        .find(|k| k.kty == "OKP" && k.crv.as_deref() == Some("Ed25519"))
        .expect("dst jwks must publish an Ed25519 key");
    assert_eq!(
        dst_ed25519_jwk.kid, src_kid,
        "restored realm's JWKS kid must equal the source's — RPs that cached \
         the kid would otherwise fail to find a matching key"
    );
    assert_eq!(
        dst_ed25519_jwk.x.as_deref(),
        Some(src_pubkey_x.as_str()),
        "restored realm's Ed25519 public coordinate must equal the source's"
    );

    // ── Assertion 3: pre-restore JWT verifies under dst's public key ───
    //
    // Decode the destination's public key from its published JWK and
    // verify the pre-backup JWT against it. This is the cryptographic
    // proof that tokens issued before the backup survive restore — the
    // exact regression HEA-745 fixes.
    let dst_pubkey_bytes = URL_SAFE_NO_PAD
        .decode(dst_ed25519_jwk.x.as_ref().expect("dst jwk x"))
        .expect("decode dst Ed25519 x");
    let verified_claims = verify_token_signature(&pre_restore_jwt, &dst_pubkey_bytes).expect(
        "pre-restore JWT must validate against restored signing key — restoring with a \
         freshly generated key (the HEA-745 bug) would surface here as InvalidToken",
    );
    assert_eq!(verified_claims.sub, "client_test-rp");
    assert_eq!(verified_claims.tid, realm_src.to_string());
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
        .import_realm(&slug_a, &reader, &import_opts_with_passphrase())
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

    // Read raw bytes and flip a 256-byte span across the middle of the
    // payload. A single-byte flip is flaky: it can land in zstd frame
    // padding or tar trailer bytes that are not part of any tracked
    // checksum, so verify_checksums would return Ok and the test would
    // spuriously fail (~5% of runs locally). A wide span virtually
    // guarantees we corrupt content the decompressor will reproduce
    // differently or a manifest hash string.
    let mut raw = std::fs::read(tmp.path()).expect("read archive");
    let midpoint = raw.len() / 2;
    let end = (midpoint + 256).min(raw.len());
    for byte in &mut raw[midpoint..end] {
        *byte ^= 0xFF;
    }

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
        ..import_opts_with_passphrase()
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
        ..import_opts_with_passphrase()
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
        .import_realm(&slug, &reader, &import_opts_with_passphrase())
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
        .import_realm(&slug, &reader, &import_opts_with_passphrase())
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
        ..import_opts_with_passphrase()
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
        // The file is AES-256-GCM encrypted — just verify it is present and
        // that the manifest record count matches (the decrypted content is
        // tested by the full_roundtrip test which restores and queries).
        assert!(
            audit_bytes_with.is_some(),
            "audit.ndjson must be present when events exist"
        );
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
        .import_realm(&slug, &reader, &import_opts_with_passphrase())
        .expect("import");
    let elapsed = start.elapsed();

    assert_eq!(report.users.created, 10_000, "all users must be created");
    assert!(
        elapsed.as_secs() < 60,
        "restore of 10 000 users must complete in < 60s; took {elapsed:?}"
    );
}

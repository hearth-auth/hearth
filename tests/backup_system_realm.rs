//! Restoring the system realm (the nil-UUID realm that holds every
//! operator-console account).
//!
//! An unfiltered backup has carried the system realm since task 26.39, but
//! restore refused it (`operation not permitted on the system realm:
//! import_realm`) and aborted. After a rebuild or a disaster recovery there was
//! then no supported way back into the operator console: the first-run setup
//! link is only issued while the store holds no realm, and no CLI command
//! creates an operator.
//!
//! These tests drive the library restore path end to end: export the system
//! realm from one store, restore it into another, and prove the operator can
//! authenticate with the original credentials, keeps their second factor and
//! their `realm.admin` grant, and that the system signing key came back.

mod common;

use base64::Engine as _;
use secrecy::SecretString;
use tempfile::NamedTempFile;

use hearth::backup::{
    BackupArchive, BackupError, BackupExporter, BackupImporter, BackupManifest, ExportOptions,
    ImportOptions, ImportReport, RestoreMode,
};
use hearth::core::{RealmId, UserId};
use hearth::identity::{CleartextPassword, CreateUserRequest, SessionContext};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};

/// The archive slug the exporter gives the system realm (`slugify("system")`).
const SYSTEM_SLUG: &str = "system";

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn test_passphrase() -> SecretString {
    SecretString::new("hearth-system-realm-restore-test".into())
}

fn opts(mode: RestoreMode) -> ImportOptions {
    ImportOptions {
        mode,
        dek_passphrase: Some(test_passphrase()),
        ..ImportOptions::default()
    }
}

fn importer(h: &common::TestHarness) -> BackupImporter {
    BackupImporter::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
}

/// Creates an operator in the system realm exactly as first-run setup does:
/// `create_admin_user`, a password, and the `realm.admin` grant.
fn seed_operator(h: &common::TestHarness, email: &str, password: &str) -> UserId {
    let sys = system_realm();
    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: email.to_string(),
            display_name: "Operator".into(),
            ..Default::default()
        })
        .expect("operator account in the system realm");
    h.identity()
        .set_password(
            &sys,
            user.id(),
            &CleartextPassword::from_string(password.to_string()),
        )
        .expect("set operator password");
    h.rbac().seed_realm(&sys).expect("seed system realm roles");
    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("look up realm.admin")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            &sys,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("grant realm.admin");
    user.id().clone()
}

/// Exports the given realms into one encrypted archive.
fn export(h: &common::TestHarness, realms: &[RealmId]) -> NamedTempFile {
    let tmp = NamedTempFile::new().expect("tempfile");
    let mut writer = BackupArchive::create(tmp.path()).expect("create archive");
    let exporter = BackupExporter::new(h.identity_arc(), h.audit_arc(), h.rbac_arc());
    let dek = BackupExporter::generate_dek().expect("DEK");
    let mut manifests = Vec::new();
    for realm in realms {
        manifests.push(
            exporter
                .export_realm(realm, &mut writer, &ExportOptions::default(), &dek)
                .expect("export realm"),
        );
    }
    let (wrapped, params) = BackupExporter::wrap_dek(&dek, &test_passphrase()).expect("wrap DEK");
    let mut manifest = BackupManifest::new(manifests);
    manifest.sections_encrypted = true;
    manifest.wrapped_dek_b64 = Some(wrapped);
    manifest.dek_wrapping_params = Some(params);
    writer.finish(manifest).expect("finish archive");
    tmp
}

fn system_key(h: &common::TestHarness) -> Vec<u8> {
    h.identity()
        .export_realm_signing_key_pkcs8(&system_realm())
        .expect("system signing key")
}

fn password_ok(h: &common::TestHarness, email: &str, password: &str) -> bool {
    let sys = system_realm();
    let Some(user) = h
        .identity()
        .get_user_by_email(&sys, email)
        .expect("look up operator")
    else {
        return false;
    };
    h.identity()
        .verify_password(
            &sys,
            user.id(),
            &CleartextPassword::from_string(password.to_string()),
        )
        .expect("verify_password")
}

fn restore(
    dst: &common::TestHarness,
    archive: &NamedTempFile,
    opts: &ImportOptions,
) -> Result<ImportReport, BackupError> {
    let reader = BackupArchive::open(archive.path()).expect("open archive");
    importer(dst).import_realm(SYSTEM_SLUG, &reader, opts)
}

fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// Rewrites an archive with one member removed, `manifest.json` untouched.
fn strip_member(src: &std::path::Path, drop_path: &str) -> NamedTempFile {
    use std::io::Read as _;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let decoder = zstd::Decoder::new(std::fs::File::open(src).expect("open")).expect("zstd");
    let mut dropped = false;
    for entry in tar::Archive::new(decoder).entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let path = entry.path().expect("path").to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("read");
        if path == drop_path {
            dropped = true;
        } else {
            entries.push((path, bytes));
        }
    }
    assert!(
        dropped,
        "member '{drop_path}' must have been in the archive"
    );
    let out = NamedTempFile::new().expect("tempfile");
    let encoder =
        zstd::Encoder::new(std::fs::File::create(out.path()).expect("create"), 0).expect("enc");
    let mut builder = tar::Builder::new(encoder);
    for (path, bytes) in &entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes.as_slice())
            .expect("append");
    }
    builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish zstd");
    out
}

// ── Full recovery into a fresh store ──────────────────────────────────────────

/// The disaster-recovery case: a fresh data directory (whose system realm was
/// seeded, with a throwaway key and no operator, when the engine opened it)
/// receives the system realm from a backup. The operator must be able to
/// authenticate with the ORIGINAL password, keep their TOTP factor and their
/// `realm.admin` grant, and the system realm must sign with the ORIGINAL key so
/// a token issued before the backup still verifies against its JWKS.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_restored_system_realm_brings_back_operators_their_factors_and_the_signing_key() {
    let sys = system_realm();
    let src = common::TestHarness::embedded().await.expect("src");
    let email = "operator@hearth.test";
    let password = "Operat0r-Pa55word!";
    let op = seed_operator(&src, email, password);

    // Second factor on the operator.
    let enrollment = src.identity().enroll_totp(&sys, &op).expect("enroll totp");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    src.identity()
        .verify_totp_enrollment(
            &sys,
            &op,
            &compute_totp_code(&enrollment.secret_base32, now_secs),
        )
        .expect("activate totp");

    // A system-realm token issued before the backup.
    let session = src
        .identity()
        .create_session(&sys, &op, &SessionContext::default())
        .expect("session");
    let pre_backup_token = src
        .identity()
        .issue_tokens(&sys, &op, session.id())
        .expect("issue")
        .access_token()
        .to_string();
    let src_key = system_key(&src);

    let archive = export(&src, std::slice::from_ref(&sys));

    let dst = common::TestHarness::embedded().await.expect("dst");
    assert_ne!(
        system_key(&dst),
        src_key,
        "precondition: a fresh store seeds its own system key"
    );
    let report = restore(&dst, &archive, &opts(RestoreMode::Skip))
        .expect("the system realm must restore — it used to abort with SystemRealmProtected");

    assert_eq!(report.users.created, 1, "the operator account is restored");
    assert_eq!(report.users.errored, 0);
    assert_eq!(report.mfa_factors.created, 1, "the operator's TOTP factor");
    assert_eq!(report.mfa_factors.errored, 0);
    assert!(report.assignments.created >= 1, "the realm.admin grant");
    assert_eq!(report.assignments.errored, 0);
    assert_eq!(
        report.realms.created, 1,
        "the system realm's key replaced the unused seeded one"
    );
    assert_eq!(report.realms.errored, 0);

    // Credentials.
    assert!(
        password_ok(&dst, email, password),
        "the operator must sign in with the original password"
    );
    let restored = dst
        .identity()
        .get_user_by_email(&sys, email)
        .expect("lookup")
        .expect("operator restored");
    assert_eq!(restored.id(), &op, "the operator keeps its id");
    assert!(
        dst.identity().mfa_enabled(&sys, &op).expect("mfa_enabled"),
        "the second factor must come back"
    );
    let next_code = compute_totp_code(&enrollment.secret_base32, now_secs + 30);
    dst.identity()
        .verify_totp(&sys, &op, &next_code)
        .expect("the restored TOTP secret must verify");

    // Authorization: the realm.admin grant the console checks.
    let admin_role = dst
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin restored");
    let grants = dst
        .rbac()
        .list_user_assignments(&sys, &op)
        .expect("assignments");
    assert!(
        grants.iter().any(|a| a.role_id == admin_role.id),
        "the operator must still hold realm.admin in the system realm"
    );

    // Signing key: byte-identical, and a pre-backup token verifies against the
    // restored system realm's published key.
    assert_eq!(
        system_key(&dst),
        src_key,
        "the archived system signing key must replace the seeded one"
    );
    let jwks = dst.identity().realm_jwks(&sys).expect("system jwks");
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kty == "OKP")
        .expect("Ed25519 key published");
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk.x.as_deref().expect("x"))
        .expect("decode x");
    let claims = hearth::identity::tokens::verify_token_signature(&pre_backup_token, &public)
        .expect("a system token issued before the backup must verify after the restore");
    assert_eq!(claims.tid, sys.to_string());

    // The system realm stays invisible to realm listings.
    let listed = dst
        .identity()
        .list_realms(&hearth::core::PageRequest::new(0, 100))
        .expect("list realms");
    assert!(
        listed.items.iter().all(|r| r.id() != &sys),
        "restore must not make the system realm a listed realm"
    );

    // Idempotent: a second run skips everything and changes nothing.
    let again = restore(&dst, &archive, &opts(RestoreMode::Skip)).expect("re-run");
    assert_eq!(again.users.created, 0);
    assert_eq!(again.users.skipped, 1);
    assert_eq!(again.realms.skipped, 1, "the now-live key is kept");
    assert_eq!(system_key(&dst), src_key);
}

// ── Skip / Merge against a live system realm ─────────────────────────────────

/// Skip and Merge never replace what a live system realm already holds: its
/// signing key (the one every live operator token is signed with) and every
/// operator account that already exists. Operators missing from the target
/// are added.
#[tokio::test]
async fn skip_and_merge_keep_a_live_system_realm_and_add_missing_operators() {
    for mode in [RestoreMode::Skip, RestoreMode::Merge] {
        let src = common::TestHarness::embedded().await.expect("src");
        seed_operator(&src, "shared@hearth.test", "Archive-Pa55word!");
        seed_operator(&src, "restored@hearth.test", "Restored-Pa55word!");
        let archive = export(&src, &[system_realm()]);

        let dst = common::TestHarness::embedded().await.expect("dst");
        seed_operator(&dst, "shared@hearth.test", "Live-Pa55word!");
        let live_key = system_key(&dst);

        let report = restore(&dst, &archive, &opts(mode.clone())).expect("restore");
        assert_eq!(report.realms.skipped, 1, "{mode:?}: the live key is kept");
        assert_eq!(report.realms.created + report.realms.overwritten, 0);
        assert!(
            report.conflicts.iter().any(|c| c.entity_type == "realm"),
            "{mode:?}: keeping the live key is reported"
        );
        assert_eq!(report.users.created, 1, "{mode:?}");
        assert_eq!(report.users.skipped, 1, "{mode:?}");
        assert_eq!(system_key(&dst), live_key, "{mode:?}: live key untouched");
        assert!(
            password_ok(&dst, "shared@hearth.test", "Live-Pa55word!"),
            "{mode:?}: the live operator keeps the live password"
        );
        assert!(
            !password_ok(&dst, "shared@hearth.test", "Archive-Pa55word!"),
            "{mode:?}: the archive must not overwrite a live operator"
        );
        assert!(
            password_ok(&dst, "restored@hearth.test", "Restored-Pa55word!"),
            "{mode:?}: a missing operator is added"
        );
    }
}

// ── Overwrite ─────────────────────────────────────────────────────────────────

/// Overwrite means the archive wins: the live system key is replaced by the
/// archived one (and the published JWKS follows immediately), and an existing
/// operator is replaced by its archived record and credential.
#[tokio::test]
async fn overwrite_replaces_the_live_system_key_and_operators() {
    let sys = system_realm();
    let src = common::TestHarness::embedded().await.expect("src");
    seed_operator(&src, "shared@hearth.test", "Archive-Pa55word!");
    let src_key = system_key(&src);
    let src_kid = src.identity().realm_jwks(&sys).expect("jwks").keys[0]
        .kid
        .clone();
    let archive = export(&src, std::slice::from_ref(&sys));

    let dst = common::TestHarness::embedded().await.expect("dst");
    seed_operator(&dst, "shared@hearth.test", "Live-Pa55word!");
    // Warm the key cache so a stale cached key would be observable.
    let _ = dst.identity().realm_jwks(&sys).expect("warm jwks");

    let report = restore(&dst, &archive, &opts(RestoreMode::Overwrite)).expect("restore");
    assert_eq!(report.realms.overwritten, 1, "the live key is replaced");
    assert_eq!(report.users.overwritten, 1);
    assert_eq!(report.users.errored, 0);
    assert_eq!(system_key(&dst), src_key);
    let kids: Vec<String> = dst
        .identity()
        .realm_jwks(&sys)
        .expect("jwks")
        .keys
        .iter()
        .map(|k| k.kid.clone())
        .collect();
    assert!(
        kids.contains(&src_kid),
        "the published system JWKS must carry the restored key at once, not a cached one: {kids:?}"
    );
    assert!(password_ok(&dst, "shared@hearth.test", "Archive-Pa55word!"));
    assert!(!password_ok(&dst, "shared@hearth.test", "Live-Pa55word!"));
}

// ── Dry run ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_dry_run_of_the_system_realm_writes_nothing() {
    let src = common::TestHarness::embedded().await.expect("src");
    seed_operator(&src, "operator@hearth.test", "Operat0r-Pa55word!");
    let archive = export(&src, &[system_realm()]);

    let dst = common::TestHarness::embedded().await.expect("dst");
    let seeded = system_key(&dst);
    let report = restore(
        &dst,
        &archive,
        &ImportOptions {
            dry_run: true,
            ..opts(RestoreMode::Skip)
        },
    )
    .expect("dry run");
    assert_eq!(report.users.created, 1, "the dry run reports the operator");
    assert_eq!(report.realms.created, 1, "and the key it would install");
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "operator@hearth.test")
            .expect("lookup")
            .is_none(),
        "a dry run must not write the operator"
    );
    assert_eq!(
        system_key(&dst),
        seeded,
        "a dry run must not replace the key"
    );
}

// ── Authorization ─────────────────────────────────────────────────────────────

/// A caller scoped to a tenant realm (`allowed_realm = Some(tenant)`, what the
/// HTTP route passes for every non-system caller) must never write the system
/// realm, and the refusal comes before anything is written.
#[tokio::test]
async fn a_realm_scoped_restore_refuses_the_system_realm_before_writing() {
    let src = common::TestHarness::embedded().await.expect("src");
    seed_operator(&src, "intruder@hearth.test", "Intruder-Pa55word!");
    let archive = export(&src, &[system_realm()]);

    let dst = common::TestHarness::embedded().await.expect("dst");
    let tenant = dst.create_realm();
    let seeded = system_key(&dst);
    for mode in [RestoreMode::Skip, RestoreMode::Overwrite] {
        let err = restore(
            &dst,
            &archive,
            &ImportOptions {
                allowed_realm: Some(tenant.clone()),
                ..opts(mode)
            },
        )
        .expect_err("a tenant-scoped caller must not restore the system realm");
        assert!(
            matches!(err, BackupError::RealmNotPermitted { .. }),
            "expected RealmNotPermitted, got {err:?}"
        );
    }
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "intruder@hearth.test")
            .expect("lookup")
            .is_none(),
        "no system-realm principal may be created by a tenant-scoped restore"
    );
    assert_eq!(system_key(&dst), seeded);
}

// ── Signing-key fail-closed rules ─────────────────────────────────────────────

/// The same `--allow-missing-signing-key` semantics as every other realm: an
/// archive whose system realm carries no signing key is refused with nothing
/// written; with the explicit opt-in the restore proceeds and the target keeps
/// the key it already has.
#[tokio::test]
async fn a_system_realm_without_its_signing_key_fails_closed_unless_allowed() {
    let src = common::TestHarness::embedded().await.expect("src");
    seed_operator(&src, "operator@hearth.test", "Operat0r-Pa55word!");
    let full = export(&src, &[system_realm()]);
    let keyless = strip_member(full.path(), "realms/system/signing_key.json");

    let dst = common::TestHarness::embedded().await.expect("dst");
    let seeded = system_key(&dst);
    let err = restore(&dst, &keyless, &opts(RestoreMode::Skip))
        .expect_err("a keyless system realm must be refused by default");
    assert!(
        matches!(err, BackupError::SigningKeyMissing { .. }),
        "expected SigningKeyMissing, got {err:?}"
    );
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "operator@hearth.test")
            .expect("lookup")
            .is_none(),
        "the refusal comes before any write"
    );

    let report = restore(
        &dst,
        &keyless,
        &ImportOptions {
            allow_missing_signing_key: true,
            ..opts(RestoreMode::Skip)
        },
    )
    .expect("the opt-in restores the accounts");
    assert_eq!(report.users.created, 1);
    assert_eq!(
        report.realms.skipped, 1,
        "no archived key: the target's is kept"
    );
    assert_eq!(system_key(&dst), seeded);
    assert!(password_ok(
        &dst,
        "operator@hearth.test",
        "Operat0r-Pa55word!"
    ));
}

// ── Tenant realms beside the system realm ────────────────────────────────────

/// A full archive (tenant realm + system realm) restores both, and an archive
/// without the system realm still restores without error and leaves the
/// target's system realm alone.
#[tokio::test]
async fn full_archives_restore_both_and_tenant_only_archives_leave_the_system_realm_alone() {
    let src = common::TestHarness::embedded().await.expect("src");
    let tenant = src.create_realm();
    src.rbac().seed_realm(&tenant).expect("seed tenant");
    seed_operator(&src, "operator@hearth.test", "Operat0r-Pa55word!");
    let tenant_slug = src
        .identity()
        .get_realm(&tenant)
        .expect("get")
        .expect("exists")
        .name()
        .to_string();

    // Full archive, restored slug by slug as the CLI does.
    let full = export(&src, &[tenant.clone(), system_realm()]);
    let dst = common::TestHarness::embedded().await.expect("dst");
    let reader = BackupArchive::open(full.path()).expect("open");
    for r in reader.realms() {
        let report = importer(&dst)
            .import_realm(&r.slug, &reader, &opts(RestoreMode::Skip))
            .unwrap_or_else(|e| panic!("realm '{}' must restore: {e}", r.slug));
        assert_eq!(report.realms.errored, 0);
    }
    assert!(dst.identity().get_realm(&tenant).expect("get").is_some());
    assert!(password_ok(
        &dst,
        "operator@hearth.test",
        "Operat0r-Pa55word!"
    ));

    // Tenant-only archive.
    let tenant_only = export(&src, std::slice::from_ref(&tenant));
    let dst2 = common::TestHarness::embedded().await.expect("dst2");
    let seeded = system_key(&dst2);
    let reader = BackupArchive::open(tenant_only.path()).expect("open");
    let report = importer(&dst2)
        .import_realm(&tenant_slug, &reader, &opts(RestoreMode::Skip))
        .expect("tenant-only archive restores");
    assert_eq!(report.realms.created, 1);
    assert_eq!(system_key(&dst2), seeded, "system realm untouched");
    assert!(dst2
        .identity()
        .get_user_by_email(&system_realm(), "operator@hearth.test")
        .expect("lookup")
        .is_none());
}

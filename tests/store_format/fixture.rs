//! The store-format fixture (#646): what it holds, how to write it, and how to
//! open it.
//!
//! Shared by `tests/store_format_fixture.rs` (reads the committed fixture) and
//! `examples/gen_store_format_fixture.rs` (writes it). Regenerate the fixture
//! with `scripts/regen-store-format-fixture.sh`, and only together with a bump
//! of `hearth::storage::format::STORE_FORMAT_VERSION`.

#![allow(dead_code)] // each includer uses a part of this module

use std::path::Path;
use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, SessionId, Timestamp, UserId};
use hearth::identity::key_encryption::StorageKek;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject, SvBumper};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use serde::{Deserialize, Serialize};

/// The fixture directory, relative to the crate root.
pub const FIXTURE_DIR: &str = "tests/fixtures/store-format";

/// The file in the fixture directory that records what the store holds.
pub const MANIFEST_FILE: &str = "fixture.json";

/// The fixture's clock: 2026-11-10T00:00:00Z.
pub const T0_MICROS: i64 = 1_794_268_800_000_000;

/// The key-encryption key of the fixture store. It is a test value; the
/// fixture holds no real secret.
pub const KEK: [u8; 32] = [0x46; 32];

/// The password of every fixture user.
pub const PASSWORD: &str = "store-format-fixture-password";

/// What the generator wrote, so the reader can check it.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// `STORE_FORMAT_VERSION` of the build that wrote the fixture.
    pub store_format: u32,
    /// The fixture realm.
    pub realm_id: uuid::Uuid,
    /// `(email, user id)` of each user.
    pub users: Vec<(String, uuid::Uuid)>,
    /// A session of the second user, written after the SST flush (WAL only).
    pub session_id: uuid::Uuid,
    /// The `kid` of each realm signing key, sorted.
    pub kids: Vec<String>,
    /// The number of audit events in the realm.
    pub audit_events: u64,
    /// The effective permissions of the first user, sorted.
    pub admin_permissions: Vec<String>,
}

/// The engines over one data directory.
pub struct Engines {
    /// The storage engine.
    pub storage: Arc<EmbeddedStorageEngine>,
    /// The identity engine.
    pub identity: Arc<EmbeddedIdentityEngine>,
    /// The RBAC engine.
    pub rbac: Arc<EmbeddedRbacEngine>,
    /// The audit engine.
    pub audit: Arc<EmbeddedAuditEngine>,
}

/// Opens the engines over `data_dir` as `hearth backup create` wires them,
/// with the fixture KEK and a clock at `now_micros`.
pub fn open(data_dir: &Path, now_micros: i64) -> Result<Engines, String> {
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.to_path_buf()))
            .map_err(|e| e.to_string())?,
    );
    let dyn_storage = Arc::clone(&storage) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(now_micros))) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&dyn_storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(
        EmbeddedAuditEngine::new(Arc::clone(&dyn_storage), Arc::clone(&clock)).with_kek(Some(KEK)),
    );
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            dyn_storage,
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                key_encryption_key: Some(StorageKek::new(KEK)),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac) as Arc<dyn RbacEngine>,
            Arc::clone(&audit) as Arc<dyn AuditEngine>,
        )
        .map_err(|e| e.to_string())?,
    );
    rbac.init_sv_bumper(Arc::clone(&identity) as Arc<dyn SvBumper>);
    Ok(Engines {
        storage,
        identity,
        rbac,
        audit,
    })
}

/// The `kid` of each signing key of `realm`, sorted.
pub fn kids(identity: &dyn IdentityEngine, realm: &RealmId) -> Result<Vec<String>, String> {
    let mut kids: Vec<String> = identity
        .realm_jwks(realm)
        .map_err(|e| e.to_string())?
        .keys
        .into_iter()
        .map(|k| k.kid)
        .collect();
    kids.sort();
    Ok(kids)
}

/// The effective permissions of `user` in `realm`, sorted.
pub fn permissions(
    rbac: &dyn RbacEngine,
    realm: &RealmId,
    user: &UserId,
) -> Result<Vec<String>, String> {
    let mut perms: Vec<String> = rbac
        .resolve_permissions(user, realm, None, None)
        .map_err(|e| e.to_string())?
        .permissions
        .iter()
        .map(ToString::to_string)
        .collect();
    perms.sort();
    Ok(perms)
}

/// Writes a new fixture store into `data_dir`, which must not exist, and
/// returns its manifest.
///
/// The first part of the data goes to an SST (a memtable flush); the session
/// and the last audit events stay in the WAL, so the reader decodes both.
pub fn generate(data_dir: &Path) -> Result<Manifest, String> {
    let e = open(data_dir, T0_MICROS)?;
    let realm = e
        .identity
        .create_realm(&CreateRealmRequest {
            name: "store-format-fixture".to_string(),
            config: None,
        })
        .map_err(|e| e.to_string())?;
    let realm_id = realm.id().clone();
    e.rbac.seed_realm(&realm_id).map_err(|e| e.to_string())?;

    let mut users = Vec::new();
    for i in 0..3 {
        let email = format!("user{i}@fixture.example");
        let user = e
            .identity
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email: email.clone(),
                    display_name: format!("Fixture User {i}"),
                    first_name: "Fixture".into(),
                    last_name: format!("User{i}"),
                    attributes: Default::default(),
                },
            )
            .map_err(|e| e.to_string())?;
        e.identity
            .set_password(
                &realm_id,
                user.id(),
                &CleartextPassword::from_string(PASSWORD.to_string()),
            )
            .map_err(|e| e.to_string())?;
        users.push((email, user.id().clone()));
    }
    let admin_role = e
        .rbac
        .get_role_by_name(&realm_id, "realm.admin")
        .map_err(|e| e.to_string())?
        .ok_or("realm.admin is not seeded")?;
    e.rbac
        .assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::User(users[0].1.clone()),
                role_id: admin_role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .map_err(|e| e.to_string())?;

    e.storage.flush_memtable().map_err(|e| e.to_string())?;

    let session = e
        .identity
        .create_session(&realm_id, &users[1].1, &SessionContext::default())
        .map_err(|e| e.to_string())?;
    for i in 0..3 {
        e.audit
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "store-format-fixture".to_string(),
                action: AuditAction::UserUpdated,
                resource_type: "user".to_string(),
                resource_id: users[i].1.as_uuid().to_string(),
                metadata: None,
            })
            .map_err(|e| e.to_string())?;
    }

    let manifest = Manifest {
        store_format: hearth::storage::format::STORE_FORMAT_VERSION,
        realm_id: *realm_id.as_uuid(),
        users: users
            .iter()
            .map(|(email, id)| (email.clone(), *id.as_uuid()))
            .collect(),
        session_id: *session.id().as_uuid(),
        kids: kids(e.identity.as_ref(), &realm_id)?,
        audit_events: e.audit.count_events(&realm_id).map_err(|e| e.to_string())?,
        admin_permissions: permissions(e.rbac.as_ref(), &realm_id, &users[0].1)?,
    };
    drop(e);
    Ok(manifest)
}

/// The realm, user and session ids of `manifest` as Hearth types.
pub fn ids(manifest: &Manifest) -> (RealmId, Vec<(String, UserId)>, SessionId) {
    (
        RealmId::new(manifest.realm_id),
        manifest
            .users
            .iter()
            .map(|(email, id)| (email.clone(), UserId::new(*id)))
            .collect(),
        SessionId::new(manifest.session_id),
    )
}

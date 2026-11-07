//! The "typical user" of the RBAC resolution budget, shared by the
//! `rbac_check` bench gate and its regression test (#636).
//!
//! `openspec/specs/performance-budgets/spec.md`, requirement "RBAC resolution
//! and claim-lookup budgets": `resolve_permissions` meets p99 < 1 ms "for a
//! typical user with 5 roles, 10 groups and 30 permissions". This module
//! builds that user in a real [`EmbeddedRbacEngine`], so the gate times the
//! engine's resolution and not a stand-in.
//!
//! - 5 roles, each with 6 distinct permissions: 30 permissions in all.
//! - The user is a direct member of 10 groups. Group `i` holds role `i % 5`,
//!   so every role is reached through 2 groups and the resolution walks all
//!   10 groups.

use std::sync::Arc;

use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, EmbeddedRbacEngine, GroupId,
    GroupMember, Permission, RbacEngine, ResolvedPermissions, Scope, Subject, UpdateGroupRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Roles the typical user holds.
pub const ROLES: usize = 5;
/// Groups the typical user is a member of.
pub const GROUPS: usize = 10;
/// Permissions each role grants directly.
pub const PERMISSIONS_PER_ROLE: usize = 6;
/// Effective permissions of the typical user.
pub const PERMISSIONS: usize = ROLES * PERMISSIONS_PER_ROLE;

/// A realm in a real RBAC engine that holds the typical user.
pub struct TypicalUser {
    engine: EmbeddedRbacEngine,
    realm: RealmId,
    user: UserId,
    /// A group outside the user's graph. Its description is rewritten to
    /// bump the realm's RBAC graph version (see [`Self::invalidate`]).
    spare_group: GroupId,
    flip: bool,
    _dir: tempfile::TempDir,
}

impl TypicalUser {
    /// Builds the realm, its roles and groups, and the user.
    pub fn build() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("open storage"),
        ) as Arc<dyn StorageEngine>;
        let engine = EmbeddedRbacEngine::new(storage, Arc::new(SystemClock) as Arc<dyn Clock>);
        let realm = RealmId::generate();
        let user = UserId::generate();

        let roles: Vec<_> = (0..ROLES)
            .map(|r| {
                let permissions = (0..PERMISSIONS_PER_ROLE)
                    .map(|p| Permission::new(format!("app.res_{r}.act_{p}")).expect("permission"))
                    .collect();
                engine
                    .create_role(
                        &realm,
                        &CreateRoleRequest {
                            name: format!("role-{r}"),
                            permissions,
                            ..Default::default()
                        },
                    )
                    .expect("create role")
                    .id
            })
            .collect();

        for g in 0..GROUPS {
            let group = Self::group(&engine, &realm, &format!("group-{g}"));
            engine
                .add_group_member(&realm, &group, &GroupMember::User(user.clone()))
                .expect("add member");
            engine
                .assign_role(
                    &realm,
                    &AssignRoleRequest {
                        subject: Subject::Group(group),
                        role_id: roles[g % ROLES].clone(),
                        scope: Scope::Realm,
                        assigned_by: None,
                    },
                )
                .expect("assign role");
        }
        let spare_group = Self::group(&engine, &realm, "spare");

        Self {
            engine,
            realm,
            user,
            spare_group,
            flip: false,
            _dir: dir,
        }
    }

    fn group(engine: &EmbeddedRbacEngine, realm: &RealmId, slug: &str) -> GroupId {
        engine
            .create_group(
                realm,
                &CreateGroupRequest {
                    name: slug.to_string(),
                    slug: slug.to_string(),
                    description: None,
                },
            )
            .expect("create group")
            .id
    }

    /// The operation the gate times: the engine's token-issue resolution of
    /// the user's effective permissions.
    pub fn resolve(&self) -> ResolvedPermissions {
        self.engine
            .resolve_permissions(&self.user, &self.realm, None, None)
            .expect("resolve permissions")
    }

    /// Writes to the realm's RBAC graph outside the user's part of it, so the
    /// next [`Self::resolve`] misses the engine's resolution cache and does
    /// the full walk. Not timed.
    pub fn invalidate(&mut self) {
        self.flip = !self.flip;
        let description = self.flip.then(|| "flip".to_string());
        self.engine
            .update_group(
                &self.realm,
                &self.spare_group,
                &UpdateGroupRequest {
                    description: Some(description),
                    ..Default::default()
                },
            )
            .expect("update spare group");
    }
}

//! Storage-backed implementation of [`RbacEngine`].
//!
//! Thread-safe via the underlying [`StorageEngine`]. All write paths that
//! touch two or more keys use [`StorageEngine::put_batch`] so that index
//! entries can never lag behind their primary records on crash recovery.
//!
//! Cycle detection for role parents and group membership runs at write
//! time (write-time rejection is cheaper than paying for it on every
//! token issuance; `resolve.rs` still tolerates a late-appearing cycle
//! in case storage was corrupted out-of-band).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use crate::core::{Clock, OrganizationId, RealmId, Uri, UserId};
use crate::identity::ClientTrustLevel;
use crate::storage::{StorageEngine, StorageError};

use super::error::RbacError;
use super::keys;
use super::resolve::{self, Resolver};
use super::seed::{self, StoredScope};
use super::types::{
    AssignRoleRequest, AssignmentId, CreateGroupRequest, CreateRoleRequest, CycleKind, Group,
    GroupId, GroupMember, GroupMembership, Page, Permission, PermissionRecord, PermissionStatus,
    ProtectedResource, ResolvedPermissions, Role, RoleAssignment, RoleId, RoleSpec, RoleStatus,
    RoleSubject, Scope, ScopeExport, ScopeSpec, Subject, TraversalKind, UpdateGroupRequest,
    UpdateRoleRequest, UserPermissionGrant,
};
use super::{RbacEngine, SvBumper};

/// Upper bound on cached resolutions across all realms. When exceeded, the
/// entire cache is cleared (coarse eviction — correctness-safe, since every
/// entry is re-derivable from storage). Sized to comfortably hold the working
/// set of a large tenant without unbounded growth.
const MAX_RESOLUTION_CACHE_ENTRIES: usize = 50_000;

/// Decision cache for full (pre-scope-narrowing) permission resolutions.
///
/// # Correctness
///
/// Each realm carries a monotonic *graph version* (`generations`). Every RBAC
/// mutation bumps its realm's version (see [`EmbeddedRbacEngine::invalidate_realm`]).
/// A cache entry is only served when its stored version equals the realm's
/// current version, so any mutation atomically renders every prior entry for
/// that realm unreachable. This makes a stale-permission read — a
/// privilege-escalation bug — impossible, at the cost of coarse (whole-realm)
/// invalidation.
///
/// The cached value is the *unnarrowed* effective set (`requested_scope = None`),
/// which depends only on the stored RBAC graph and never on the config scope
/// registry, so RBAC hot-reload of scope definitions needs no special handling
/// here: scope narrowing runs fresh on top of the cached full set on every call.
#[derive(Default)]
struct ResolutionCache {
    /// Per-realm graph version, bumped on every mutation.
    generations: HashMap<RealmId, u64>,
    /// `(realm, user, org)` → `(version-at-fill, resolved)`.
    entries: HashMap<(RealmId, UserId, Option<OrganizationId>), (u64, ResolvedPermissions)>,
}

impl ResolutionCache {
    /// Current graph version for a realm (`0` if never mutated).
    fn generation(&self, realm_id: &RealmId) -> u64 {
        self.generations.get(realm_id).copied().unwrap_or(0)
    }

    /// Returns the cached resolution iff it matches the realm's current version.
    fn get(
        &self,
        key: &(RealmId, UserId, Option<OrganizationId>),
    ) -> Option<ResolvedPermissions> {
        let current = self.generation(&key.0);
        match self.entries.get(key) {
            Some((version, value)) if *version == current => Some(value.clone()),
            _ => None,
        }
    }

    /// Inserts a resolution tagged with the version it was computed against.
    /// Callers MUST pass the version captured *before* the storage reads that
    /// produced `value`, and only after confirming it is still current.
    fn insert(
        &mut self,
        key: (RealmId, UserId, Option<OrganizationId>),
        version: u64,
        value: ResolvedPermissions,
    ) {
        if self.entries.len() >= MAX_RESOLUTION_CACHE_ENTRIES && !self.entries.contains_key(&key) {
            self.entries.clear();
        }
        self.entries.insert(key, (version, value));
    }

    /// Bumps a realm's graph version, invalidating all of its cached entries.
    fn bump(&mut self, realm_id: &RealmId) {
        *self.generations.entry(realm_id.clone()).or_insert(0) += 1;
    }
}

/// Embedded RBAC engine backed by [`StorageEngine`].
pub struct EmbeddedRbacEngine {
    storage: Arc<dyn StorageEngine>,
    clock: Arc<dyn Clock>,
    /// Injected at startup via [`Self::init_sv_bumper`]. Absent until the
    /// identity engine is fully constructed (avoids construction-order coupling).
    sv_bumper: OnceLock<Arc<dyn SvBumper>>,
    /// Serializes concurrent role-assignment writes to prevent duplicate assignments
    /// (A-28: same user+role+scope pair from two concurrent requests).
    assign_write_lock: std::sync::Mutex<()>,
    /// Memoizes full permission resolutions to collapse the per-issuance N+1
    /// storage fan-out (HEA-1770). Invalidated per-realm on every mutation.
    resolution_cache: Mutex<ResolutionCache>,
}

impl EmbeddedRbacEngine {
    /// Creates a new embedded RBAC engine.
    pub fn new(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> Self {
        Self {
            storage,
            clock,
            sv_bumper: OnceLock::new(),
            assign_write_lock: std::sync::Mutex::new(()),
            resolution_cache: Mutex::new(ResolutionCache::default()),
        }
    }

    // -------------------- resolution decision cache (HEA-1770) --------------------

    /// Bumps the realm's RBAC graph version, invalidating every cached
    /// resolution for that realm.
    ///
    /// INVARIANT: callers MUST invoke this strictly *after* the storage write
    /// that mutated the RBAC graph is durable. Because readers capture the
    /// pre-read version and only cache when it is unchanged, bumping after the
    /// write guarantees a concurrent reader either (a) observes the new version
    /// and refuses to cache its pre-mutation snapshot, or (b) already cached a
    /// snapshot under the old version which this bump renders unreachable.
    fn invalidate_realm(&self, realm_id: &RealmId) {
        self.resolution_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bump(realm_id);
    }

    /// [`StorageEngine::put`] followed by cache invalidation for the realm.
    fn write_put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.storage.put(realm_id, key, value)?;
        self.invalidate_realm(realm_id);
        Ok(())
    }

    /// [`StorageEngine::put_batch`] followed by cache invalidation for the realm.
    fn write_put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        self.storage.put_batch(realm_id, entries)?;
        self.invalidate_realm(realm_id);
        Ok(())
    }

    /// [`StorageEngine::delete`] followed by cache invalidation for the realm.
    fn write_delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.storage.delete(realm_id, key)?;
        self.invalidate_realm(realm_id);
        Ok(())
    }

    /// Injects the [`SvBumper`] implementation. Called once at startup after
    /// the identity engine is fully constructed. Subsequent calls are silently
    /// ignored (OnceLock semantics).
    pub fn init_sv_bumper(&self, bumper: Arc<dyn SvBumper>) {
        let _ = self.sv_bumper.set(bumper);
    }

    /// Best-effort sv bump for a single user. Logs on failure.
    fn bump_sv_for_user(&self, realm_id: &RealmId, user_id: &UserId) {
        if let Some(b) = self.sv_bumper.get() {
            b.bump_user_sessions(realm_id, user_id);
        }
    }

    /// Best-effort sv bump for all users that are direct members of `group_id`.
    ///
    /// Scans the forward membership index and bumps each user member found.
    /// Non-recursive: group-within-group nesting is not followed; tokens for
    /// transitively-affected users will become stale at natural expiry.
    fn bump_sv_for_group_members(&self, realm_id: &RealmId, group_id: &GroupId) {
        let prefix = keys::gm_forward_scan_prefix(group_id);
        let end = keys::prefix_end(&prefix);
        let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) else {
            return;
        };
        for entry in &entries {
            if let Ok(GroupMember::User(uid)) = Self::de::<GroupMember>(&entry.value) {
                self.bump_sv_for_user(realm_id, &uid);
            }
        }
    }

    // -------------------- helpers (serde wrapping) --------------------

    fn ser<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, RbacError> {
        serde_json::to_vec(v).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })
    }

    fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, RbacError> {
        serde_json::from_slice(bytes).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })
    }

    // -------------------- role helpers --------------------

    fn load_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        let k = keys::encode_role(role_id);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => {
                let role: Role = Self::de(&bytes)?;
                if &role.realm_id != realm_id {
                    // Belongs to another realm — treat as not found here.
                    return Ok(None);
                }
                Ok(Some(role))
            }
            None => Ok(None),
        }
    }

    fn load_role_id_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<RoleId>, RbacError> {
        let k = keys::encode_role_name(realm_id, name);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => Ok(Some(Self::de::<RoleId>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn validate_role_name(name: &str) -> Result<(), RbacError> {
        if name.is_empty() {
            return Err(RbacError::InvalidRoleName {
                reason: "role name must not be empty".to_string(),
            });
        }
        if name.len() > 128 {
            return Err(RbacError::InvalidRoleName {
                reason: "role name exceeds 128 chars".to_string(),
            });
        }
        for c in name.chars() {
            if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
                return Err(RbacError::InvalidRoleName {
                    reason: format!("role name contains invalid char '{c}'"),
                });
            }
        }
        Ok(())
    }

    fn validate_group_slug(slug: &str) -> Result<(), RbacError> {
        if slug.is_empty() {
            return Err(RbacError::InvalidGroupSlug {
                reason: "slug must not be empty".to_string(),
            });
        }
        if slug.len() > 128 {
            return Err(RbacError::InvalidGroupSlug {
                reason: "slug exceeds 128 chars".to_string(),
            });
        }
        for c in slug.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
                return Err(RbacError::InvalidGroupSlug {
                    reason: format!("slug contains invalid char '{c}' (a-z, 0-9, -, _)"),
                });
            }
        }
        Ok(())
    }

    fn validate_permissions_for_operator(perms: &[Permission]) -> Result<(), RbacError> {
        for p in perms {
            if p.is_reserved() {
                return Err(RbacError::ReservedNamespace {
                    permission: p.as_str().to_string(),
                });
            }
        }
        Ok(())
    }

    /// Walk role parents (DFS) to ensure no cycle involves `start` via
    /// `parents`. Also ensures depth bound.
    fn check_role_parents_no_cycle(
        &self,
        realm_id: &RealmId,
        start: &RoleId,
        parents: &[RoleId],
    ) -> Result<(), RbacError> {
        let mut visited: HashSet<RoleId> = HashSet::new();
        for p in parents {
            if p == start {
                return Err(RbacError::CycleDetected {
                    kind: CycleKind::RoleComposition,
                    entity: start.to_string(),
                });
            }
            self.walk_role_parents(realm_id, start, p, &mut visited, 1)?;
        }
        Ok(())
    }

    fn walk_role_parents(
        &self,
        realm_id: &RealmId,
        start: &RoleId,
        current: &RoleId,
        visited: &mut HashSet<RoleId>,
        depth: usize,
    ) -> Result<(), RbacError> {
        if depth > resolve::MAX_ROLE_DEPTH {
            return Err(RbacError::DepthExceeded {
                kind: TraversalKind::RoleComposition,
                limit: resolve::MAX_ROLE_DEPTH,
            });
        }
        if !visited.insert(current.clone()) {
            return Ok(());
        }
        let Some(role) = self.load_role(realm_id, current)? else {
            return Ok(());
        };
        for parent in &role.parent_roles {
            if parent == start {
                return Err(RbacError::CycleDetected {
                    kind: CycleKind::RoleComposition,
                    entity: start.to_string(),
                });
            }
            self.walk_role_parents(realm_id, start, parent, visited, depth + 1)?;
        }
        Ok(())
    }

    // -------------------- group helpers --------------------

    fn load_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<Group>, RbacError> {
        let k = keys::encode_group(group_id);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => {
                let g: Group = Self::de(&bytes)?;
                if &g.realm_id != realm_id {
                    return Ok(None);
                }
                Ok(Some(g))
            }
            None => Ok(None),
        }
    }

    fn load_group_id_by_slug(
        &self,
        realm_id: &RealmId,
        slug: &str,
    ) -> Result<Option<GroupId>, RbacError> {
        let k = keys::encode_group_slug(realm_id, slug);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => Ok(Some(Self::de::<GroupId>(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check that adding `member` to `group` would not create a cycle.
    ///
    /// Only relevant when `member` is itself a group: walk from `member`
    /// through forward edges (group → members) and confirm the target
    /// `group` is not reachable.
    fn check_group_no_cycle(
        &self,
        realm_id: &RealmId,
        target_group: &GroupId,
        member: &GroupMember,
    ) -> Result<(), RbacError> {
        let GroupMember::Group(member_group) = member else {
            return Ok(());
        };
        if member_group == target_group {
            return Err(RbacError::CycleDetected {
                kind: CycleKind::GroupMembership,
                entity: target_group.to_string(),
            });
        }

        // BFS forward edges from member_group; if we can reach target_group,
        // adding member→target would create a cycle (target would contain a
        // group that transitively contains target).
        let mut visited: HashSet<GroupId> = HashSet::new();
        let mut stack: Vec<(GroupId, usize)> = vec![(member_group.clone(), 0)];

        while let Some((cur, depth)) = stack.pop() {
            if depth > resolve::MAX_GROUP_DEPTH {
                return Err(RbacError::DepthExceeded {
                    kind: TraversalKind::GroupMembership,
                    limit: resolve::MAX_GROUP_DEPTH,
                });
            }
            if !visited.insert(cur.clone()) {
                continue;
            }
            // Walk forward members of `cur` that are themselves groups.
            let prefix = keys::gm_forward_scan_prefix(&cur);
            let end = keys::prefix_end(&prefix);
            for entry in self.storage.scan(realm_id, &prefix, &end)? {
                // Decode the stored GroupMember to see if it's a group we must traverse.
                let decoded: GroupMember = Self::de(&entry.value)?;
                if let GroupMember::Group(child) = decoded {
                    if &child == target_group {
                        return Err(RbacError::CycleDetected {
                            kind: CycleKind::GroupMembership,
                            entity: target_group.to_string(),
                        });
                    }
                    stack.push((child, depth + 1));
                }
            }
        }

        Ok(())
    }

    // -------------------- assignment helpers --------------------

    fn load_assignment(
        &self,
        realm_id: &RealmId,
        id: &AssignmentId,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        let k = keys::encode_assignment(id);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => {
                let a: RoleAssignment = Self::de(&bytes)?;
                if &a.realm_id != realm_id {
                    return Ok(None);
                }
                Ok(Some(a))
            }
            None => Ok(None),
        }
    }

    fn scan_assignments_by_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let end = keys::prefix_end(prefix);
        let entries = self.storage.scan(realm_id, prefix, &end)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let aid: AssignmentId = Self::de(&entry.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                out.push(a);
            }
        }
        Ok(out)
    }

    /// Returns all [`RoleAssignment`]s for `subject`, regardless of whether it
    /// is a user or a group. Used by [`Self::assign_role`] for the A-28
    /// idempotency check under the write lock.
    fn subject_assignments(
        &self,
        realm_id: &RealmId,
        subject: &Subject,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        match subject {
            Subject::User(u) => self.user_assignments(realm_id, u),
            Subject::Group(g) => self.group_assignments(realm_id, g),
        }
    }

    fn load_user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        let prefix = keys::user_permission_scan_prefix(realm_id, user_id);
        let end = keys::prefix_end(&prefix);
        let mut out = Vec::new();
        for entry in self.storage.scan(realm_id, &prefix, &end)? {
            out.push(Self::de::<UserPermissionGrant>(&entry.value)?);
        }
        Ok(out)
    }

    // Resource-scope methods are implemented in the Resolver trait impl below.
}

// ---------------------------------------------------------------------------
// Resolver impl — allows resolve.rs to drive the DB.
// ---------------------------------------------------------------------------

impl Resolver for EmbeddedRbacEngine {
    /// Memoized full (unnarrowed) resolution — the decision cache that
    /// collapses the per-issuance N+1 storage fan-out (HEA-1770).
    ///
    /// Reads outside the lock (only the hit-check and version capture hold it),
    /// and only fills the cache when the realm's graph version is unchanged
    /// across the read — a concurrent mutation between the version capture and
    /// the fill skips caching, so a snapshot taken before a mutation can never
    /// be stored as current.
    fn resolve_full_cached(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
    ) -> Result<ResolvedPermissions, RbacError> {
        let key = (realm_id.clone(), user_id.clone(), org_id.cloned());

        // Fast path: serve a version-matched hit; otherwise capture the current
        // version to validate the fill against.
        let version_at_read = {
            let cache = self
                .resolution_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(hit) = cache.get(&key) {
                return Ok(hit);
            }
            cache.generation(realm_id)
        };

        let resolved = resolve::resolve_full(self, user_id, realm_id, org_id)?;

        let mut cache = self
            .resolution_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only cache if no mutation raced our storage reads. If the version
        // moved, the snapshot may already be stale — drop it rather than risk
        // serving stale permissions.
        if cache.generation(realm_id) == version_at_read {
            cache.insert(key, version_at_read, resolved.clone());
        }
        Ok(resolved)
    }

    fn parent_groups_of(
        &self,
        realm_id: &RealmId,
        member: &GroupMember,
    ) -> Result<Vec<GroupId>, RbacError> {
        let prefix = keys::gm_reverse_scan_prefix(member);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let gid: GroupId = Self::de(&entry.value)?;
            out.push(gid);
        }
        Ok(out)
    }

    fn user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_user_scan_prefix(user_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_group_scan_prefix(group_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        self.load_role(realm_id, role_id)
    }

    fn get_group_slug(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<String>, RbacError> {
        Ok(self.load_group(realm_id, group_id)?.map(|g| g.slug))
    }

    fn scope_permissions(
        &self,
        realm_id: &RealmId,
        scope_name: &str,
    ) -> Result<Option<Vec<Permission>>, RbacError> {
        let key = keys::encode_scope(realm_id, scope_name);
        match self.storage.get(realm_id, &key)? {
            None => Ok(Some(Vec::new())),
            Some(bytes) => {
                let s: StoredScope = Self::de(&bytes)?;
                Ok(s.permissions)
            }
        }
    }

    fn user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        self.load_user_permissions(realm_id, user_id)
    }

    fn get_role_id_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<RoleId>, RbacError> {
        self.load_role_id_by_name(realm_id, name)
    }

    fn additional_roles(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Vec<String>, RbacError> {
        let prefix = keys::org_extra_role_scan_prefix(realm_id, org_id, user_id);
        let end = keys::prefix_end(&prefix);
        let mut out = Vec::new();
        for entry in self.storage.scan(realm_id, &prefix, &end)? {
            let name: String = Self::de(&entry.value)?;
            out.push(name);
        }
        Ok(out)
    }

    fn resource_scope_permissions(
        &self,
        realm_id: &RealmId,
        resource_uri: &Uri,
        scope_name: &str,
    ) -> Result<Option<Vec<Permission>>, RbacError> {
        let hash = resource_uri.storage_hash();
        let key = keys::encode_resource_scope(realm_id, &hash, scope_name);
        match self.storage.get(realm_id, &key)? {
            None => Ok(None),
            Some(bytes) => {
                let s: StoredScope = Self::de(&bytes)?;
                Ok(s.permissions)
            }
        }
    }

    fn resource_scope_permission_names(
        &self,
        realm_id: &RealmId,
        resource_uri: &Uri,
    ) -> Result<Vec<Permission>, RbacError> {
        let hash = resource_uri.storage_hash();
        let prefix = keys::resource_scope_scan_prefix(realm_id, &hash);
        let end = keys::prefix_end(&prefix);
        let mut out = BTreeSet::new();
        for entry in self.storage.scan(realm_id, &prefix, &end)? {
            let s: StoredScope = Self::de(&entry.value)?;
            if let Some(perms) = s.permissions {
                for p in perms {
                    out.insert(p);
                }
            }
        }
        Ok(out.into_iter().collect())
    }
}

// ---------------------------------------------------------------------------
// RbacEngine trait impl
// ---------------------------------------------------------------------------

impl RbacEngine for EmbeddedRbacEngine {
    fn resolve_permissions(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scope: Option<&str>,
    ) -> Result<ResolvedPermissions, RbacError> {
        resolve::resolve_permissions(self, user_id, realm_id, org_id, requested_scope)
    }

    fn resolve_with_scopes(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scopes: &[String],
        client_trust_level: ClientTrustLevel,
        declared_scopes: &[String],
        resource: Option<&Uri>,
    ) -> Result<ResolvedPermissions, RbacError> {
        resolve::resolve_with_scopes(
            self,
            user_id,
            realm_id,
            org_id,
            requested_scopes,
            client_trust_level,
            declared_scopes,
            resource,
        )
    }

    fn grant_user_permission(
        &self,
        realm_id: &RealmId,
        grant: &UserPermissionGrant,
    ) -> Result<UserPermissionGrant, RbacError> {
        let primary = keys::encode_user_permission(
            realm_id,
            &grant.user_id,
            &grant.scope,
            grant.permission.as_str(),
        );
        let reverse = keys::encode_user_permission_by_perm(
            realm_id,
            grant.permission.as_str(),
            &grant.scope,
            &grant.user_id,
        );
        let bytes = Self::ser(grant)?;
        self.storage
            .put_batch(realm_id, &[(primary, bytes), (reverse, Vec::new())])?;
        tracing::info!(
            realm_id = %realm_id,
            user_id = %grant.user_id,
            permission = grant.permission.as_str(),
            scope_type = match &grant.scope {
                Scope::Realm => "realm",
                Scope::Org { .. } => "org",
            },
            action = "user_permission_granted",
            "user permission granted"
        );
        Ok(grant.clone())
    }

    fn revoke_user_permission(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        permission: &Permission,
        scope: &Scope,
    ) -> Result<(), RbacError> {
        let primary = keys::encode_user_permission(realm_id, user_id, scope, permission.as_str());
        let reverse =
            keys::encode_user_permission_by_perm(realm_id, permission.as_str(), scope, user_id);
        self.write_delete(realm_id, &primary)?;
        self.write_delete(realm_id, &reverse)?;
        tracing::info!(
            realm_id = %realm_id,
            user_id = %user_id,
            permission = permission.as_str(),
            scope_type = match scope {
                Scope::Realm => "realm",
                Scope::Org { .. } => "org",
            },
            action = "user_permission_revoked",
            "user permission revoked"
        );
        Ok(())
    }

    fn list_user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        self.load_user_permissions(realm_id, user_id)
    }

    fn add_additional_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role_name: &str,
        _granted_by: Option<&UserId>,
    ) -> Result<(), RbacError> {
        if role_name.is_empty() {
            return Err(RbacError::InvalidRoleName {
                reason: "role name must not be empty".to_string(),
            });
        }
        if self.get_role_by_name(realm_id, role_name)?.is_none() {
            return Err(RbacError::RoleNotFound);
        }
        let key = keys::encode_org_extra_role(realm_id, org_id, user_id, role_name);
        let value = Self::ser(&role_name)?;
        self.write_put(realm_id, &key, &value)?;
        tracing::info!(
            realm_id = %realm_id,
            org_id = %org_id,
            user_id = %user_id,
            role = %role_name,
            "org member additional role added"
        );
        Ok(())
    }

    fn remove_additional_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role_name: &str,
    ) -> Result<(), RbacError> {
        let key = keys::encode_org_extra_role(realm_id, org_id, user_id, role_name);
        self.write_delete(realm_id, &key)?;
        tracing::info!(
            realm_id = %realm_id,
            org_id = %org_id,
            user_id = %user_id,
            role = %role_name,
            "org member additional role removed"
        );
        Ok(())
    }

    fn list_additional_roles(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Vec<String>, RbacError> {
        let prefix = keys::org_extra_role_scan_prefix(realm_id, org_id, user_id);
        let end = keys::prefix_end(&prefix);
        let mut out = Vec::new();
        for entry in self.storage.scan(realm_id, &prefix, &end)? {
            let name: String = Self::de(&entry.value)?;
            out.push(name);
        }
        Ok(out)
    }

    // ---------- Roles ----------

    fn create_role(&self, realm_id: &RealmId, req: &CreateRoleRequest) -> Result<Role, RbacError> {
        Self::validate_role_name(&req.name)?;
        if !req.allow_reserved_permissions {
            Self::validate_permissions_for_operator(&req.permissions)?;
        }

        if self.load_role_id_by_name(realm_id, &req.name)?.is_some() {
            return Err(RbacError::DuplicateRoleName);
        }

        // Verify parents exist + no immediate cycle.
        for p in &req.parent_roles {
            if self.load_role(realm_id, p)?.is_none() {
                return Err(RbacError::RoleNotFound);
            }
        }

        let now = self.clock.now();
        let role = Role {
            id: RoleId::generate(),
            realm_id: realm_id.clone(),
            name: req.name.clone(),
            description: req.description.clone(),
            permissions: req.permissions.clone(),
            parent_roles: req.parent_roles.clone(),
            scope_kind: req.scope_kind,
            status: RoleStatus::Active,
            yaml_managed: false,
            created_at: now,
            updated_at: now,
        };

        // Self-edge cycle check isn't strictly needed for create (id is
        // freshly generated and can't appear in parent_roles), but calling
        // through keeps behavior consistent and respects MAX_ROLE_DEPTH.
        self.check_role_parents_no_cycle(realm_id, &role.id, &role.parent_roles)?;

        let role_key = keys::encode_role(&role.id);
        let name_key = keys::encode_role_name(realm_id, &role.name);
        self.write_put_batch(
            realm_id,
            &[
                (role_key, Self::ser(&role)?),
                (name_key, Self::ser(&role.id)?),
            ],
        )?;

        Ok(role)
    }

    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        self.load_role(realm_id, role_id)
    }

    fn get_role_by_name(&self, realm_id: &RealmId, name: &str) -> Result<Option<Role>, RbacError> {
        let Some(id) = self.load_role_id_by_name(realm_id, name)? else {
            return Ok(None);
        };
        self.load_role(realm_id, &id)
    }

    fn update_role(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        req: &UpdateRoleRequest,
    ) -> Result<Role, RbacError> {
        let Some(mut role) = self.load_role(realm_id, role_id)? else {
            return Err(RbacError::RoleNotFound);
        };

        let mut rename: Option<(Vec<u8>, Vec<u8>)> = None;
        if let Some(new_name) = &req.name {
            Self::validate_role_name(new_name)?;
            if new_name != &role.name {
                if self.load_role_id_by_name(realm_id, new_name)?.is_some() {
                    return Err(RbacError::DuplicateRoleName);
                }
                rename = Some((
                    keys::encode_role_name(realm_id, &role.name),
                    keys::encode_role_name(realm_id, new_name),
                ));
                role.name.clone_from(new_name);
            }
        }

        if let Some(desc) = &req.description {
            role.description.clone_from(desc);
        }

        if let Some(perms) = &req.permissions {
            if !req.allow_reserved_permissions {
                Self::validate_permissions_for_operator(perms)?;
            }
            role.permissions.clone_from(perms);
        }

        if let Some(parents) = &req.parent_roles {
            for p in parents {
                if self.load_role(realm_id, p)?.is_none() {
                    return Err(RbacError::RoleNotFound);
                }
            }
            self.check_role_parents_no_cycle(realm_id, role_id, parents)?;
            role.parent_roles.clone_from(parents);
        }

        if let Some(scope_kind) = req.scope_kind {
            role.scope_kind = scope_kind;
        }

        if let Some(status) = req.status {
            role.status = status;
        }

        role.updated_at = self.clock.now();

        let role_key = keys::encode_role(&role.id);
        let mut writes: Vec<(Vec<u8>, Vec<u8>)> = vec![(role_key, Self::ser(&role)?)];
        if let Some((_old, new)) = &rename {
            writes.push((new.clone(), Self::ser(&role.id)?));
        }
        self.write_put_batch(realm_id, &writes)?;

        if let Some((old, _)) = rename {
            self.write_delete(realm_id, &old)?;
        }

        Ok(role)
    }

    fn delete_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<(), RbacError> {
        let Some(role) = self.load_role(realm_id, role_id)? else {
            return Err(RbacError::RoleNotFound);
        };
        self.write_delete(realm_id, &keys::encode_role(role_id))?;
        self.storage
            .delete(realm_id, &keys::encode_role_name(realm_id, &role.name))?;
        Ok(())
    }

    fn list_roles(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Role>, RbacError> {
        let prefix = keys::role_name_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let start = match cursor {
            Some(c) => {
                let mut v = prefix.clone();
                v.extend_from_slice(c.as_bytes());
                // Exclusive: bump one byte.
                v.push(0);
                v
            }
            None => prefix.clone(),
        };
        let entries = self.storage.scan(realm_id, &start, &end)?;

        let mut items = Vec::new();
        let mut next_cursor = None;
        for entry in entries {
            if items.len() >= limit {
                // Derive cursor from the boundary entry's key (role name),
                // not from items.last() — the boundary entry always exists
                // and its key carries the correct sort position.
                let name_bytes = &entry.key[prefix.len()..];
                next_cursor = Some(String::from_utf8_lossy(name_bytes).to_string());
                break;
            }
            let id: RoleId = Self::de(&entry.value)?;
            if let Some(role) = self.load_role(realm_id, &id)? {
                items.push(role);
            }
        }

        Ok(Page { items, next_cursor })
    }

    // ---------- Groups ----------

    fn create_group(
        &self,
        realm_id: &RealmId,
        req: &CreateGroupRequest,
    ) -> Result<Group, RbacError> {
        Self::validate_group_slug(&req.slug)?;
        if req.name.is_empty() {
            return Err(RbacError::InvalidGroupSlug {
                reason: "group name must not be empty".to_string(),
            });
        }
        if self.load_group_id_by_slug(realm_id, &req.slug)?.is_some() {
            return Err(RbacError::DuplicateGroupSlug);
        }

        let now = self.clock.now();
        let group = Group {
            id: GroupId::generate(),
            realm_id: realm_id.clone(),
            name: req.name.clone(),
            slug: req.slug.clone(),
            description: req.description.clone(),
            created_at: now,
            updated_at: now,
        };

        self.write_put_batch(
            realm_id,
            &[
                (keys::encode_group(&group.id), Self::ser(&group)?),
                (
                    keys::encode_group_slug(realm_id, &group.slug),
                    Self::ser(&group.id)?,
                ),
            ],
        )?;

        Ok(group)
    }

    fn get_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<Group>, RbacError> {
        self.load_group(realm_id, group_id)
    }

    fn update_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        req: &UpdateGroupRequest,
    ) -> Result<Group, RbacError> {
        let Some(mut group) = self.load_group(realm_id, group_id)? else {
            return Err(RbacError::GroupNotFound);
        };

        let mut reslug: Option<(Vec<u8>, Vec<u8>)> = None;
        if let Some(new_slug) = &req.slug {
            Self::validate_group_slug(new_slug)?;
            if new_slug != &group.slug {
                if self.load_group_id_by_slug(realm_id, new_slug)?.is_some() {
                    return Err(RbacError::DuplicateGroupSlug);
                }
                reslug = Some((
                    keys::encode_group_slug(realm_id, &group.slug),
                    keys::encode_group_slug(realm_id, new_slug),
                ));
                group.slug.clone_from(new_slug);
            }
        }

        if let Some(name) = &req.name {
            group.name.clone_from(name);
        }
        if let Some(desc) = &req.description {
            group.description.clone_from(desc);
        }
        group.updated_at = self.clock.now();

        let mut writes: Vec<(Vec<u8>, Vec<u8>)> =
            vec![(keys::encode_group(&group.id), Self::ser(&group)?)];
        if let Some((_, new)) = &reslug {
            writes.push((new.clone(), Self::ser(&group.id)?));
        }
        self.write_put_batch(realm_id, &writes)?;

        if let Some((old, _)) = reslug {
            self.write_delete(realm_id, &old)?;
        }

        Ok(group)
    }

    fn delete_group(&self, realm_id: &RealmId, group_id: &GroupId) -> Result<(), RbacError> {
        let Some(group) = self.load_group(realm_id, group_id)? else {
            return Err(RbacError::GroupNotFound);
        };

        // Cascade: remove forward + reverse memberships and group-scoped assignments.
        let fwd_prefix = keys::gm_forward_scan_prefix(group_id);
        let fwd_end = keys::prefix_end(&fwd_prefix);
        for e in self.storage.scan(realm_id, &fwd_prefix, &fwd_end)? {
            let member: GroupMember = Self::de(&e.value)?;
            self.write_delete(realm_id, &e.key)?;
            self.storage
                .delete(realm_id, &keys::encode_gm_reverse(&member, group_id))?;
        }

        // Also walk the reverse index keyed as this group-as-member, so we
        // remove its edges out of any parent group.
        let rev_prefix = keys::gm_reverse_scan_prefix(&GroupMember::Group(group_id.clone()));
        let rev_end = keys::prefix_end(&rev_prefix);
        for e in self.storage.scan(realm_id, &rev_prefix, &rev_end)? {
            let parent_group: GroupId = Self::de(&e.value)?;
            self.write_delete(realm_id, &e.key)?;
            self.write_delete(
                realm_id,
                &keys::encode_gm_forward(&parent_group, &GroupMember::Group(group_id.clone())),
            )?;
        }

        // Remove all role assignments bound to this group.
        let asgn_prefix = keys::assign_group_scan_prefix(group_id);
        let asgn_end = keys::prefix_end(&asgn_prefix);
        for e in self.storage.scan(realm_id, &asgn_prefix, &asgn_end)? {
            let aid: AssignmentId = Self::de(&e.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                self.storage
                    .delete(realm_id, &keys::encode_assignment(&aid))?;
                self.storage
                    .delete(realm_id, &keys::encode_assign_role(&a.role_id, &aid))?;
            }
            self.write_delete(realm_id, &e.key)?;
        }

        self.storage
            .delete(realm_id, &keys::encode_group(group_id))?;
        self.storage
            .delete(realm_id, &keys::encode_group_slug(realm_id, &group.slug))?;
        Ok(())
    }

    fn list_groups(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<Group>, RbacError> {
        let prefix = keys::group_slug_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let all = self.storage.scan(realm_id, &prefix, &end)?;

        // Exact total: full result set is already materialised, so capping the
        // count only hides groups from the admin UI pager (HEA-1614).
        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end_idx = (start + page.limit as usize).min(all.len());
        let window = &all[start..end_idx];

        let mut items = Vec::with_capacity(window.len());
        for entry in window {
            let gid: GroupId = Self::de(&entry.value)?;
            if let Some(g) = self.load_group(realm_id, &gid)? {
                items.push(g);
            }
        }

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn add_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<GroupMembership, RbacError> {
        if self.load_group(realm_id, group_id)?.is_none() {
            return Err(RbacError::GroupNotFound);
        }
        // If member is a group, verify it exists.
        if let GroupMember::Group(g) = member {
            if self.load_group(realm_id, g)?.is_none() {
                return Err(RbacError::GroupNotFound);
            }
        }

        self.check_group_no_cycle(realm_id, group_id, member)?;

        let now = self.clock.now();
        let membership = GroupMembership {
            group_id: group_id.clone(),
            member: member.clone(),
            added_at: now,
            added_by: None,
        };

        // Forward value holds the GroupMember (for cycle scans).
        // Reverse value holds the GroupId (so user → parent groups list is cheap).
        self.write_put_batch(
            realm_id,
            &[
                (
                    keys::encode_gm_forward(group_id, member),
                    Self::ser(member)?,
                ),
                (
                    keys::encode_gm_reverse(member, group_id),
                    Self::ser(group_id)?,
                ),
            ],
        )?;

        match member {
            GroupMember::User(uid) => self.bump_sv_for_user(realm_id, uid),
            GroupMember::Group(gid) => self.bump_sv_for_group_members(realm_id, gid),
        }

        Ok(membership)
    }

    fn remove_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<(), RbacError> {
        self.storage
            .delete(realm_id, &keys::encode_gm_forward(group_id, member))?;
        self.storage
            .delete(realm_id, &keys::encode_gm_reverse(member, group_id))?;

        match member {
            GroupMember::User(uid) => self.bump_sv_for_user(realm_id, uid),
            GroupMember::Group(gid) => self.bump_sv_for_group_members(realm_id, gid),
        }

        Ok(())
    }

    fn list_group_members(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        _cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<GroupMember>, RbacError> {
        let prefix = keys::gm_forward_scan_prefix(group_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;

        let mut items = Vec::new();
        for entry in entries {
            if items.len() >= limit {
                break;
            }
            let m: GroupMember = Self::de(&entry.value)?;
            items.push(m);
        }
        Ok(Page {
            items,
            next_cursor: None,
        })
    }

    // ---------- Assignments ----------

    fn resolve_role_permissions(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
    ) -> Result<Vec<Permission>, RbacError> {
        Ok(resolve::expand_role_permissions(self, realm_id, role_id)?
            .into_iter()
            .collect())
    }

    fn assign_role(
        &self,
        realm_id: &RealmId,
        req: &AssignRoleRequest,
    ) -> Result<RoleAssignment, RbacError> {
        match self.load_role(realm_id, &req.role_id)? {
            None => return Err(RbacError::RoleNotFound),
            Some(role) if role.status != RoleStatus::Active => {
                return Err(RbacError::RoleArchived);
            }
            Some(_) => {}
        }
        // Subject existence: user existence is the identity layer's concern;
        // here we just verify group subject exists if that's what was named.
        if let Subject::Group(g) = &req.subject {
            if self.load_group(realm_id, g)?.is_none() {
                return Err(RbacError::GroupNotFound);
            }
        }

        // A-28: acquire write lock to prevent concurrent duplicate assignments.
        let assignment = {
            let _guard = self
                .assign_write_lock
                .lock()
                .expect("assign write lock poisoned");

            // Idempotency: if this exact (subject, role, scope) already exists,
            // return it without creating a duplicate record.
            let existing = self
                .subject_assignments(realm_id, &req.subject)?
                .into_iter()
                .find(|a| a.role_id == req.role_id && a.scope == req.scope);
            if let Some(existing) = existing {
                return Ok(existing);
            }

            let now = self.clock.now();
            let id = AssignmentId::generate();
            let assignment = RoleAssignment {
                id: id.clone(),
                realm_id: realm_id.clone(),
                subject: req.subject.clone(),
                role_id: req.role_id.clone(),
                scope: req.scope.clone(),
                assigned_at: now,
                assigned_by: req.assigned_by.clone(),
            };

            let pri = keys::encode_assignment(&id);
            let subject_idx = match &assignment.subject {
                Subject::User(u) => keys::encode_assign_user(u, &id),
                Subject::Group(g) => keys::encode_assign_group(g, &id),
            };
            let role_idx = keys::encode_assign_role(&assignment.role_id, &id);

            self.write_put_batch(
                realm_id,
                &[
                    (pri, Self::ser(&assignment)?),
                    (subject_idx, Self::ser(&id)?),
                    (role_idx, Self::ser(&id)?),
                ],
            )?;

            assignment
            // _guard dropped here — lock released before sv_bump
        };

        match &assignment.subject {
            Subject::User(uid) => self.bump_sv_for_user(realm_id, uid),
            Subject::Group(gid) => self.bump_sv_for_group_members(realm_id, gid),
        }

        Ok(assignment)
    }

    fn unassign_role(
        &self,
        realm_id: &RealmId,
        assignment_id: &AssignmentId,
    ) -> Result<(), RbacError> {
        let Some(a) = self.load_assignment(realm_id, assignment_id)? else {
            return Err(RbacError::AssignmentNotFound);
        };

        self.storage
            .delete(realm_id, &keys::encode_assignment(assignment_id))?;
        let subject_idx = match &a.subject {
            Subject::User(u) => keys::encode_assign_user(u, assignment_id),
            Subject::Group(g) => keys::encode_assign_group(g, assignment_id),
        };
        self.write_delete(realm_id, &subject_idx)?;
        self.write_delete(
            realm_id,
            &keys::encode_assign_role(&a.role_id, assignment_id),
        )?;

        match &a.subject {
            Subject::User(uid) => self.bump_sv_for_user(realm_id, uid),
            Subject::Group(gid) => self.bump_sv_for_group_members(realm_id, gid),
        }

        Ok(())
    }

    fn list_user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_user_scan_prefix(user_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn list_group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_group_scan_prefix(group_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn purge_user_from_realm(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), RbacError> {
        // Remove all direct role assignments where this user is the subject.
        // Each user-index entry's value is the AssignmentId; mirrors delete_group cascade.
        let asgn_prefix = keys::assign_user_scan_prefix(user_id);
        let asgn_end = keys::prefix_end(&asgn_prefix);
        for e in self.storage.scan(realm_id, &asgn_prefix, &asgn_end)? {
            let aid: AssignmentId = Self::de(&e.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                self.storage
                    .delete(realm_id, &keys::encode_assignment(&aid))?;
                self.storage
                    .delete(realm_id, &keys::encode_assign_role(&a.role_id, &aid))?;
            }
            self.write_delete(realm_id, &e.key)?;
        }

        // Remove the user from all groups they belong to.
        let member = GroupMember::User(user_id.clone());
        let gm_prefix = keys::gm_reverse_scan_prefix(&member);
        let gm_end = keys::prefix_end(&gm_prefix);
        for e in self.storage.scan(realm_id, &gm_prefix, &gm_end)? {
            let group_id: GroupId = Self::de(&e.value)?;
            self.storage
                .delete(realm_id, &keys::encode_gm_forward(&group_id, &member))?;
            self.write_delete(realm_id, &e.key)?;
        }

        Ok(())
    }

    fn list_role_members(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<RoleSubject>, RbacError> {
        let prefix = keys::assign_role_scan_prefix(role_id);
        let end = keys::prefix_end(&prefix);
        let start = match cursor {
            Some(c) => {
                let mut v = prefix.clone();
                v.extend_from_slice(c.as_bytes());
                v.push(0);
                v
            }
            None => prefix.clone(),
        };
        let entries = self.storage.scan(realm_id, &start, &end)?;
        let mut items = Vec::new();
        let mut next_cursor = None;
        for entry in entries {
            if items.len() >= limit {
                let suffix = &entry.key[prefix.len()..];
                next_cursor = Some(String::from_utf8_lossy(suffix).to_string());
                break;
            }
            let aid: AssignmentId = Self::de(&entry.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                let subject = match a.subject {
                    Subject::User(u) => RoleSubject::User(u),
                    Subject::Group(g) => RoleSubject::Group(g),
                };
                items.push(subject);
            }
        }
        Ok(Page { items, next_cursor })
    }

    // ---------- Bootstrap ----------

    fn seed_realm(&self, realm_id: &RealmId) -> Result<(), RbacError> {
        // `seed` writes through the raw storage handle (bypassing the
        // cache-invalidating `write_*` helpers), so invalidate explicitly after
        // it lands.
        seed::seed_realm(&self.storage, &self.clock, realm_id)?;
        self.invalidate_realm(realm_id);
        Ok(())
    }

    // ---------- Declarative reconciliation ----------

    fn reconcile_permissions(
        &self,
        realm_id: &RealmId,
        permission_names: &[String],
    ) -> Result<(), RbacError> {
        for name in permission_names {
            let perm = Permission::new(name.clone())
                .map_err(|reason| RbacError::InvalidPermission { reason })?;
            let key = keys::encode_permission(realm_id, perm.as_str());
            if let Some(raw) = self.storage.get(realm_id, &key)? {
                // If previously archived, restore to Active.
                if let Ok(mut record) = Self::de::<PermissionRecord>(&raw) {
                    if record.status == PermissionStatus::Archived {
                        record.status = PermissionStatus::Active;
                        self.write_put(realm_id, &key, &Self::ser(&record)?)?;
                    }
                }
                continue;
            }
            let record = PermissionRecord {
                name: perm,
                status: PermissionStatus::Active,
            };
            self.write_put(realm_id, &key, &Self::ser(&record)?)?;
        }
        Ok(())
    }

    fn archive_removed_permissions(
        &self,
        realm_id: &RealmId,
        yaml_names: &std::collections::HashSet<String>,
    ) -> Result<(), RbacError> {
        let prefix = keys::permission_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        for entry in entries {
            let Ok(mut record) = Self::de::<PermissionRecord>(&entry.value) else {
                continue;
            };
            if record.status != PermissionStatus::Active {
                continue;
            }
            let perm_name = record.name.as_str();
            // Never archive seed permissions (hearth.* namespace).
            if perm_name.starts_with("hearth.") {
                continue;
            }
            if !yaml_names.contains(perm_name) {
                record.status = PermissionStatus::Archived;
                let key = keys::encode_permission(realm_id, perm_name);
                self.write_put(realm_id, &key, &Self::ser(&record)?)?;
            }
        }
        Ok(())
    }

    fn archive_removed_roles(
        &self,
        realm_id: &RealmId,
        yaml_names: &std::collections::HashSet<String>,
    ) -> Result<(), RbacError> {
        let now = self.clock.now();
        let prefix = keys::role_name_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        for entry in entries {
            let Ok(id) = Self::de::<RoleId>(&entry.value) else {
                continue;
            };
            let Some(mut role) = self.load_role(realm_id, &id)? else {
                continue;
            };
            // Only archive roles that were YAML-managed and are now missing.
            if !role.yaml_managed || role.status == RoleStatus::Archived {
                continue;
            }
            if !yaml_names.contains(&role.name) {
                role.status = RoleStatus::Archived;
                role.updated_at = now;
                let role_key = keys::encode_role(&role.id);
                self.write_put(realm_id, &role_key, &Self::ser(&role)?)?;
            }
        }
        Ok(())
    }

    fn reconcile_roles(&self, realm_id: &RealmId, specs: &[RoleSpec]) -> Result<(), RbacError> {
        let now = self.clock.now();

        for spec in specs {
            Self::validate_role_name(&spec.name)?;

            let permissions: Vec<Permission> = spec
                .permissions
                .iter()
                .map(|p| {
                    Permission::new(p.clone())
                        .map_err(|reason| RbacError::InvalidPermission { reason })
                })
                .collect::<Result<_, _>>()?;
            Self::validate_permissions_for_operator(&permissions)?;

            // Resolve parent names against the realm's current state.
            // Unknown parents are a hard error — the YAML referenced something
            // that doesn't exist (and isn't being created in this batch).
            let mut parent_roles: Vec<RoleId> = Vec::with_capacity(spec.parent_names.len());
            for pname in &spec.parent_names {
                match self.load_role_id_by_name(realm_id, pname)? {
                    Some(pid) => parent_roles.push(pid),
                    None => {
                        return Err(RbacError::Serialization {
                            reason: format!(
                                "role '{}' references missing parent '{pname}'",
                                spec.name
                            ),
                        });
                    }
                }
            }

            if let Some(existing_id) = self.load_role_id_by_name(realm_id, &spec.name)? {
                let Some(mut role) = self.load_role(realm_id, &existing_id)? else {
                    continue;
                };
                // Re-activate if previously archived, and always mark yaml_managed.
                let was_archived = role.status == RoleStatus::Archived;
                let drift = role.description != spec.description
                    || role.permissions != permissions
                    || role.parent_roles != parent_roles
                    || role.scope_kind != spec.scope_kind
                    || was_archived
                    || !role.yaml_managed;
                if drift {
                    role.description.clone_from(&spec.description);
                    role.permissions = permissions;
                    role.parent_roles = parent_roles;
                    role.scope_kind = spec.scope_kind;
                    role.status = RoleStatus::Active;
                    role.yaml_managed = true;
                    role.updated_at = now;
                    self.check_role_parents_no_cycle(realm_id, &role.id, &role.parent_roles)?;
                    let role_key = keys::encode_role(&role.id);
                    self.write_put(realm_id, &role_key, &Self::ser(&role)?)?;
                }
                continue;
            }

            // New role: create.
            let role = Role {
                id: RoleId::generate(),
                realm_id: realm_id.clone(),
                name: spec.name.clone(),
                description: spec.description.clone(),
                permissions,
                parent_roles,
                scope_kind: spec.scope_kind,
                status: RoleStatus::Active,
                yaml_managed: true,
                created_at: now,
                updated_at: now,
            };
            self.check_role_parents_no_cycle(realm_id, &role.id, &role.parent_roles)?;
            let role_key = keys::encode_role(&role.id);
            let name_key = keys::encode_role_name(realm_id, &role.name);
            self.write_put_batch(
                realm_id,
                &[
                    (role_key, Self::ser(&role)?),
                    (name_key, Self::ser(&role.id)?),
                ],
            )?;
        }
        Ok(())
    }

    fn reconcile_scopes(&self, realm_id: &RealmId, specs: &[ScopeSpec]) -> Result<(), RbacError> {
        for spec in specs {
            let permissions: Option<Vec<Permission>> = match &spec.permissions {
                None => None,
                Some(list) => Some(
                    list.iter()
                        .map(|p| {
                            Permission::new(p.clone())
                                .map_err(|reason| RbacError::InvalidPermission { reason })
                        })
                        .collect::<Result<_, _>>()?,
                ),
            };
            let stored = seed::StoredScope {
                name: spec.name.clone(),
                permissions,
            };
            let key = keys::encode_scope(realm_id, &spec.name);
            self.write_put(realm_id, &key, &Self::ser(&stored)?)?;
        }
        Ok(())
    }

    fn reconcile_protected_resources(
        &self,
        realm_id: &RealmId,
        resources: &[ProtectedResource],
    ) -> Result<(), RbacError> {
        for resource in resources {
            // Validate the resource URI.
            let uri = Uri::try_from(resource.resource_uri.clone()).map_err(|e| {
                RbacError::Serialization {
                    reason: format!("invalid resource URI '{}': {e}", resource.resource_uri),
                }
            })?;
            let hash = uri.storage_hash();

            for bundle in &resource.scopes {
                let permissions: Option<Vec<Permission>> = if bundle.permissions.is_empty() {
                    None
                } else {
                    Some(bundle.permissions.clone())
                };
                let stored = seed::StoredScope {
                    name: bundle.name.clone(),
                    permissions,
                };
                let key = keys::encode_resource_scope(realm_id, &hash, &bundle.name);
                self.write_put(realm_id, &key, &Self::ser(&stored)?)?;
            }
        }
        Ok(())
    }

    fn reconcile_groups(&self, realm_id: &RealmId, groups: &[Group]) -> Result<(), RbacError> {
        let now = self.clock.now();
        for group in groups {
            let slug = if group.slug.is_empty() {
                continue;
            } else {
                &group.slug
            };

            match self.load_group_id_by_slug(realm_id, slug)? {
                Some(gid) => {
                    if let Some(mut existing) = self.load_group(realm_id, &gid)? {
                        let drift = existing.name != group.name
                            || existing.description != group.description;
                        if drift {
                            existing.name.clone_from(&group.name);
                            existing.description.clone_from(&group.description);
                            existing.updated_at = now;
                            let group_key = keys::encode_group(&existing.id);
                            self.storage
                                .put(realm_id, &group_key, &Self::ser(&existing)?)?;
                        }
                    }
                }
                None => {
                    let new_group = Group {
                        id: GroupId::generate(),
                        realm_id: realm_id.clone(),
                        name: group.name.clone(),
                        slug: slug.clone(),
                        description: group.description.clone(),
                        created_at: now,
                        updated_at: now,
                    };
                    let group_key = keys::encode_group(&new_group.id);
                    let slug_key = keys::encode_group_slug(realm_id, slug);
                    self.write_put_batch(
                        realm_id,
                        &[
                            (group_key, Self::ser(&new_group)?),
                            (slug_key, Self::ser(&new_group.id)?),
                        ],
                    )?;
                }
            }
        }
        Ok(())
    }

    fn export_all_permissions(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<PermissionRecord>, RbacError> {
        let prefix = keys::permission_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let mut out = Vec::new();
        for entry in entries {
            let Ok(record) = Self::de::<PermissionRecord>(&entry.value) else {
                continue;
            };
            out.push(record);
        }
        Ok(out)
    }

    fn export_all_scopes(&self, realm_id: &RealmId) -> Result<Vec<ScopeExport>, RbacError> {
        let prefix = keys::scope_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let mut out = Vec::new();
        for entry in entries {
            let Ok(stored) = Self::de::<StoredScope>(&entry.value) else {
                continue;
            };
            out.push(ScopeExport {
                name: stored.name,
                permissions: stored.permissions,
            });
        }
        Ok(out)
    }

    fn export_all_assignments(&self, realm_id: &RealmId) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::ASSIGN_PRI_PREFIX.as_bytes().to_vec();
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let mut out = Vec::new();
        for entry in entries {
            let Ok(assignment) = Self::de::<RoleAssignment>(&entry.value) else {
                continue;
            };
            out.push(assignment);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn mk_engine() -> (EmbeddedRbacEngine, RealmId) {
        let tmp = tempfile::tempdir().expect("tmp");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf()))
                .expect("storage"),
        ) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1))) as Arc<dyn Clock>;
        std::mem::forget(tmp);
        (EmbeddedRbacEngine::new(storage, clock), RealmId::generate())
    }

    fn perm(s: &str) -> Permission {
        Permission::new(s).expect("valid perm")
    }

    /// A [`StorageEngine`] decorator that counts read operations (`get`,
    /// `scan`) so tests can prove the resolution decision cache actually
    /// avoids re-hitting storage on a hit. All writes and defaults delegate to
    /// the inner engine.
    struct CountingStorage {
        inner: Arc<dyn StorageEngine>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl CountingStorage {
        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl StorageEngine for CountingStorage {
        fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.get(realm_id, key)
        }
        fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put(realm_id, key, value)
        }
        fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(realm_id, key)
        }
        fn scan(
            &self,
            realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
        ) -> Result<Vec<crate::storage::ScanEntry>, StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.scan(realm_id, start, end)
        }
        fn put_batch(
            &self,
            realm_id: &RealmId,
            entries: &[(Vec<u8>, Vec<u8>)],
        ) -> Result<(), StorageError> {
            self.inner.put_batch(realm_id, entries)
        }
    }

    fn mk_counting_engine() -> (EmbeddedRbacEngine, Arc<CountingStorage>, RealmId) {
        let tmp = tempfile::tempdir().expect("tmp");
        let inner = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf()))
                .expect("storage"),
        ) as Arc<dyn StorageEngine>;
        std::mem::forget(tmp);
        let counting = Arc::new(CountingStorage {
            inner,
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let storage = counting.clone() as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1))) as Arc<dyn Clock>;
        (
            EmbeddedRbacEngine::new(storage, clock),
            counting,
            RealmId::generate(),
        )
    }

    fn assign(engine: &EmbeddedRbacEngine, realm: &RealmId, user: &UserId, role_id: &RoleId) {
        engine
            .assign_role(
                realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role_id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");
    }

    fn mk_role(engine: &EmbeddedRbacEngine, realm: &RealmId, name: &str, p: &str) -> RoleId {
        engine
            .create_role(
                realm,
                &CreateRoleRequest {
                    name: name.to_string(),
                    description: None,
                    permissions: vec![perm(p)],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create role")
            .id
    }

    // HEA-1770: the decision cache must (1) memoize repeated identical
    // resolutions so a hit performs zero storage reads, and (2) invalidate on
    // mutation so a re-issued token never carries a stale (pre-mutation)
    // permission set — a stale read here is a privilege-escalation bug.
    #[test]
    fn resolution_cache_memoizes_and_invalidates_on_mutation() {
        let (engine, storage, realm) = mk_counting_engine();
        engine.seed_realm(&realm).expect("seed");
        let user = UserId::generate();
        let role1 = mk_role(&engine, &realm, "viewer", "docs.view");
        assign(&engine, &realm, &user, &role1);

        // First resolution is a cache miss → touches storage.
        let r1 = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        assert!(r1.permissions.contains(&perm("docs.view")));
        let after_first = storage.reads();
        assert!(after_first > 0, "first resolve must read storage");

        // Second identical resolution is a hit → zero additional reads.
        let r2 = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        assert_eq!(r2, r1);
        assert_eq!(
            storage.reads(),
            after_first,
            "cache hit must not touch storage"
        );

        // Mutation must invalidate: grant a second permission via a new role.
        let role2 = mk_role(&engine, &realm, "editor", "docs.edit");
        assign(&engine, &realm, &user, &role2);

        let before_third = storage.reads();
        let r3 = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        assert!(
            storage.reads() > before_third,
            "post-mutation resolve must re-read storage (cache invalidated)"
        );
        assert!(
            r3.permissions.contains(&perm("docs.edit")),
            "resolution after mutation must reflect the new grant (no stale cache)"
        );
        assert!(r3.permissions.contains(&perm("docs.view")));
    }

    // Guards the invalidation path specifically for direct user-permission
    // revocation (a different mutation family than role assignment).
    #[test]
    fn resolution_cache_invalidates_on_permission_revoke() {
        let (engine, _storage, realm) = mk_counting_engine();
        engine.seed_realm(&realm).expect("seed");
        let user = UserId::generate();
        let grant = UserPermissionGrant {
            realm_id: realm.clone(),
            user_id: user.clone(),
            permission: perm("billing.read"),
            scope: Scope::Realm,
            granted_at: Timestamp::from_micros(1),
            granted_by: None,
        };
        engine.grant_user_permission(&realm, &grant).expect("grant");

        let r1 = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        assert!(r1.permissions.contains(&perm("billing.read")));

        engine
            .revoke_user_permission(&realm, &user, &perm("billing.read"), &Scope::Realm)
            .expect("revoke");

        let r2 = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        assert!(
            !r2.permissions.contains(&perm("billing.read")),
            "revoked permission must not survive in a cached resolution"
        );
    }

    #[test]
    fn create_and_get_role_roundtrip() {
        let (engine, realm) = mk_engine();
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "docs.viewer".to_string(),
                    description: Some("read docs".to_string()),
                    permissions: vec![perm("docs.view")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create");
        let fetched = RbacEngine::get_role(&engine, &realm, &role.id)
            .expect("get")
            .expect("some");
        assert_eq!(fetched.id, role.id);
        assert_eq!(fetched.name, "docs.viewer");

        let by_name = engine
            .get_role_by_name(&realm, "docs.viewer")
            .expect("get by name")
            .expect("some");
        assert_eq!(by_name.id, role.id);
    }

    #[test]
    fn duplicate_role_name_rejected() {
        let (engine, realm) = mk_engine();
        engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("first");
        let result = engine.create_role(
            &realm,
            &CreateRoleRequest {
                name: "r".to_string(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                ..Default::default()
            },
        );
        match result {
            Err(RbacError::DuplicateRoleName) => {}
            other => panic!("expected DuplicateRoleName, got {other:?}"),
        }
    }

    #[test]
    fn reserved_namespace_rejected_for_operator_role() {
        // Per AUTHZ_EXPANSION.md the global namespace is `hearth.*` —
        // operator-created roles may not include it directly.
        let (engine, realm) = mk_engine();
        let result = engine.create_role(
            &realm,
            &CreateRoleRequest {
                name: "evil".to_string(),
                description: None,
                permissions: vec![perm("hearth.admin")],
                parent_roles: vec![],
                ..Default::default()
            },
        );
        match result {
            Err(RbacError::ReservedNamespace { permission }) => {
                assert_eq!(permission, "hearth.admin");
            }
            other => panic!("expected ReservedNamespace, got {other:?}"),
        }
    }

    #[test]
    fn create_group_and_membership() {
        let (engine, realm) = mk_engine();
        let g = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "Engineering".to_string(),
                    slug: "eng".to_string(),
                    description: None,
                },
            )
            .expect("create group");
        let user = UserId::generate();
        engine
            .add_group_member(&realm, &g.id, &GroupMember::User(user.clone()))
            .expect("add member");

        let page = engine
            .list_group_members(&realm, &g.id, None, 100)
            .expect("list");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0], GroupMember::User(user));
    }

    #[test]
    fn duplicate_slug_rejected() {
        let (engine, realm) = mk_engine();
        engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "A".to_string(),
                    slug: "slug".to_string(),
                    description: None,
                },
            )
            .expect("first");
        let result = engine.create_group(
            &realm,
            &CreateGroupRequest {
                name: "B".to_string(),
                slug: "slug".to_string(),
                description: None,
            },
        );
        match result {
            Err(RbacError::DuplicateGroupSlug) => {}
            other => panic!("expected DuplicateGroupSlug, got {other:?}"),
        }
    }

    #[test]
    fn group_cycle_rejected_at_write_time() {
        let (engine, realm) = mk_engine();
        let a = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "A".to_string(),
                    slug: "a".to_string(),
                    description: None,
                },
            )
            .expect("a");
        let b = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "B".to_string(),
                    slug: "b".to_string(),
                    description: None,
                },
            )
            .expect("b");
        // A contains B.
        engine
            .add_group_member(&realm, &a.id, &GroupMember::Group(b.id.clone()))
            .expect("add b to a");
        // Adding A to B would create a cycle.
        let result = engine.add_group_member(&realm, &b.id, &GroupMember::Group(a.id.clone()));
        match result {
            Err(RbacError::CycleDetected {
                kind: CycleKind::GroupMembership,
                ..
            }) => {}
            other => panic!("expected group cycle, got {other:?}"),
        }
    }

    #[test]
    fn role_parent_cycle_rejected_at_update_time() {
        let (engine, realm) = mk_engine();
        let a = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "a".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("a");
        let b = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "b".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![a.id.clone()],
                    ..Default::default()
                },
            )
            .expect("b with parent a");
        // Now attempt to make A a child of B → cycle.
        let result = engine.update_role(
            &realm,
            &a.id,
            &UpdateRoleRequest {
                parent_roles: Some(vec![b.id.clone()]),
                ..UpdateRoleRequest::default()
            },
        );
        match result {
            Err(RbacError::CycleDetected {
                kind: CycleKind::RoleComposition,
                ..
            }) => {}
            other => panic!("expected role cycle, got {other:?}"),
        }
    }

    #[test]
    fn assign_and_unassign_role_to_user() {
        let (engine, realm) = mk_engine();
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![perm("docs.view")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        let user = UserId::generate();
        let a = engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let list = engine.list_user_assignments(&realm, &user).expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, a.id);

        engine.unassign_role(&realm, &a.id).expect("unassign");
        let list = engine.list_user_assignments(&realm, &user).expect("list");
        assert!(list.is_empty());
    }

    #[test]
    fn resolve_permissions_through_engine_returns_union() {
        let (engine, realm) = mk_engine();
        let r1 = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r1".to_string(),
                    description: None,
                    permissions: vec![perm("docs.view"), perm("docs.edit")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r1");
        let user = UserId::generate();
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: r1.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let resolved = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"docs.view"));
        assert!(names.contains(&"docs.edit"));
        assert_eq!(resolved.permissions.len(), 2);
    }

    #[test]
    fn resolve_is_realm_isolated() {
        let (engine, realm_a) = mk_engine();
        let realm_b = RealmId::generate();
        let r_a = engine
            .create_role(
                &realm_a,
                &CreateRoleRequest {
                    name: "only_in_a".to_string(),
                    description: None,
                    permissions: vec![perm("a.only")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        let user = UserId::generate();
        engine
            .assign_role(
                &realm_a,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: r_a.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        // Resolve in OTHER realm — must be empty.
        let resolved = engine
            .resolve_permissions(&user, &realm_b, None, None)
            .expect("resolve b");
        assert!(resolved.permissions.is_empty());
        assert!(resolved.roles.is_empty());
    }

    #[test]
    fn seed_realm_runs_and_is_idempotent() {
        let (engine, realm) = mk_engine();
        engine.seed_realm(&realm).expect("seed 1");
        let first = engine
            .get_role_by_name(&realm, "realm.admin")
            .expect("get")
            .expect("some");
        engine.seed_realm(&realm).expect("seed 2");
        let second = engine
            .get_role_by_name(&realm, "realm.admin")
            .expect("get")
            .expect("some");
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn seeded_realm_admin_resolves_with_hearth_admin() {
        let (engine, realm) = mk_engine();
        engine.seed_realm(&realm).expect("seed");
        let role = engine
            .get_role_by_name(&realm, "realm.admin")
            .expect("get")
            .expect("some");

        let user = UserId::generate();
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let resolved = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"hearth.admin"));
        assert!(names.contains(&"realm.admin"));
    }

    #[test]
    fn list_role_members_returns_assigned_subjects() {
        let (engine, realm) = mk_engine();
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        let user = UserId::generate();
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let page = engine
            .list_role_members(&realm, &role.id, None, 100)
            .expect("list");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0], RoleSubject::User(user));
    }

    #[test]
    fn delete_role_removes_name_index() {
        let (engine, realm) = mk_engine();
        let r = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "tmp".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        RbacEngine::delete_role(&engine, &realm, &r.id).expect("delete");
        assert!(RbacEngine::get_role(&engine, &realm, &r.id)
            .expect("get")
            .is_none());
        assert!(RbacEngine::get_role_by_name(&engine, &realm, "tmp")
            .expect("get by name")
            .is_none());
    }

    #[test]
    fn delete_group_cascades_members_and_assignments() {
        let (engine, realm) = mk_engine();
        let g = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "G".to_string(),
                    slug: "g".to_string(),
                    description: None,
                },
            )
            .expect("g");
        let user = UserId::generate();
        engine
            .add_group_member(&realm, &g.id, &GroupMember::User(user))
            .expect("add");
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::Group(g.id.clone()),
                    role_id: role.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign to group");

        engine.delete_group(&realm, &g.id).expect("delete");
        assert!(engine.get_group(&realm, &g.id).expect("get").is_none());
        assert!(engine
            .list_group_members(&realm, &g.id, None, 100)
            .expect("list")
            .items
            .is_empty());
        assert!(engine
            .list_group_assignments(&realm, &g.id)
            .expect("list asgn")
            .is_empty());
    }
}

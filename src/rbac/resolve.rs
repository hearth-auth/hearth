//! Permission resolution algorithm.
//!
//! Implements openspec/specs/rbac-model/spec.md: transitive group BFS, assignment
//! collection (filtered by realm/org scope), role composition DFS,
//! permission union, and OAuth-scope narrowing.
//!
//! This module is pure algorithm. It reads from the storage engine via a
//! small trait (`Resolver`) implemented by the embedded engine. Keeping
//! the traversal decoupled from the concrete engine makes property
//! testing (e.g. "cycles are rejected") self-contained.

use std::collections::{BTreeSet, HashSet, VecDeque};

use crate::core::{OrganizationId, RealmId, Uri, UserId};
use crate::identity::ClientTrustLevel;
use crate::rbac::registry::{classify_scope_string, ScopeKind};

use super::error::RbacError;
#[cfg(test)]
use super::types::Subject;
use super::types::{
    CycleKind, GroupId, GroupMember, OrphanKind, OrphanRef, Permission, ResolvedPermissions, Role,
    RoleAssignment, RoleId, RoleStatus, Scope, ScopeMode, ScopeRequest, TraversalKind,
    UserPermissionGrant,
};

/// Maximum depth for transitive group membership BFS.
pub(crate) const MAX_GROUP_DEPTH: usize = 10;
/// Maximum number of distinct groups any single user may be transitively in.
pub(crate) const MAX_GROUP_BREADTH: usize = 1000;
/// Maximum depth for role-composition DFS.
pub(crate) const MAX_ROLE_DEPTH: usize = 10;
/// Maximum permissions in a single resolved token (openspec/specs/rbac-model/spec.md).
pub(crate) const MAX_PERMISSIONS_PER_TOKEN: usize = 100;
/// Maximum role names in a single resolved token (openspec/specs/rbac-model/spec.md).
pub(crate) const MAX_ROLES_PER_TOKEN: usize = 50;
/// Maximum group names in a single resolved token (openspec/specs/rbac-model/spec.md).
pub(crate) const MAX_GROUPS_PER_TOKEN: usize = 50;

/// What a scope name maps to in a scope registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScopeLookup {
    /// The registry has no row for this name.
    Missing,
    /// A row that does not narrow: the seeded OIDC identifier scopes.
    NoNarrowing,
    /// A bundle and the permissions it grants.
    Bundle(Vec<Permission>),
}

/// Data-access surface the resolver needs.
///
/// Abstracting over this keeps `resolve.rs` concrete-engine-free and makes
/// test fakes trivial.
pub(crate) trait Resolver {
    /// Full (unnarrowed) effective resolution for `(user, realm, org?)`.
    ///
    /// The default computes fresh via [`resolve_full`]. The embedded engine
    /// overrides this with a per-realm-versioned decision cache (HEA-1770) so
    /// repeated token issuances for an unchanged graph avoid re-running the
    /// N+1 storage fan-out. Any implementation MUST return a value consistent
    /// with the current stored graph — a stale result is a privilege-escalation
    /// bug.
    fn resolve_full_cached(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
    ) -> Result<ResolvedPermissions, RbacError> {
        resolve_full(self, user_id, realm_id, org_id)
    }

    /// Groups that directly contain the given member.
    fn parent_groups_of(
        &self,
        realm_id: &RealmId,
        member: &GroupMember,
    ) -> Result<Vec<GroupId>, RbacError>;

    /// Role assignments directly bound to a user (no transitive expansion).
    fn user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Role assignments directly bound to a group.
    fn group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Fetch a role by ID. Returns `None` if it has been deleted.
    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError>;

    /// Fetch a group by ID (used to convert `GroupId` → slug for output).
    fn get_group_slug(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<String>, RbacError>;

    /// What a scope value maps to in the realm-level scope registry.
    fn scope_permissions(
        &self,
        realm_id: &RealmId,
        scope_name: &str,
    ) -> Result<ScopeLookup, RbacError>;

    /// What a scope value maps to in a protected resource's scope registry.
    fn resource_scope_permissions(
        &self,
        realm_id: &RealmId,
        resource_uri: &Uri,
        scope_name: &str,
    ) -> Result<ScopeLookup, RbacError>;

    /// Direct extra permissions granted to a user.
    fn user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError>;

    /// Fetch a role ID by its (realm-unique) name. Returns `None` if not found.
    fn get_role_id_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<RoleId>, RbacError>;

    /// Whether the realm's registry holds `permission` as an archived entry:
    /// one that `hearth.yaml` declared and later removed. A permission with no
    /// registry record at all (a realm with no YAML vocabulary) is not
    /// archived.
    fn permission_archived(
        &self,
        realm_id: &RealmId,
        permission: &Permission,
    ) -> Result<bool, RbacError>;

    /// Extra org-scoped role names for a user within the given organization.
    ///
    /// Returns an empty vec when there are no additional roles stored for the
    /// user in that org.
    fn additional_roles(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Vec<String>, RbacError>;
}

/// Full (unnarrowed) effective resolution for `(user, realm, org?)`.
///
/// This is the expensive graph traversal — transitive group BFS, assignment
/// collection, role-composition DFS, and group-slug materialization. Scope
/// narrowing and token-size caps are layered on by [`resolve_permissions`], so
/// the value here depends only on the stored RBAC graph. That is what lets the
/// embedded engine memoize it keyed by a per-realm graph version (the decision
/// cache, HEA-1770).
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub(crate) fn resolve_full<R: Resolver + ?Sized>(
    resolver: &R,
    user_id: &UserId,
    realm_id: &RealmId,
    org_id: Option<&OrganizationId>,
) -> Result<ResolvedPermissions, RbacError> {
    // ----- Step 1: transitive group membership BFS -----
    let groups = bfs_groups(resolver, realm_id, user_id)?;

    // ----- Step 2: gather reachable assignments, filtered by scope -----
    let mut assignments: Vec<RoleAssignment> = Vec::new();
    for ra in resolver.user_assignments(realm_id, user_id)? {
        if assignment_applies(&ra, org_id) {
            assignments.push(ra);
        }
    }
    for gid in &groups {
        for ra in resolver.group_assignments(realm_id, gid)? {
            if assignment_applies(&ra, org_id) {
                assignments.push(ra);
            }
        }
    }

    // ----- Step 3: role composition DFS -----
    let mut role_names: BTreeSet<String> = BTreeSet::new();
    let mut perms: BTreeSet<Permission> = BTreeSet::new();
    let mut visited: HashSet<RoleId> = HashSet::new();
    let mut path: HashSet<RoleId> = HashSet::new();
    let mut orphans: BTreeSet<OrphanRef> = BTreeSet::new();
    for ra in &assignments {
        expand_role(
            resolver,
            realm_id,
            &ra.role_id,
            &mut RoleWalk {
                role_names: &mut role_names,
                perms: &mut perms,
                visited: &mut visited,
                path: &mut path,
                orphans: &mut orphans,
            },
            0,
        )?;
    }

    // ----- Step 4: extra direct permissions + additional org roles -----
    for extra in resolver.user_permissions(realm_id, user_id)? {
        if extra_applies(&extra, org_id) {
            perms.insert(extra.permission);
        }
    }

    // When resolving in an org context, expand any additional org-scoped
    // roles stored on the membership record.
    if let Some(oid) = org_id {
        for name in resolver.additional_roles(realm_id, oid, user_id)? {
            match resolver.get_role_id_by_name(realm_id, &name)? {
                Some(rid) => {
                    expand_role(
                        resolver,
                        realm_id,
                        &rid,
                        &mut RoleWalk {
                            role_names: &mut role_names,
                            perms: &mut perms,
                            visited: &mut visited,
                            path: &mut path,
                            orphans: &mut orphans,
                        },
                        0,
                    )?;
                }
                None => {
                    orphans.insert(OrphanRef {
                        kind: OrphanKind::RoleName,
                        reference: name,
                    });
                }
            }
        }
    }

    // ----- Step 4b: drop permissions the registry has archived -----
    // Resolution is the single enforcement point for a registry entry that
    // `hearth.yaml` removed (custom-permissions "Registry reload is lazy and
    // non-destructive"): the grant stays in storage, but it is not granted.
    let mut archived: Vec<Permission> = Vec::new();
    for p in &perms {
        if resolver.permission_archived(realm_id, p)? {
            archived.push(p.clone());
        }
    }
    for p in archived {
        perms.remove(&p);
        orphans.insert(OrphanRef {
            kind: OrphanKind::Permission,
            reference: p.as_str().to_string(),
        });
    }

    // ----- Step 5: group slugs for JWT claim -----
    let mut group_slugs: BTreeSet<String> = BTreeSet::new();
    for gid in &groups {
        if let Some(slug) = resolver.get_group_slug(realm_id, gid)? {
            group_slugs.insert(slug);
        }
    }

    // Scope narrowing and per-token size caps are applied by
    // `resolve_permissions` on top of this full set.
    Ok(ResolvedPermissions {
        roles: role_names.into_iter().collect(),
        groups: group_slugs.into_iter().collect(),
        permissions: perms.into_iter().collect(),
        granted_scopes: Vec::new(),
        orphans: orphans.into_iter().collect(),
        scope_narrowed: false,
    })
}

/// Enforces the per-token size caps (openspec/specs/rbac-model/spec.md). Hard caps prevent
/// oversized JWTs from escaping the issuance path.
pub(crate) fn enforce_token_caps(
    permissions: &[Permission],
    roles: &[String],
    groups: &[String],
) -> Result<(), RbacError> {
    if permissions.len() > MAX_PERMISSIONS_PER_TOKEN {
        return Err(RbacError::TokenSizeExceeded {
            limit: "permissions_per_token".to_string(),
            limit_value: MAX_PERMISSIONS_PER_TOKEN,
            actual: permissions.len(),
        });
    }
    if roles.len() > MAX_ROLES_PER_TOKEN {
        return Err(RbacError::TokenSizeExceeded {
            limit: "roles_per_token".to_string(),
            limit_value: MAX_ROLES_PER_TOKEN,
            actual: roles.len(),
        });
    }
    if groups.len() > MAX_GROUPS_PER_TOKEN {
        return Err(RbacError::TokenSizeExceeded {
            limit: "groups_per_token".to_string(),
            limit_value: MAX_GROUPS_PER_TOKEN,
            actual: groups.len(),
        });
    }
    Ok(())
}

/// Core algorithm: resolve `(user, realm, org?, scope?)` → `ResolvedPermissions`.
///
/// Delegates the expensive graph traversal to [`Resolver::resolve_full_cached`]
/// (memoized by the embedded engine), then applies optional OAuth-scope
/// narrowing and the per-token size caps. Because narrowing and caps run here
/// rather than inside the cached traversal, behavior is identical to the
/// pre-cache single-pass implementation.
pub(crate) fn resolve_permissions<R: Resolver + ?Sized>(
    resolver: &R,
    user_id: &UserId,
    realm_id: &RealmId,
    org_id: Option<&OrganizationId>,
    requested_scope: Option<&str>,
) -> Result<ResolvedPermissions, RbacError> {
    let ResolvedPermissions {
        roles,
        groups,
        permissions: full_perms,
        orphans,
        ..
    } = resolver.resolve_full_cached(user_id, realm_id, org_id)?;

    let permissions: Vec<Permission> = match requested_scope {
        Some(scope_str) => narrow_by_scope(
            resolver,
            realm_id,
            scope_str,
            full_perms.into_iter().collect(),
        )?,
        None => full_perms,
    };

    enforce_token_caps(&permissions, &roles, &groups)?;

    Ok(ResolvedPermissions {
        roles,
        groups,
        permissions,
        granted_scopes: Vec::new(),
        orphans,
        scope_narrowed: false,
    })
}

/// What one requested scope is, once classified against the selected
/// registry.
enum ScopeEntry {
    /// An OIDC standard scope: always grantable, no permissions.
    Oidc,
    /// A bundle (or a bare-word realm scope) and its permissions, or a raw
    /// permission scope as a one-permission bundle.
    Bearing(Vec<Permission>),
}

fn invalid_scope(reason: String) -> RbacError {
    RbacError::InvalidScope { reason }
}

/// Classifies `scope` against the registry the audience selects
/// (custom-permissions "The token audience selects the scope registry").
/// A name the selected registry does not define is refused.
fn classify_requested_scope<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    scope: &str,
    request: &ScopeRequest<'_>,
) -> Result<ScopeEntry, RbacError> {
    let unknown = || invalid_scope(format!("unknown scope '{scope}'"));
    match classify_scope_string(scope) {
        Some(ScopeKind::OidcStandard) => Ok(ScopeEntry::Oidc),
        Some(ScopeKind::Permission) => {
            if request.resource.is_some() {
                return Err(invalid_scope(format!(
                    "raw permission scope '{scope}' is not legal under a resource"
                )));
            }
            if request.trust_level == ClientTrustLevel::ThirdParty {
                return Err(invalid_scope(format!(
                    "third-party clients cannot request raw permission scope '{scope}'"
                )));
            }
            let permission = Permission::new(scope).map_err(|_| unknown())?;
            Ok(ScopeEntry::Bearing(vec![permission]))
        }
        kind => {
            // A bundle, or a bare word that only the realm registry may define.
            let lookup = match request.resource {
                Some(uri) if kind == Some(ScopeKind::Bundle) => {
                    resolver.resource_scope_permissions(realm_id, uri, scope)?
                }
                Some(_) => return Err(unknown()),
                None => resolver.scope_permissions(realm_id, scope)?,
            };
            match lookup {
                ScopeLookup::Bundle(list) => Ok(ScopeEntry::Bearing(list)),
                ScopeLookup::Missing | ScopeLookup::NoNarrowing => Err(unknown()),
            }
        }
    }
}

/// The scope-resolution entry point (`scope-consent-integrity` design §2).
///
/// - Every scope must be legal for the audience: an OIDC standard scope, a
///   bundle of the selected registry, or (first-party, no resource) a raw
///   permission. Anything else is refused with `InvalidScope`, in both modes.
/// - In [`ScopeMode::Request`], a non-empty `declared_scopes` must hold every
///   non-OIDC scope.
/// - A bundle is grantable only when the user holds every permission of it.
///   With no user (`client_credentials`), every legal scope is granted and
///   carries no permissions.
/// - An ungrantable scope refuses a third-party request; otherwise it drops.
///   When scopes were asked for and none is granted, the call is refused.
/// - `permissions` is the union of the granted permission-bearing scopes.
///   When only OIDC scopes (or none) were asked for, a first-party client gets
///   the user's full effective set and a third-party client gets nothing.
pub(crate) fn resolve_with_scopes<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    request: &ScopeRequest<'_>,
) -> Result<ResolvedPermissions, RbacError> {
    let first_party = request.trust_level == ClientTrustLevel::FirstParty;
    if request.requested.is_empty() && !first_party && request.mode == ScopeMode::Request {
        return Err(invalid_scope(
            "third-party clients must request at least one scope".to_string(),
        ));
    }

    // The full set, uncapped: the per-token caps apply to what a token
    // carries, after narrowing (see `enforce_token_caps`).
    let full = match request.user_id {
        Some(user_id) => Some(resolver.resolve_full_cached(user_id, realm_id, request.org_id)?),
        None => None,
    };
    let effective: BTreeSet<&Permission> = full
        .as_ref()
        .map(|f| f.permissions.iter().collect())
        .unwrap_or_default();

    let mut granted_scopes: Vec<String> = Vec::new();
    let mut admitted: BTreeSet<Permission> = BTreeSet::new();
    let mut named_bearing = request.narrowed;
    for scope in request.requested {
        let entry = classify_requested_scope(resolver, realm_id, scope, request)?;
        let ScopeEntry::Bearing(perms) = entry else {
            granted_scopes.push(scope.clone());
            continue;
        };
        named_bearing = true;
        if request.mode == ScopeMode::Request
            && !request.declared.is_empty()
            && !request.declared.contains(scope)
        {
            return Err(invalid_scope(format!(
                "scope '{scope}' is not in the client's declared_scopes"
            )));
        }
        let grantable = full.is_none() || perms.iter().all(|p| effective.contains(p));
        if grantable {
            granted_scopes.push(scope.clone());
            if full.is_some() {
                admitted.extend(perms);
            }
        } else if !first_party && request.mode == ScopeMode::Request {
            return Err(invalid_scope(format!(
                "the user does not hold every permission of scope '{scope}'"
            )));
        }
    }
    if !request.requested.is_empty() && granted_scopes.is_empty() {
        return Err(invalid_scope(
            "no requested scope could be granted".to_string(),
        ));
    }

    let Some(full) = full else {
        return Ok(ResolvedPermissions {
            granted_scopes,
            scope_narrowed: named_bearing,
            ..ResolvedPermissions::default()
        });
    };
    let permissions: Vec<Permission> = if named_bearing {
        full.permissions
            .into_iter()
            .filter(|p| admitted.contains(p))
            .collect()
    } else if first_party {
        full.permissions
    } else {
        Vec::new()
    };
    Ok(ResolvedPermissions {
        roles: full.roles,
        groups: full.groups,
        permissions,
        granted_scopes,
        orphans: full.orphans,
        scope_narrowed: named_bearing,
    })
}

fn extra_applies(extra: &UserPermissionGrant, org_id: Option<&OrganizationId>) -> bool {
    match &extra.scope {
        Scope::Realm => true,
        Scope::Org { org_id: oid } => org_id.is_some_and(|requested| requested == oid),
    }
}

/// Returns true if a role assignment applies given the optional org context.
fn assignment_applies(ra: &RoleAssignment, org_id: Option<&OrganizationId>) -> bool {
    match &ra.scope {
        Scope::Realm => true,
        Scope::Org { org_id: oid } => match org_id {
            Some(requested) => requested == oid,
            None => false,
        },
    }
}

/// Every organization named by an org-scoped source of `user_id`'s
/// permissions: its own org-scoped role assignments, those of every group it
/// belongs to (transitively), and its org-scoped direct grants.
///
/// [`resolve_full`] honours these for any requested organization without
/// consulting organization membership, so a caller that must see all of a
/// user's authority (the admin privilege ceiling) resolves each of them.
pub(crate) fn org_contexts<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<BTreeSet<OrganizationId>, RbacError> {
    let mut orgs = BTreeSet::new();
    let mut note = |scope: &Scope| {
        if let Scope::Org { org_id } = scope {
            orgs.insert(org_id.clone());
        }
    };
    for ra in resolver.user_assignments(realm_id, user_id)? {
        note(&ra.scope);
    }
    for gid in bfs_groups(resolver, realm_id, user_id)? {
        for ra in resolver.group_assignments(realm_id, &gid)? {
            note(&ra.scope);
        }
    }
    for grant in resolver.user_permissions(realm_id, user_id)? {
        note(&grant.scope);
    }
    Ok(orgs)
}

/// Transitive group-membership BFS with cycle detection and breadth cap.
///
/// Walks reverse edges (member → containing-group) starting from the user.
/// Returns the distinct set of groups the user ends up in.
fn bfs_groups<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<Vec<GroupId>, RbacError> {
    let mut visited: HashSet<GroupId> = HashSet::new();
    // BFS queue: (member, depth_from_user).
    let mut queue: VecDeque<(GroupMember, usize)> = VecDeque::new();
    queue.push_back((GroupMember::User(user_id.clone()), 0));

    while let Some((member, depth)) = queue.pop_front() {
        // The user itself contributes no group until its parents are examined.
        let parents = resolver.parent_groups_of(realm_id, &member)?;

        let next_depth = depth + 1;

        for parent in parents {
            // Cycle detection: if we've already visited this group from the
            // same user we simply skip — this is safe because the visited
            // set is bounded by the realm's group set and each group is
            // explored at most once.
            if !visited.insert(parent.clone()) {
                continue;
            }

            if visited.len() > MAX_GROUP_BREADTH {
                return Err(RbacError::BreadthExceeded {
                    kind: TraversalKind::GroupMembership,
                    limit: MAX_GROUP_BREADTH,
                });
            }

            if next_depth > MAX_GROUP_DEPTH {
                return Err(RbacError::DepthExceeded {
                    kind: TraversalKind::GroupMembership,
                    limit: MAX_GROUP_DEPTH,
                });
            }

            queue.push_back((GroupMember::Group(parent), next_depth));
        }
    }

    Ok(visited.into_iter().collect())
}

/// The mutable state of one role-composition walk.
struct RoleWalk<'a> {
    role_names: &'a mut BTreeSet<String>,
    perms: &'a mut BTreeSet<Permission>,
    visited: &'a mut HashSet<RoleId>,
    path: &'a mut HashSet<RoleId>,
    orphans: &'a mut BTreeSet<OrphanRef>,
}

/// DFS role composition expansion.
///
/// - Skips a role whose ID isn't found (a dangling parent edge) or that the
///   registry has archived, and records it as an orphan.
/// - Rejects cycles with `CycleDetected`.
/// - Enforces `MAX_ROLE_DEPTH`.
fn expand_role<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    role_id: &RoleId,
    walk: &mut RoleWalk<'_>,
    depth: usize,
) -> Result<(), RbacError> {
    if depth > MAX_ROLE_DEPTH {
        return Err(RbacError::DepthExceeded {
            kind: TraversalKind::RoleComposition,
            limit: MAX_ROLE_DEPTH,
        });
    }

    // Cycle detection must come before the diamond check:
    // if the role is already on the current DFS path, it's a true
    // cycle (e.g. A→B→C→A or self-edge A→A). The visited set
    // handles diamonds (shared ancestors) correctly below.
    if !walk.path.insert(role_id.clone()) {
        return Err(RbacError::CycleDetected {
            kind: CycleKind::RoleComposition,
            entity: role_id.to_string(),
        });
    }

    // Diamond check: already fully expanded by another branch.
    // Safe to stop — permissions are already collected.
    if walk.visited.contains(role_id) {
        walk.path.remove(role_id);
        return Ok(());
    }

    let role = match resolver.get_role(realm_id, role_id)? {
        Some(role) if role.status != RoleStatus::Archived => role,
        found => {
            // A dangling edge (the role was deleted) or a role that
            // `hearth.yaml` removed: tolerate it at resolve time and report it.
            walk.orphans.insert(OrphanRef {
                kind: OrphanKind::Role,
                reference: found.map_or_else(|| role_id.to_string(), |r| r.name),
            });
            walk.path.remove(role_id);
            return Ok(());
        }
    };

    walk.visited.insert(role_id.clone());

    walk.role_names.insert(role.name.clone());
    for p in &role.permissions {
        walk.perms.insert(p.clone());
    }

    for parent in &role.parent_roles {
        expand_role(resolver, realm_id, parent, walk, depth + 1)?;
    }

    walk.path.remove(role_id);
    Ok(())
}

/// Resolves the transitive (direct + inherited via parent chain) permission set of a single role.
///
/// Used by protocol handlers to enforce privilege-ceiling checks on role assignment:
/// the assigning principal must hold a superset of the assigned role's effective permissions.
pub(crate) fn expand_role_permissions<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    role_id: &RoleId,
) -> Result<BTreeSet<Permission>, RbacError> {
    let mut role_names = BTreeSet::new();
    let mut perms = BTreeSet::new();
    let mut visited = HashSet::new();
    let mut path = HashSet::new();
    let mut orphans = BTreeSet::new();
    expand_role(
        resolver,
        realm_id,
        role_id,
        &mut RoleWalk {
            role_names: &mut role_names,
            perms: &mut perms,
            visited: &mut visited,
            path: &mut path,
            orphans: &mut orphans,
        },
        0,
    )?;
    // What the role grants, as resolution would grant it.
    let mut granted = BTreeSet::new();
    for p in perms {
        if !resolver.permission_archived(realm_id, &p)? {
            granted.insert(p);
        }
    }
    Ok(granted)
}

/// Narrow a permission set by an OAuth scope's declared permissions.
///
/// If the scope resolves to `None`, no narrowing occurs (e.g. `openid`,
/// `profile`, `email`). If it resolves to an empty `Vec`, the intersection
/// is empty — the caller will issue a token with zero permissions.
fn narrow_by_scope<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    scope_str: &str,
    perms: BTreeSet<Permission>,
) -> Result<Vec<Permission>, RbacError> {
    // Scope string is space-delimited per OAuth 2.0. We take the UNION of
    // each scope's permission set, then intersect the user's perms with
    // that union. `openid`-style scopes with no mapping are treated as
    // "no narrowing from this scope value" and contribute the full set.
    let mut any_nonfilter = false;
    let mut allowed: BTreeSet<Permission> = BTreeSet::new();

    for scope_name in scope_str.split_whitespace() {
        match resolver.scope_permissions(realm_id, scope_name)? {
            ScopeLookup::NoNarrowing => {
                // No-filter scope — the entire original set is admitted.
                any_nonfilter = true;
            }
            ScopeLookup::Bundle(list) => {
                for p in list {
                    allowed.insert(p);
                }
            }
            // A scope the registry does not know admits nothing.
            ScopeLookup::Missing => {}
        }
    }

    if any_nonfilter {
        // At least one scope is non-filtering → no narrowing applied.
        return Ok(perms.into_iter().collect());
    }

    Ok(perms.into_iter().filter(|p| allowed.contains(p)).collect())
}

// ---------------------------------------------------------------------------
// Tests (using an in-memory resolver)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;
    use std::collections::HashMap;

    struct Fake {
        // member-uuid (discriminator+id) -> parent group ids
        parents: HashMap<String, Vec<GroupId>>,
        // user -> assignments
        user_asgn: HashMap<UserId, Vec<RoleAssignment>>,
        // group -> assignments
        group_asgn: HashMap<GroupId, Vec<RoleAssignment>>,
        roles: HashMap<RoleId, Role>,
        group_slugs: HashMap<GroupId, String>,
        scopes: HashMap<String, Option<Vec<Permission>>>,
        user_perms: HashMap<UserId, Vec<UserPermissionGrant>>,
        resource_scopes: HashMap<String, HashMap<String, Option<Vec<Permission>>>>,
        archived: HashSet<Permission>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                parents: HashMap::new(),
                user_asgn: HashMap::new(),
                group_asgn: HashMap::new(),
                roles: HashMap::new(),
                group_slugs: HashMap::new(),
                scopes: HashMap::new(),
                user_perms: HashMap::new(),
                resource_scopes: HashMap::new(),
                archived: HashSet::new(),
            }
        }

        fn key_of(m: &GroupMember) -> String {
            match m {
                GroupMember::User(u) => format!("u:{}", u.as_uuid()),
                GroupMember::Group(g) => format!("g:{}", g.as_uuid()),
            }
        }

        fn add_parent(&mut self, child: &GroupMember, parent: GroupId) {
            self.parents
                .entry(Self::key_of(child))
                .or_default()
                .push(parent);
        }

        fn upsert_role(&mut self, role: Role) {
            self.roles.insert(role.id.clone(), role);
        }

        fn upsert_group_slug(&mut self, g: &GroupId, slug: &str) {
            self.group_slugs.insert(g.clone(), slug.to_string());
        }

        fn set_scope(&mut self, name: &str, perms: Option<Vec<Permission>>) {
            self.scopes.insert(name.to_string(), perms);
        }
    }

    /// Maps a fake registry row the way the engine maps a stored one.
    fn lookup(row: Option<&Option<Vec<Permission>>>) -> ScopeLookup {
        match row {
            None => ScopeLookup::Missing,
            Some(None) => ScopeLookup::NoNarrowing,
            Some(Some(list)) => ScopeLookup::Bundle(list.clone()),
        }
    }

    impl Resolver for Fake {
        fn parent_groups_of(
            &self,
            _r: &RealmId,
            member: &GroupMember,
        ) -> Result<Vec<GroupId>, RbacError> {
            Ok(self
                .parents
                .get(&Self::key_of(member))
                .cloned()
                .unwrap_or_default())
        }

        fn user_assignments(
            &self,
            _r: &RealmId,
            user_id: &UserId,
        ) -> Result<Vec<RoleAssignment>, RbacError> {
            Ok(self.user_asgn.get(user_id).cloned().unwrap_or_default())
        }

        fn group_assignments(
            &self,
            _r: &RealmId,
            group_id: &GroupId,
        ) -> Result<Vec<RoleAssignment>, RbacError> {
            Ok(self.group_asgn.get(group_id).cloned().unwrap_or_default())
        }

        fn get_role(&self, _r: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
            Ok(self.roles.get(role_id).cloned())
        }

        fn get_group_slug(
            &self,
            _r: &RealmId,
            group_id: &GroupId,
        ) -> Result<Option<String>, RbacError> {
            Ok(self.group_slugs.get(group_id).cloned())
        }

        fn scope_permissions(
            &self,
            _r: &RealmId,
            scope_name: &str,
        ) -> Result<ScopeLookup, RbacError> {
            Ok(lookup(self.scopes.get(scope_name)))
        }

        fn user_permissions(
            &self,
            _r: &RealmId,
            user_id: &UserId,
        ) -> Result<Vec<UserPermissionGrant>, RbacError> {
            Ok(self.user_perms.get(user_id).cloned().unwrap_or_default())
        }

        fn get_role_id_by_name(
            &self,
            _r: &RealmId,
            name: &str,
        ) -> Result<Option<RoleId>, RbacError> {
            Ok(self
                .roles
                .values()
                .find(|r| r.name == name)
                .map(|r| r.id.clone()))
        }

        fn additional_roles(
            &self,
            _r: &RealmId,
            _org_id: &OrganizationId,
            _user_id: &UserId,
        ) -> Result<Vec<String>, RbacError> {
            Ok(Vec::new())
        }

        fn permission_archived(
            &self,
            _r: &RealmId,
            permission: &Permission,
        ) -> Result<bool, RbacError> {
            Ok(self.archived.contains(permission))
        }

        fn resource_scope_permissions(
            &self,
            _r: &RealmId,
            resource_uri: &Uri,
            scope_name: &str,
        ) -> Result<ScopeLookup, RbacError> {
            Ok(lookup(
                self.resource_scopes
                    .get(resource_uri.as_str())
                    .and_then(|scopes| scopes.get(scope_name)),
            ))
        }
    }

    fn mk_role(realm: &RealmId, name: &str, perms: &[&str], parents: Vec<RoleId>) -> Role {
        Role {
            id: RoleId::generate(),
            realm_id: realm.clone(),
            name: name.to_string(),
            description: None,
            permissions: perms
                .iter()
                .map(|p| Permission::new(*p).expect("valid perm in test"))
                .collect(),
            parent_roles: parents,
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            status: crate::rbac::RoleStatus::Active,
            yaml_managed: false,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        }
    }

    fn mk_asgn(realm: &RealmId, subject: Subject, role_id: RoleId, scope: Scope) -> RoleAssignment {
        RoleAssignment {
            id: crate::rbac::types::AssignmentId::generate(),
            realm_id: realm.clone(),
            subject,
            role_id,
            scope,
            assigned_at: Timestamp::from_micros(1),
            assigned_by: None,
        }
    }

    // === Worked example (openspec/specs/rbac-model/spec.md) ===

    #[test]
    fn worked_example_resolves_to_union_of_docs_perms() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let leads = GroupId::generate();
        let engineers = GroupId::generate();

        let mut fake = Fake::new();
        fake.upsert_group_slug(&leads, "leads");
        fake.upsert_group_slug(&engineers, "engineers");
        // alice → leads
        fake.add_parent(&GroupMember::User(alice.clone()), leads.clone());
        // leads → engineers
        fake.add_parent(&GroupMember::Group(leads.clone()), engineers.clone());

        let docs_editor = mk_role(&realm, "docs.editor", &["docs.view", "docs.edit"], vec![]);
        let docs_admin = mk_role(
            &realm,
            "docs.admin",
            &["docs.delete"],
            vec![docs_editor.id.clone()],
        );
        let editor_id = docs_editor.id.clone();
        let admin_id = docs_admin.id.clone();
        fake.upsert_role(docs_editor);
        fake.upsert_role(docs_admin);

        // engineers → docs.editor, leads → docs.admin (both realm-scoped)
        fake.group_asgn.insert(
            engineers.clone(),
            vec![mk_asgn(
                &realm,
                Subject::Group(engineers.clone()),
                editor_id,
                Scope::Realm,
            )],
        );
        fake.group_asgn.insert(
            leads.clone(),
            vec![mk_asgn(
                &realm,
                Subject::Group(leads.clone()),
                admin_id,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"docs.view"));
        assert!(names.contains(&"docs.edit"));
        assert!(names.contains(&"docs.delete"));
        assert_eq!(resolved.permissions.len(), 3, "expected exactly 3");
        assert!(resolved.roles.contains(&"docs.admin".to_string()));
        assert!(resolved.roles.contains(&"docs.editor".to_string()));
        assert!(resolved.groups.contains(&"leads".to_string()));
        assert!(resolved.groups.contains(&"engineers".to_string()));
    }

    #[test]
    fn org_scope_only_applies_with_matching_oid() {
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let org_a = OrganizationId::generate();
        let org_b = OrganizationId::generate();

        let role = mk_role(&realm, "org.member", &["org.read"], vec![]);
        let role_id = role.id.clone();

        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                role_id,
                Scope::Org {
                    org_id: org_a.clone(),
                },
            )],
        );

        // No org context — assignment should NOT apply.
        let none = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        assert_eq!(none.permissions, [] as [crate::rbac::types::Permission; 0]);

        // Matching org — applies.
        let r_a = resolve_permissions(&fake, &alice, &realm, Some(&org_a), None).expect("resolve");
        assert_eq!(r_a.permissions.len(), 1);

        // Different org — does NOT apply.
        let r_b = resolve_permissions(&fake, &alice, &realm, Some(&org_b), None).expect("resolve");
        assert_eq!(r_b.permissions, [] as [crate::rbac::types::Permission; 0]);
    }

    #[test]
    fn role_cycle_self_edge_returns_cycle_error() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        // Build a role whose parent list points to itself.
        let id = RoleId::generate();
        let role = Role {
            id: id.clone(),
            realm_id: realm.clone(),
            name: "r1".to_string(),
            description: None,
            permissions: vec![],
            parent_roles: vec![id.clone()],
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            status: crate::rbac::RoleStatus::Active,
            yaml_managed: false,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        };

        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                id,
                Scope::Realm,
            )],
        );

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::CycleDetected {
                kind: CycleKind::RoleComposition,
                ..
            }) => {}
            other => panic!("expected role-composition cycle, got {other:?}"),
        }
    }

    #[test]
    fn role_cycle_three_hop_returns_cycle_error() {
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let id_a = RoleId::generate();
        let id_b = RoleId::generate();
        let id_c = RoleId::generate();

        let mk = |id: &RoleId, name: &str, parent: &RoleId| Role {
            id: id.clone(),
            realm_id: realm.clone(),
            name: name.to_string(),
            description: None,
            permissions: vec![],
            parent_roles: vec![parent.clone()],
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            status: crate::rbac::RoleStatus::Active,
            yaml_managed: false,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        };

        let mut fake = Fake::new();
        fake.upsert_role(mk(&id_a, "a", &id_b));
        fake.upsert_role(mk(&id_b, "b", &id_c));
        fake.upsert_role(mk(&id_c, "c", &id_a));
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                id_a,
                Scope::Realm,
            )],
        );

        match resolve_permissions(&fake, &alice, &realm, None, None) {
            Err(RbacError::CycleDetected {
                kind: CycleKind::RoleComposition,
                ..
            }) => {}
            other => panic!("expected CycleDetected, got {other:?}"),
        }
    }

    #[test]
    fn role_diamond_does_not_false_positive_as_cycle() {
        // A → B, A → C, B → D, C → D. D reached twice but no cycle.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let d = mk_role(&realm, "d", &["p.d"], vec![]);
        let b = mk_role(&realm, "b", &["p.b"], vec![d.id.clone()]);
        let c = mk_role(&realm, "c", &["p.c"], vec![d.id.clone()]);
        let a = mk_role(&realm, "a", &["p.a"], vec![b.id.clone(), c.id.clone()]);
        let a_id = a.id.clone();

        let mut fake = Fake::new();
        fake.upsert_role(a);
        fake.upsert_role(b);
        fake.upsert_role(c);
        fake.upsert_role(d);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                a_id,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        assert_eq!(resolved.permissions.len(), 4, "expected p.a, p.b, p.c, p.d");
    }

    #[test]
    fn role_depth_exceeds_limit_returns_error() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let mut ids: Vec<RoleId> = (0..=(MAX_ROLE_DEPTH + 2))
            .map(|_| RoleId::generate())
            .collect();
        ids.reverse();

        // Chain: ids[0] → ids[1] → ... → ids[last]
        let mut fake = Fake::new();
        for window in ids.windows(2) {
            let child = &window[0];
            let parent = &window[1];
            fake.upsert_role(Role {
                id: child.clone(),
                realm_id: realm.clone(),
                name: format!("r_{}", child.as_uuid()),
                description: None,
                permissions: vec![],
                parent_roles: vec![parent.clone()],
                scope_kind: crate::rbac::RoleScopeKind::Realm,
                status: crate::rbac::RoleStatus::Active,
                yaml_managed: false,
                created_at: Timestamp::from_micros(1),
                updated_at: Timestamp::from_micros(1),
            });
        }
        // Final leaf role has no parents.
        let leaf = ids.last().expect("ids non-empty").clone();
        fake.upsert_role(Role {
            id: leaf,
            realm_id: realm.clone(),
            name: "leaf".to_string(),
            description: None,
            permissions: vec![],
            parent_roles: vec![],
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            status: crate::rbac::RoleStatus::Active,
            yaml_managed: false,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        });

        let head = ids.first().expect("ids non-empty").clone();
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                head,
                Scope::Realm,
            )],
        );

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::DepthExceeded {
                kind: TraversalKind::RoleComposition,
                limit,
            }) => assert_eq!(limit, MAX_ROLE_DEPTH),
            other => panic!("expected role DepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn group_depth_exceeds_limit_returns_error() {
        // Build a chain alice ∈ g0 ∈ g1 ∈ ... ∈ g_{MAX_GROUP_DEPTH+2}. The
        // BFS increments depth each hop; once it crosses MAX_GROUP_DEPTH
        // the resolver must abort with a typed DepthExceeded rather than
        // silently truncate, otherwise ambient-authority leaks could
        // hide behind the cap.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let groups: Vec<GroupId> = (0..=(MAX_GROUP_DEPTH + 2))
            .map(|_| GroupId::generate())
            .collect();

        let mut fake = Fake::new();
        for (i, g) in groups.iter().enumerate() {
            fake.upsert_group_slug(g, &format!("g{i}"));
        }
        fake.add_parent(&GroupMember::User(alice.clone()), groups[0].clone());
        for window in groups.windows(2) {
            fake.add_parent(&GroupMember::Group(window[0].clone()), window[1].clone());
        }

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::DepthExceeded {
                kind: TraversalKind::GroupMembership,
                limit,
            }) => assert_eq!(limit, MAX_GROUP_DEPTH),
            other => panic!("expected group DepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn group_breadth_exceeds_limit_returns_error() {
        // Fan-out exceeding MAX_GROUP_BREADTH must return
        // BreadthExceeded rather than quietly truncating.
        //
        // Shape: one user directly in MAX_GROUP_BREADTH+10 distinct groups.
        // No chaining, so depth stays at 1 — only the breadth cap trips.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let mut fake = Fake::new();
        let total = MAX_GROUP_BREADTH + 10;
        for i in 0..total {
            let g = GroupId::generate();
            fake.upsert_group_slug(&g, &format!("g{i}"));
            fake.add_parent(&GroupMember::User(alice.clone()), g);
        }

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::BreadthExceeded {
                kind: TraversalKind::GroupMembership,
                limit,
            }) => assert_eq!(limit, MAX_GROUP_BREADTH),
            other => panic!("expected group BreadthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn group_cycle_does_not_loop_forever() {
        // A ∈ B, B ∈ A (cycle). BFS must terminate via visited set.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let a = GroupId::generate();
        let b = GroupId::generate();

        let mut fake = Fake::new();
        fake.upsert_group_slug(&a, "a");
        fake.upsert_group_slug(&b, "b");
        // alice → a
        fake.add_parent(&GroupMember::User(alice.clone()), a.clone());
        // a → b → a (cycle)
        fake.add_parent(&GroupMember::Group(a.clone()), b.clone());
        fake.add_parent(&GroupMember::Group(b.clone()), a.clone());

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        // Both groups visible, no duplicates, no hang.
        assert_eq!(resolved.groups.len(), 2);
    }

    #[test]
    fn scope_narrowing_intersects_with_scope_perms() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let role = mk_role(
            &realm,
            "r",
            &["docs.view", "docs.edit", "hearth.admin"],
            vec![],
        );
        let rid = role.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                rid,
                Scope::Realm,
            )],
        );
        fake.set_scope(
            "docs",
            Some(vec![
                Permission::new("docs.view").expect("valid"),
                Permission::new("docs.edit").expect("valid"),
            ]),
        );

        let resolved =
            resolve_permissions(&fake, &alice, &realm, None, Some("docs")).expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"docs.view"));
        assert!(names.contains(&"docs.edit"));
        assert!(!names.contains(&"hearth.admin"));
        assert_eq!(resolved.permissions.len(), 2);
    }

    #[test]
    fn scope_none_means_no_narrowing() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let role = mk_role(&realm, "r", &["docs.view", "hearth.admin"], vec![]);
        let rid = role.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                rid,
                Scope::Realm,
            )],
        );
        // openid → no narrowing (None means no filter).
        fake.set_scope("openid", None);

        let resolved =
            resolve_permissions(&fake, &alice, &realm, None, Some("openid")).expect("resolve");
        assert_eq!(resolved.permissions.len(), 2);
    }

    #[test]
    fn scope_unknown_narrows_to_empty() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let role = mk_role(&realm, "r", &["docs.view"], vec![]);
        let rid = role.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                rid,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, Some("unknown_scope"))
            .expect("resolve");
        assert_eq!(
            resolved.permissions,
            [] as [crate::rbac::types::Permission; 0]
        );
    }

    #[test]
    fn permissions_are_deduplicated_and_sorted() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let r1 = mk_role(&realm, "r1", &["b.x", "a.x"], vec![]);
        let r2 = mk_role(&realm, "r2", &["a.x", "c.x"], vec![]);
        let r1_id = r1.id.clone();
        let r2_id = r2.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(r1);
        fake.upsert_role(r2);
        fake.user_asgn.insert(
            alice.clone(),
            vec![
                mk_asgn(&realm, Subject::User(alice.clone()), r1_id, Scope::Realm),
                mk_asgn(&realm, Subject::User(alice.clone()), r2_id, Scope::Realm),
            ],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert_eq!(names, vec!["a.x", "b.x", "c.x"]);
    }

    #[test]
    fn missing_role_is_tolerated_at_resolve_time() {
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let dangling = RoleId::generate();

        let mut fake = Fake::new();
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                dangling,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        assert_eq!(
            resolved.permissions,
            [] as [crate::rbac::types::Permission; 0]
        );
        assert_eq!(resolved.roles, [] as [std::string::String; 0]);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        // Permission strings drawn from a small vocabulary. We deliberately
        // include duplicates in the generated Vec so the dedup invariant is
        // exercised, and mix single-segment / dotted forms for realism.
        fn perm_vocab() -> Vec<&'static str> {
            // All entries must satisfy the AUTHZ_EXPANSION grammar
            // (≥ 1 dot, no `:`). Single-segment names belong to the
            // OIDC scope namespace and are rejected by Permission::new.
            vec![
                "docs.view",
                "docs.edit",
                "docs.delete",
                "org.billing.view",
                "org.billing.admin",
                "users.list",
                "users.invite",
                "a.b",
                "z.a",
                "m.n.o",
            ]
        }

        proptest! {
            /// Property: for any set of roles assigned directly to a user,
            /// `resolved.permissions` is **sorted ascending** and contains
            /// **no duplicates**, regardless of:
            ///   - duplication across roles,
            ///   - duplication within a single role,
            ///   - order in which roles are listed on the user.
            ///
            /// This is the contract stated on `ResolvedPermissions` and the
            /// one SDKs rely on for deterministic JWT claim ordering.
            #[test]
            fn resolved_permissions_are_sorted_and_deduped(
                per_role in proptest::collection::vec(
                    proptest::collection::vec(0usize..10, 0..6),
                    1..5,
                ),
            ) {
                let realm = RealmId::generate();
                let alice = UserId::generate();
                let vocab = perm_vocab();

                let mut fake = Fake::new();
                let mut asgns = Vec::new();
                for idx_set in &per_role {
                    // Duplicate each index once inside the role's perm list so
                    // the within-role dedup path is exercised too.
                    let perm_strs: Vec<&str> = idx_set
                        .iter()
                        .flat_map(|i| std::iter::repeat_n(vocab[*i], 2))
                        .collect();
                    let role = mk_role(&realm, "r", &perm_strs, vec![]);
                    let rid = role.id.clone();
                    fake.upsert_role(role);
                    asgns.push(mk_asgn(
                        &realm,
                        Subject::User(alice.clone()),
                        rid,
                        Scope::Realm,
                    ));
                }
                fake.user_asgn.insert(alice.clone(), asgns);

                let resolved = resolve_permissions(&fake, &alice, &realm, None, None)
                    .expect("resolve");

                // Sorted ascending (by Permission's Ord — which delegates to
                // the inner String's Ord).
                let sorted: Vec<_> = {
                    let mut v = resolved.permissions.clone();
                    v.sort();
                    v
                };
                prop_assert_eq!(&resolved.permissions, &sorted);

                // Deduplicated.
                let mut seen = std::collections::HashSet::new();
                for p in &resolved.permissions {
                    prop_assert!(
                        seen.insert(p.as_str().to_string()),
                        "duplicate permission in resolved set: {}", p.as_str()
                    );
                }

                // Groups and roles share the same contract.
                let mut roles_sorted = resolved.roles.clone();
                roles_sorted.sort();
                prop_assert_eq!(&resolved.roles, &roles_sorted);

                let mut groups_sorted = resolved.groups.clone();
                groups_sorted.sort();
                prop_assert_eq!(&resolved.groups, &groups_sorted);
            }
        }
    }

    #[test]
    fn resolve_with_dangling_role_emits_orphan_event_and_succeeds() {
        // Verify that a dangling role ID in the assignment list does not
        // abort permission resolution — the user just gets no permissions
        // from that assignment.
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let dangling = RoleId::generate();

        let mut fake = Fake::new();
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                dangling,
                Scope::Realm,
            )],
        );

        let resolved =
            resolve_permissions(&fake, &alice, &realm, None, None).expect("must not error");
        assert_eq!(
            resolved.permissions,
            [] as [crate::rbac::types::Permission; 0]
        );
        assert_eq!(resolved.roles, [] as [std::string::String; 0]);
    }

    // ===== Scope resolution (scope-consent-integrity design §2) =====

    const MCP: &str = "https://mcp.acme.com";

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// Alice holds `docs.read` and `org.read`. Realm bundles: `read:docs`
    /// (three permissions), `view:docs` (`docs.read`), the bare-word `org`.
    /// Resource bundle: `mcp:tools:invoke` (`docs.read`) under [`MCP`].
    fn scope_fixture() -> (Fake, RealmId, UserId) {
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let mut fake = Fake::new();
        let role = mk_role(&realm, "reader", &["docs.read", "org.read"], vec![]);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                role.id.clone(),
                Scope::Realm,
            )],
        );
        fake.roles.insert(role.id.clone(), role);
        let perms = |list: &[&str]| -> Option<Vec<Permission>> {
            Some(
                list.iter()
                    .map(|p| Permission::new(*p).expect("perm"))
                    .collect(),
            )
        };
        fake.scopes.insert("openid".into(), None);
        fake.scopes.insert(
            "read:docs".into(),
            perms(&["docs.read", "docs.list", "docs.share"]),
        );
        fake.scopes
            .insert("view:docs".into(), perms(&["docs.read"]));
        fake.scopes.insert("org".into(), perms(&["org.read"]));
        fake.resource_scopes.insert(
            MCP.to_string(),
            HashMap::from([("mcp:tools:invoke".to_string(), perms(&["docs.read"]))]),
        );
        (fake, realm, alice)
    }

    fn resolve_scopes(
        fake: &Fake,
        realm: &RealmId,
        user: Option<&UserId>,
        requested: &[&str],
        trust_level: ClientTrustLevel,
        mode: ScopeMode,
        declared: &[&str],
        resource: Option<&str>,
    ) -> Result<ResolvedPermissions, RbacError> {
        let requested = strings(requested);
        let declared = strings(declared);
        let uri = resource.map(|r| Uri::try_from(r.to_string()).expect("uri"));
        resolve_with_scopes(
            fake,
            realm,
            &ScopeRequest {
                user_id: user,
                org_id: None,
                requested: &requested,
                trust_level,
                declared: &declared,
                resource: uri.as_ref(),
                mode,
                narrowed: false,
            },
        )
    }

    fn perm_names(r: &ResolvedPermissions) -> Vec<&str> {
        r.permissions.iter().map(Permission::as_str).collect()
    }

    use ClientTrustLevel::{FirstParty, ThirdParty};
    use ScopeMode::{Reissue, Request};

    #[test]
    fn a_bundle_is_granted_only_when_fully_held() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["read:docs", "docs.read"],
            FirstParty,
            Request,
            &[],
            None,
        )
        .expect("first-party partial grant");
        assert_eq!(r.granted_scopes, strings(&["docs.read"]));
        assert_eq!(perm_names(&r), vec!["docs.read"]);
    }

    #[test]
    fn a_third_party_client_never_gets_an_unsatisfiable_bundle() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "read:docs"],
            ThirdParty,
            Request,
            &[],
            None,
        );
        assert!(matches!(r, Err(RbacError::InvalidScope { .. })), "{r:?}");
    }

    #[test]
    fn an_unknown_scope_is_refused_for_every_trust_level() {
        let (f, realm, alice) = scope_fixture();
        for requested in [["openid", "nosuch:bundle"], ["openid", "nosuchword"]] {
            for trust in [FirstParty, ThirdParty] {
                let r = resolve_scopes(
                    &f,
                    &realm,
                    Some(&alice),
                    &requested,
                    trust,
                    Request,
                    &[],
                    None,
                );
                assert!(
                    matches!(r, Err(RbacError::InvalidScope { .. })),
                    "{requested:?} {trust:?}: {r:?}"
                );
            }
        }
    }

    #[test]
    fn an_undeclared_scope_is_refused_for_every_trust_level() {
        let (f, realm, alice) = scope_fixture();
        for trust in [FirstParty, ThirdParty] {
            let r = resolve_scopes(
                &f,
                &realm,
                Some(&alice),
                &["view:docs", "org"],
                trust,
                Request,
                &["view:docs"],
                None,
            );
            assert!(
                matches!(r, Err(RbacError::InvalidScope { .. })),
                "{trust:?}: {r:?}"
            );
        }
    }

    #[test]
    fn a_bare_word_realm_scope_narrows_like_a_bundle() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["org"],
            FirstParty,
            Request,
            &[],
            None,
        )
        .expect("org");
        assert_eq!(r.granted_scopes, strings(&["org"]));
        assert_eq!(perm_names(&r), vec!["org.read"]);
    }

    #[test]
    fn only_resource_bundles_apply_under_a_resource() {
        let (f, realm, alice) = scope_fixture();
        for requested in [
            ["openid", "view:docs"],
            ["openid", "docs.read"],
            ["openid", "org"],
        ] {
            let r = resolve_scopes(
                &f,
                &realm,
                Some(&alice),
                &requested,
                FirstParty,
                Request,
                &[],
                Some(MCP),
            );
            assert!(
                matches!(r, Err(RbacError::InvalidScope { .. })),
                "{requested:?}: {r:?}"
            );
        }
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "mcp:tools:invoke"],
            ThirdParty,
            Request,
            &["mcp:tools:invoke"],
            Some(MCP),
        )
        .expect("resource bundle");
        assert_eq!(r.granted_scopes, strings(&["openid", "mcp:tools:invoke"]));
        assert_eq!(perm_names(&r), vec!["docs.read"]);
    }

    #[test]
    fn a_resource_bundle_must_be_declared_too() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["mcp:tools:invoke"],
            ThirdParty,
            Request,
            &["view:docs"],
            Some(MCP),
        );
        assert!(matches!(r, Err(RbacError::InvalidScope { .. })), "{r:?}");
    }

    #[test]
    fn only_oidc_scopes_give_first_party_the_full_set_and_third_party_nothing() {
        let (f, realm, alice) = scope_fixture();
        let first = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "profile"],
            FirstParty,
            Request,
            &[],
            None,
        )
        .expect("first");
        assert_eq!(perm_names(&first), vec!["docs.read", "org.read"]);
        let third = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "profile"],
            ThirdParty,
            Request,
            &[],
            None,
        )
        .expect("third");
        assert_eq!(third.granted_scopes, strings(&["openid", "profile"]));
        assert!(
            third.permissions.is_empty(),
            "a third-party OIDC-only grant carries no permission"
        );
    }

    #[test]
    fn every_requested_bundle_dropped_means_no_permissions() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "read:docs"],
            FirstParty,
            Request,
            &[],
            None,
        )
        .expect("first-party drop");
        assert_eq!(r.granted_scopes, strings(&["openid"]));
        assert!(r.permissions.is_empty(), "no permission is granted");
    }

    #[test]
    fn nothing_grantable_is_refused() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["read:docs"],
            FirstParty,
            Request,
            &[],
            None,
        );
        assert!(matches!(r, Err(RbacError::InvalidScope { .. })), "{r:?}");
    }

    #[test]
    fn reissue_drops_an_ungrantable_scope_for_every_trust_level() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "read:docs", "view:docs"],
            ThirdParty,
            Reissue,
            &[],
            None,
        )
        .expect("reissue drops");
        assert_eq!(r.granted_scopes, strings(&["openid", "view:docs"]));
        assert_eq!(perm_names(&r), vec!["docs.read"]);
    }

    #[test]
    fn a_narrowed_grant_never_widens_to_the_full_set() {
        let (f, realm, alice) = scope_fixture();
        let requested = strings(&["openid"]);
        let r = resolve_with_scopes(
            &f,
            &realm,
            &ScopeRequest {
                user_id: Some(&alice),
                org_id: None,
                requested: &requested,
                trust_level: FirstParty,
                declared: &[],
                resource: None,
                mode: Reissue,
                narrowed: true,
            },
        )
        .expect("reissue");
        assert!(r.permissions.is_empty(), "no permission is granted");
        assert!(r.scope_narrowed);
    }

    #[test]
    fn reissue_refuses_a_scope_the_registry_no_longer_knows() {
        let (f, realm, alice) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &["openid", "gone:bundle"],
            FirstParty,
            Reissue,
            &[],
            None,
        );
        assert!(matches!(r, Err(RbacError::InvalidScope { .. })), "{r:?}");
    }

    #[test]
    fn without_a_user_legal_scopes_are_granted_with_no_permissions() {
        let (f, realm, _) = scope_fixture();
        let r = resolve_scopes(
            &f,
            &realm,
            None,
            &["read:docs"],
            FirstParty,
            Request,
            &[],
            None,
        )
        .expect("client credentials");
        assert_eq!(r.granted_scopes, strings(&["read:docs"]));
        assert!(r.permissions.is_empty() && r.roles.is_empty());
        let r = resolve_scopes(
            &f,
            &realm,
            None,
            &["nosuch:bundle"],
            FirstParty,
            Request,
            &[],
            None,
        );
        assert!(matches!(r, Err(RbacError::InvalidScope { .. })), "{r:?}");
    }

    #[test]
    fn an_empty_request_depends_on_the_trust_level() {
        let (f, realm, alice) = scope_fixture();
        let first = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &[],
            FirstParty,
            Request,
            &[],
            None,
        )
        .expect("first");
        assert_eq!(perm_names(&first), vec!["docs.read", "org.read"]);
        let third = resolve_scopes(
            &f,
            &realm,
            Some(&alice),
            &[],
            ThirdParty,
            Request,
            &[],
            None,
        );
        assert!(
            matches!(third, Err(RbacError::InvalidScope { .. })),
            "{third:?}"
        );
    }
}

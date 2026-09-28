//! Privilege ceiling for role definitions, shared by the REST and gRPC admin
//! surfaces (GA audit 2026-09-28 M6).
//!
//! A sub-admin (a caller without `hearth.admin`) may define or edit a role
//! only when every permission the role would grant is one the caller holds.
//! Without the check a `hearth.realm.admin` sub-admin could add a permission it
//! lacks to a role that is already assigned to it — raising its own authority
//! without the assignment-time ceiling ever running. gRPC checked the role's
//! direct permissions; REST checked nothing. Both surfaces now call this one
//! function, which also covers `parent_roles`: naming a parent grants the
//! parent's (transitively resolved) permissions too.

use crate::core::RealmId;
use crate::rbac::{Permission, RbacEngine, RbacError, RoleId};

/// The permission a caller holding `held` may not grant, if any.
///
/// Returns `Ok(None)` when the caller holds `hearth.admin` (full admins are
/// not bound by the ceiling) or holds every permission in `permissions` and
/// every permission `parent_roles` resolve to; otherwise `Ok(Some(p))` naming
/// the first permission outside the ceiling.
///
/// # Errors
///
/// Propagates an [`RbacError`] from resolving a parent role — including an
/// unknown parent, which the caller answers as it answers any RBAC error, so
/// the check fails closed.
pub(crate) fn role_definition_ceiling_violation(
    rbac: &dyn RbacEngine,
    realm_id: &RealmId,
    held: &[String],
    permissions: &[Permission],
    parent_roles: &[RoleId],
) -> Result<Option<String>, RbacError> {
    if held.iter().any(|p| p == "hearth.admin") {
        return Ok(None);
    }
    let holds = |p: &Permission| held.iter().any(|h| h.as_str() == p.as_str());
    if let Some(p) = permissions.iter().find(|p| !holds(p)) {
        return Ok(Some(p.as_str().to_string()));
    }
    for parent in parent_roles {
        let inherited = rbac.resolve_role_permissions(realm_id, parent)?;
        if let Some(p) = inherited.iter().find(|p| !holds(p)) {
            return Ok(Some(p.as_str().to_string()));
        }
    }
    Ok(None)
}

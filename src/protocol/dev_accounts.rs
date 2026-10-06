//! The dev accounts of a `--dev` server (`dev-endpoints` builds only).
//!
//! Two accounts, with fixed passwords and a TOTP factor each:
//!
//! - `admin@hearth.test` in the system realm — the admin console;
//! - `admin@dev.local` in `dev-realm` — a tenant realm admin.
//!
//! `POST /admin/bootstrap` and the dev console (`/dev`) both set them up from
//! here, so the two surfaces cannot drift. Every function is idempotent: an
//! account that exists is left as it is, password and factor included.

use crate::core::{RealmId, UserId};
use crate::identity::{IdentityEngine, IdentityError};
use crate::rbac::{AssignRoleRequest, RbacEngine, Scope, Subject};

/// The tenant realm the dev accounts live in.
pub(crate) const DEV_REALM_NAME: &str = "dev-realm";
/// The `dev-realm` admin.
pub(crate) const DEV_REALM_ADMIN_EMAIL: &str = "admin@dev.local";
/// The `dev-realm` admin's password. Compiled into `dev-endpoints` builds only.
pub(crate) const DEV_REALM_ADMIN_PASSWORD: &str = "HearthDev123!";
/// The admin-console (system realm) admin.
pub(crate) const SYSTEM_ADMIN_EMAIL: &str = "admin@hearth.test";
/// The admin-console admin's password. Compiled into `dev-endpoints` builds
/// only.
pub(crate) const SYSTEM_ADMIN_PASSWORD: &str = "HearthTest123!";

/// The two dev accounts, once they exist.
#[derive(Debug, Clone)]
pub(crate) struct DevAccounts {
    /// `admin@hearth.test` in the system realm.
    pub(crate) system_admin: UserId,
    /// `dev-realm`.
    pub(crate) realm_id: RealmId,
    /// `admin@dev.local` in `dev-realm`.
    pub(crate) realm_admin: UserId,
}

fn rbac_internal(context: &str, e: impl std::fmt::Display) -> IdentityError {
    IdentityError::Internal {
        reason: format!("dev accounts: {context}: {e}"),
    }
}

/// Enrols TOTP for a dev admin and activates it with a code computed from
/// the new secret — the step a person makes with an authenticator app.
/// Returns the base32 secret.
pub(crate) fn enrol_totp(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<String, IdentityError> {
    let enrolment = identity.enroll_totp(realm_id, user_id)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let code = crate::identity::totp::code_at(&enrolment.secret_base32, now).ok_or_else(|| {
        IdentityError::Internal {
            reason: "dev accounts: TOTP secret did not decode".to_string(),
        }
    })?;
    identity.verify_totp_enrollment(realm_id, user_id, &code)?;
    Ok(enrolment.secret_base32.clone())
}

/// Grants `realm.admin` in `realm_id`, seeding the realm's RBAC defaults
/// first. A realm that is already seeded keeps its roles.
fn grant_realm_admin(
    rbac: &dyn RbacEngine,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<(), IdentityError> {
    let seeded = rbac.seed_realm(realm_id);
    let role = rbac
        .get_role_by_name(realm_id, "realm.admin")
        .map_err(|e| rbac_internal("role lookup", e))?
        .ok_or_else(|| match seeded {
            Err(e) => rbac_internal("RBAC seed", e),
            Ok(()) => rbac_internal("role lookup", "realm.admin missing"),
        })?;
    rbac.assign_role(
        realm_id,
        &AssignRoleRequest {
            subject: Subject::User(user_id.clone()),
            role_id: role.id.clone(),
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .map_err(|e| rbac_internal("role assignment", e))?;
    Ok(())
}

/// Creates the system-realm admin (`admin@hearth.test`) when it does not
/// exist. Returns its password and TOTP secret on creation, `None` when it
/// already existed — an existing account is never changed (HEA-1670).
///
/// Best-effort: logs a failure and returns `None`.
pub(crate) fn seed_system_admin(
    identity: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
) -> Option<(String, String)> {
    let sys = crate::identity::keys::system_realm_id();
    match identity.get_user_by_email(&sys, SYSTEM_ADMIN_EMAIL) {
        Ok(Some(_)) => return None,
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "dev accounts: system realm user lookup failed");
            return None;
        }
    }
    let created = (|| -> Result<String, IdentityError> {
        let admin = identity.create_admin_user(&crate::identity::CreateUserRequest {
            email: SYSTEM_ADMIN_EMAIL.to_string(),
            display_name: "Dev Admin".to_string(),
            ..Default::default()
        })?;
        // Active regardless of the server's default status, so a dev sign-in
        // needs no email verification.
        identity.update_user(
            &sys,
            admin.id(),
            &crate::identity::UpdateUserRequest {
                status: Some(crate::identity::UserStatus::Active),
                ..Default::default()
            },
        )?;
        identity.set_password(
            &sys,
            admin.id(),
            &crate::identity::CleartextPassword::from_string(SYSTEM_ADMIN_PASSWORD.to_string()),
        )?;
        grant_realm_admin(rbac, &sys, admin.id())?;
        // The system realm always requires MFA.
        enrol_totp(identity, &sys, admin.id())
    })();
    match created {
        Ok(secret) => Some((SYSTEM_ADMIN_PASSWORD.to_string(), secret)),
        Err(e) => {
            tracing::warn!(error = %e, "dev accounts: system admin setup failed");
            None
        }
    }
}

/// Creates the `dev-realm` admin (`admin@dev.local`) in `realm_id`: the
/// realm's RBAC defaults, an Active user with the dev password, `realm.admin`
/// and a TOTP factor (every realm requires MFA by default). Returns the user
/// and the TOTP secret.
pub(crate) fn provision_dev_realm_admin(
    identity: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
    realm_id: &RealmId,
) -> Result<(UserId, String), IdentityError> {
    let user = identity.create_user(
        realm_id,
        &crate::identity::CreateUserRequest {
            email: DEV_REALM_ADMIN_EMAIL.to_string(),
            display_name: "Dev Admin".to_string(),
            ..Default::default()
        },
    )?;
    let user_id = user.id().clone();
    identity.update_user(
        realm_id,
        &user_id,
        &crate::identity::UpdateUserRequest {
            status: Some(crate::identity::UserStatus::Active),
            ..Default::default()
        },
    )?;
    identity.set_password(
        realm_id,
        &user_id,
        &crate::identity::CleartextPassword::from_string(DEV_REALM_ADMIN_PASSWORD.to_string()),
    )?;
    // Before any token is issued, so the token's `permissions` carry the
    // admin set.
    grant_realm_admin(rbac, realm_id, &user_id)?;
    let secret = enrol_totp(identity, realm_id, &user_id)?;
    Ok((user_id, secret))
}

/// Creates `dev-realm` (MFA required, as in production).
pub(crate) fn create_dev_realm(
    identity: &dyn IdentityEngine,
) -> Result<crate::identity::Realm, IdentityError> {
    identity.create_realm(&crate::identity::CreateRealmRequest {
        name: DEV_REALM_NAME.to_string(),
        config: Some(crate::identity::RealmConfig {
            mfa_required: Some(true),
            ..Default::default()
        }),
    })
}

/// Makes sure both dev accounts exist, creating what is missing. Existing
/// accounts keep their password and factor. A `dev-realm` that config
/// reconciliation archived is made Active again.
pub(crate) fn ensure(
    identity: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
) -> Result<DevAccounts, IdentityError> {
    let sys = crate::identity::keys::system_realm_id();
    seed_system_admin(identity, rbac);
    let system_admin = identity
        .get_user_by_email(&sys, SYSTEM_ADMIN_EMAIL)?
        .ok_or_else(|| IdentityError::Internal {
            reason: "dev accounts: the system admin could not be created".to_string(),
        })?;

    let realm = match identity.get_realm_by_name(DEV_REALM_NAME)? {
        Some(realm) => realm,
        None => create_dev_realm(identity)?,
    };
    let realm_id = realm.id().clone();
    if realm.status() != crate::identity::RealmStatus::Active {
        identity.update_realm(
            &realm_id,
            &crate::identity::UpdateRealmRequest {
                status: Some(crate::identity::RealmStatus::Active),
                ..Default::default()
            },
        )?;
    }
    let realm_admin = match identity.get_user_by_email(&realm_id, DEV_REALM_ADMIN_EMAIL)? {
        Some(user) => user.id().clone(),
        None => provision_dev_realm_admin(identity, rbac, &realm_id)?.0,
    };
    Ok(DevAccounts {
        system_admin: system_admin.id().clone(),
        realm_id,
        realm_admin,
    })
}

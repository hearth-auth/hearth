//! The MFA policy (scope-trim-trusted-core, spec `mfa-policy`).
//!
//! MFA is a plain policy, never a score. A realm requires it unless its
//! `mfa_required` says `false`; a server records the value explicitly on every
//! realm it builds (YAML, the system realm, the bootstrap dev realm), so an
//! absent value only appears on a realm created in-process and reads as "not
//! required".

use crate::core::{PageRequest, MAX_PAGE_LIMIT};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::{IdentityEngine, RealmConfig};

/// Whether the realm policy alone requires MFA. The one place a realm's
/// `mfa_required` is read; every sign-in decision goes through
/// [`IdentityEngine::effective_mfa_requirement`], which starts here.
#[must_use]
pub fn realm_requires_mfa(config: &RealmConfig) -> bool {
    config.mfa_required.unwrap_or(false) // mfa-resolver-ok: the resolver
}

/// Names every realm whose MFA requirement is off, the system realm included
/// (as `system`), for the startup warning.
///
/// # Errors
/// A realm lookup or listing failure.
pub fn realms_with_mfa_off(engine: &dyn IdentityEngine) -> Result<Vec<String>, IdentityError> {
    let mut off = Vec::new();
    if let Some(system) = engine.get_realm(&keys::system_realm_id())? {
        if !realm_requires_mfa(system.config()) {
            off.push(keys::SYSTEM_REALM_NAME.to_string());
        }
    }
    let mut offset = 0u64;
    loop {
        let page = engine.list_realms(&PageRequest::new(offset, MAX_PAGE_LIMIT))?;
        let n = page.items.len() as u64;
        off.extend(
            page.items
                .iter()
                .filter(|r| !realm_requires_mfa(r.config()))
                .map(|r| r.name().to_string()),
        );
        if n == 0 || offset + n >= page.total {
            break;
        }
        offset += n;
    }
    Ok(off)
}

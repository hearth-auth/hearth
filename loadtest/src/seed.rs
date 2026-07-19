//! Seed-step orchestration (HEA-1789).
//!
//! Boots (well, *attaches* to) a running dev Hearth, then drives the admin/OAuth
//! REST surface to build the deterministic corpus described by [`SeedParams`]
//! and persists a [`SeedHandle`].
//!
//! ## Server-capability constraints (discovered against the current server)
//!
//! Two assumptions in the original plan (HEA-1787 §5) do not hold against the
//! live REST surface, so the achievable seed is narrower than the plan text:
//!
//! * **`POST /admin/realms` is disabled** (returns `405`; realms are declared
//!   in `hearth.yaml`). The boot-local path therefore seeds only the single
//!   dev realm that `POST /admin/bootstrap` creates. `--realms > 1` is clamped
//!   with a warning; true multi-realm corpora require realms pre-declared in
//!   `hearth.yaml` plus a per-realm admin token (the `--target-host` path).
//! * **`POST /admin/users` cannot set a password.** Admin-created users have no
//!   credential, so they cannot drive the ROPC (`/token` password grant)
//!   journey. Live tokens are therefore minted for the well-known dev-realm
//!   admin (`admin@dev.local` / `HearthDev123!`), which yields multiple live
//!   sessions for one subject. Multi-*subject* live tokens require users
//!   pre-seeded with passwords in `hearth.yaml` (reconcile seed users) — the
//!   large-corpus `--target-host` path. The user *records* created here still
//!   populate a realistic `lookup_user` / session-count corpus.
//!
//! These gaps are tracked for a server-side decision (see the HEA-1789 thread).

use crate::client::{SeedClient, SeedError};
use crate::handle::{SeedHandle, SeededRealm, SeededToken, SeededUser};
use crate::params::SeedParams;

/// Well-known dev-realm admin created by `POST /admin/bootstrap` in `--dev`
/// mode. These are fixed dev constants baked into the server (not secrets); we
/// ROPC as this user to mint live tokens because admin-created users have no
/// password. The load journeys (`crate::scenarios`) reuse them to drive the
/// issuance and revoke→re-validate flows against the same dev subject.
pub(crate) const DEV_ADMIN_EMAIL: &str = "admin@dev.local";
pub(crate) const DEV_ADMIN_PASSWORD: &str = "HearthDev123!";

/// Runs the full seed flow and returns the persisted handle.
///
/// # Errors
/// Returns [`SeedError`] if any REST call fails or the handle cannot be
/// written.
pub async fn run_seed(params: &SeedParams) -> Result<SeedHandle, SeedError> {
    println!("hearth-loadtest seed: {}", params.dataset_shape_summary());
    println!("  target: {}", params.target_host);

    if params.allow_remote_target {
        println!(
            "  WARNING: --allow-remote-target set — seeding a NON-loopback host. \
             This mints live tokens against it and writes them to the seed handle. \
             Only do this to an isolated lab instance you control."
        );
    }

    if params.realms > 1 {
        println!(
            "  WARNING: POST /admin/realms is disabled on the server (realms come \
             from hearth.yaml). Seeding the single bootstrap dev realm only; \
             requested realms={} clamped to 1. See the README for multi-realm runs.",
            params.realms
        );
    }

    let (client, boot) = SeedClient::bootstrap(&params.target_host).await?;
    println!("  bootstrapped realm {}", boot.realm_id);

    let realm = seed_realm(&client, params, 0).await?;

    let mut handle = SeedHandle::new(params);
    handle.realms.push(realm);

    let out = std::path::Path::new(&params.seed_out);
    handle.write_to(out)?;
    println!(
        "  wrote seed handle: {} ({} users, {} live tokens, {} revoked)",
        params.seed_out,
        handle.realms.iter().map(|r| r.users.len()).sum::<usize>(),
        handle.total_tokens(),
        handle.total_revoked(),
    );

    Ok(handle)
}

/// Seeds one realm: users, a password client, live tokens, and revocations.
async fn seed_realm(
    client: &SeedClient,
    params: &SeedParams,
    realm_index: u32,
) -> Result<SeededRealm, SeedError> {
    // 1. User records (deterministic emails). No credential — populates the
    //    lookup/session-count corpus.
    let mut users = Vec::with_capacity(params.users_per_realm as usize);
    for user_index in 0..params.users_per_realm {
        let email = params.user_email(realm_index, user_index);
        let id = client.create_user(&email, "Load Test User").await?;
        users.push(SeededUser { id, email });
    }
    println!("    created {} users", users.len());

    // 2. Password-grant client for the ROPC + revoke journeys.
    let client_id = client
        .register_password_client("hearth-loadtest-seed")
        .await?;

    // 3. Mint live tokens for the dev admin (see module docs for why the
    //    subject is the admin, not each seeded user).
    let want_sessions = params.sessions_per_realm() as usize;
    let want_revoked = params.revoked_per_realm() as usize;
    let mut tokens = Vec::with_capacity(want_sessions);
    for i in 0..want_sessions {
        let access_token = client
            .password_grant(&client_id, DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD)
            .await?;
        let revoked = i < want_revoked;
        if revoked {
            client.revoke(&client_id, &access_token).await?;
        }
        tokens.push(SeededToken {
            user_email: DEV_ADMIN_EMAIL.to_string(),
            access_token,
            revoked,
        });
    }
    println!(
        "    minted {} live tokens ({} pre-revoked)",
        tokens.len(),
        want_revoked
    );

    Ok(SeededRealm {
        realm_id: client.realm_id().to_string(),
        client_id,
        users,
        tokens,
    })
}

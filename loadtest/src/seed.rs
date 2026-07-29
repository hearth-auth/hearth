//! Seed-step orchestration (HEA-1789, updated HEA-1907).
//!
//! Boots (well, *attaches* to) a running dev Hearth, then drives the admin
//! REST surface to build the deterministic corpus described by [`SeedParams`]
//! and persists a [`SeedHandle`].
//!
//! ## Server-capability constraints
//!
//! * **`POST /admin/realms` is disabled** (returns `405`; realms are declared
//!   in `hearth.yaml`). The boot-local path therefore seeds only the single
//!   dev realm that `POST /admin/bootstrap` creates. `--realms > 1` is clamped
//!   with a warning; true multi-realm corpora require realms pre-declared in
//!   `hearth.yaml` plus a per-realm admin token (the `--target-host` path).
//! * **ROPC (`grant_type=password`) was removed** (HEA-1862). Sessions are now
//!   seeded via the dev-only `POST /dev/seed-session` endpoint (HEA-1907),
//!   which writes a real session record directly to storage for each seeded user.
//!   This is sufficient for the C0 per-session memory sweep and T4 throughput
//!   re-measurement; `--sessions-frac > 0` now works.

use crate::client::{SeedClient, SeedError};
use crate::handle::{SeedHandle, SeededRealm, SeededSession, SeededUser};
use crate::params::SeedParams;

/// Well-known dev-realm admin created by `POST /admin/bootstrap` in `--dev`
/// mode. These are fixed dev constants baked into the server (not secrets).
/// The load journeys (`crate::scenarios`) use them to drive the interactive
/// login / issuance flows against the admin subject. Not used for session
/// seeding (which now goes through `POST /dev/seed-session`, HEA-1907).
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

    let (client, boot) =
        match SeedClient::bootstrap(&params.target_host, params.admin_token.as_deref()).await {
            Ok(v) => v,
            Err(e) => {
                // The most common failure: seeding an instance that was already
                // bootstrapped (manual quickstart curl, or a prior seed run) with
                // no admin token, so the anonymous re-bootstrap is rejected 401.
                // Point the operator at the exact fix instead of failing opaquely.
                if params.admin_token.is_none()
                    && matches!(
                        &e,
                        SeedError::Api {
                            op: "bootstrap",
                            status: 401,
                            ..
                        }
                    )
                {
                    eprintln!(
                        "  HINT: this target is already bootstrapped, so anonymous \
                         POST /admin/bootstrap is rejected. Re-run with the admin bearer \
                         token from your first bootstrap:\n\
                         \x20     make seed ARGS=\"--admin-token $ADMIN_TOKEN ...\"\n\
                         \x20   (or set HEARTH_LOADTEST_ADMIN_TOKEN). Alternatively restart \
                         the dev server from a clean data dir, or use `make loadtest`, which \
                         boots its own fresh instance. See loadtest/README.md."
                    );
                }
                return Err(e);
            }
        };
    println!("  bootstrapped realm {}", boot.realm_id);

    let realm = seed_realm(&client, params, 0).await?;

    let mut handle = SeedHandle::new(params);
    handle.realms.push(realm);

    let out = std::path::Path::new(&params.seed_out);
    handle.write_to(out)?;
    println!(
        "  wrote seed handle: {} ({} users, {} sessions)",
        params.seed_out,
        handle.realms.iter().map(|r| r.users.len()).sum::<usize>(),
        handle.total_sessions(),
    );

    Ok(handle)
}

/// Seeds one realm: users and raw sessions.
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

    // 2. Create raw session records for a fraction of the seeded users via the
    //    dev-only endpoint (HEA-1907). ROPC was removed by HEA-1862; this path
    //    bypasses OAuth and writes session records directly to storage so that
    //    `--sessions-frac > 0` produces a real per-session memory measurement.
    let want_sessions = params.sessions_per_realm() as usize;
    let mut sessions = Vec::with_capacity(want_sessions);
    for user in users.iter().take(want_sessions) {
        let session_id = client.create_dev_session(&user.id).await?;
        sessions.push(SeededSession {
            user_id: user.id.clone(),
            session_id,
        });
    }
    if !sessions.is_empty() {
        println!("    created {} sessions", sessions.len());
    }

    Ok(SeededRealm {
        realm_id: client.realm_id().to_string(),
        client_id: String::new(), // ROPC client no longer registered (HEA-1862/HEA-1907)
        users,
        tokens: Vec::new(), // ROPC tokens no longer minted (HEA-1862/HEA-1907)
        sessions,
    })
}

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
//! * **ROPC (`grant_type=password`) was removed** (HEA-1862). Access tokens are
//!   now minted via the dev-only `POST /dev/seed-token` endpoint (HEA-1991),
//!   which creates a real session + issues a signed JWT for each seeded user.
//!   Sessions for the C0 memory sweep are still created via `POST /dev/seed-session`
//!   (HEA-1907).
//! * **The issuance saturation plane mints over a production grant** (HEA-2003).
//!   The seeder registers a confidential `client_credentials` client (via DCR,
//!   since the admin `POST /clients` handler strips secrets) and carries its
//!   `client_id` + `client_secret` in the handle; the harness mints with
//!   `POST /token`, so the two-host rig needs no `/dev/*` endpoint for issuance.

use crate::client::{SeedClient, SeedError};
use crate::handle::{SeedHandle, SeededRealm, SeededSession, SeededToken, SeededUser};
use crate::params::SeedParams;

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
    handle.admin_token = boot.admin_token;
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

/// Seeds one realm: an OAuth client, users, raw sessions, and live tokens.
async fn seed_realm(
    client: &SeedClient,
    params: &SeedParams,
    realm_index: u32,
) -> Result<SeededRealm, SeedError> {
    // 1. Register a public OAuth client. Its client_id authenticates the
    //    introspect and revoke calls during the load run. ROPC was removed by
    //    HEA-1862 so we use authorization_code (no PKCE required; client is
    //    public and never actually exchanges a code here — it only provides a
    //    valid client_id for endpoint authentication). (HEA-1991)
    let client_id = client.register_client("hearth-loadtest").await?;
    println!("    registered OAuth client {}", &client_id[..8]);

    // 1b. Register a CONFIDENTIAL client that supports `client_credentials`, for
    //     the issuance saturation plane (HEA-2003). The harness mints tokens over
    //     the production `POST /token` (grant_type=client_credentials) with these
    //     credentials — so the issuance plane needs no dev-only endpoint at run
    //     time and is measurable on the two-host rig with the HEA-1980 gate intact.
    //
    //     The admin `POST /clients` handler strips any secret (HEA-1750), so DCR
    //     (`POST /register`) is the only server path that returns a usable secret.
    //     DCR is disabled by default, so we flip the realm to `authenticated`
    //     (registration still requires the admin bearer), register, then flip it
    //     back to `disabled` — the measured phase-3B server carries no residual
    //     DCR exposure.
    client.set_dcr_policy("authenticated").await?;
    let cc_result = client
        .register_confidential_client("hearth-loadtest-cc")
        .await;
    // Always restore the policy, even if registration failed, so a partial seed
    // never leaves DCR enabled on the corpus.
    let restore = client.set_dcr_policy("disabled").await;
    let (cc_client_id, cc_client_secret) = cc_result?;
    restore?;
    println!(
        "    registered confidential client_credentials client {} (issuance plane)",
        &cc_client_id[..8]
    );

    // 2. User records (deterministic emails). When `--login-password` is set,
    //    each user is also given that known password via the dev-only
    //    `POST /dev/seed-password` endpoint (HEA-1998) so the login / KDF
    //    saturation plane can authenticate the corpus. The password MUST be set
    //    before any token/session is minted below: `set_password` revokes all of
    //    the user's sessions (A-42), which would otherwise wipe the read-plane
    //    corpus. Users get no credential when the flag is unset.
    let mut users = Vec::with_capacity(params.users_per_realm as usize);
    for user_index in 0..params.users_per_realm {
        let email = params.user_email(realm_index, user_index);
        let id = client.create_user(&email, "Load Test User").await?;
        if let Some(password) = params.login_password.as_deref() {
            client.set_password(&id, password).await?;
        }
        users.push(SeededUser { id, email });
    }
    if params.login_password.is_some() {
        println!(
            "    created {} users (with login password for the login/KDF plane)",
            users.len()
        );
    } else {
        println!("    created {} users", users.len());
    }

    // 3. Mint one access token per user via the dev-only endpoint (HEA-1991).
    //    ROPC was removed by HEA-1862; POST /dev/seed-token creates a real
    //    session + issues a signed JWT so that introspect returns active:true
    //    and userinfo resolves a real session.
    let mut tokens = Vec::with_capacity(users.len());
    for user in &users {
        let access_token = client.seed_token(&user.id).await?;
        tokens.push(SeededToken {
            user_email: user.email.clone(),
            access_token,
            revoked: false,
        });
    }
    println!("    minted {} access tokens", tokens.len());

    // 4. Create raw session records for a fraction of the seeded users via the
    //    dev-only endpoint (HEA-1907). These are storage-level session IDs used
    //    for the C0 per-session memory sweep; distinct from the token sessions
    //    above.
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
        client_id,
        cc_client_id,
        cc_client_secret,
        users,
        tokens,
        sessions,
    })
}

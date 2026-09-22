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
        "  wrote seed handle: {} ({} users, {} sessions, {} tokens of which {} revoked)",
        params.seed_out,
        handle.realms.iter().map(|r| r.users.len()).sum::<usize>(),
        handle.total_sessions(),
        handle.total_tokens(),
        // Printed so the operator can see the pre-revoked count the run will
        // actually have, rather than only the `revoked/realm=N` the parameter
        // summary *claims* (audit 2026-09-21, task 23.14).
        handle.total_revoked(),
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

    // 3b. Pre-revoke `--revoked-frac` of the minted tokens (audit 2026-09-21,
    //     task 23.14). Until now nothing in the seed step ever called
    //     `SeedClient::revoke` — the method had zero callers anywhere in the
    //     crate, which is why `cargo clippy --all-targets` reported it dead —
    //     and every `SeededToken` was written with a hard-coded
    //     `revoked: false`. So `--revoked-frac` (validated, defaulted to 0.1,
    //     documented in the README as "fraction of live tokens pre-revoked",
    //     and stamped into every report's `dataset_shape` as `revoked/realm=N`)
    //     described a corpus property that did not exist, and
    //     `LoadContext::from_handle`'s `!t.revoked` filter — there so the
    //     validate journey is never handed a dead token — had nothing to
    //     filter.
    //
    //     Revocation is by construction the LAST seeding step for a token: the
    //     remaining tokens must stay live for the read-plane journeys.
    let want_revoked = params.revoked_per_realm() as usize;
    let revoke_count = revoke_target_count(want_revoked, tokens.len());
    for token in tokens.iter_mut().take(revoke_count) {
        client.revoke(&client_id, &token.access_token).await?;
        token.revoked = true;
    }
    if revoke_count > 0 {
        println!(
            "    pre-revoked {revoke_count} of {} access tokens",
            tokens.len()
        );
    }

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
        realm_name: client.realm_name().to_string(),
        client_id,
        cc_client_id,
        cc_client_secret,
        users,
        tokens,
        sessions,
    })
}

/// How many minted tokens to pre-revoke.
///
/// `SeedParams::revoked_per_realm` derives its count from the *session* count,
/// which is itself a fraction of the user count, so it can exceed the number of
/// tokens actually minted. Revoking every token would leave
/// `LoadContext::from_handle` with no live token and fail the run with
/// `NoLiveTokens`, so at least one token is always kept live.
fn revoke_target_count(want: usize, minted: usize) -> usize {
    if minted == 0 {
        return 0;
    }
    want.min(minted.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::revoke_target_count;

    #[test]
    fn revocation_never_consumes_the_whole_live_pool() {
        // Audit 2026-09-21 (task 23.14). `revoked_per_realm()` is a fraction of
        // the SESSION count, not of the token count, so it can exceed the
        // tokens minted. Revoking all of them would leave the run with no live
        // token at all.
        assert_eq!(revoke_target_count(0, 10), 0);
        assert_eq!(revoke_target_count(1, 10), 1);
        assert_eq!(revoke_target_count(10, 10), 9, "one token must stay live");
        assert_eq!(revoke_target_count(999, 10), 9);
        assert_eq!(
            revoke_target_count(5, 1),
            0,
            "a single token is never revoked"
        );
        assert_eq!(revoke_target_count(5, 0), 0);
    }
}

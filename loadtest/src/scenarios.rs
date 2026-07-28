//! Goose closed-loop journeys for the five hot paths (HEA-1790).
//!
//! These are **closed-loop user journeys**, not endpoint hammering: each
//! transaction resolves a realistic action end-to-end over HTTP against a
//! seeded dev Hearth. The default weights mirror the plan (HEA-1787 §4) —
//! `validation >> lookup >> issuance >> revoke` — and every weight is
//! overridable from the CLI (see [`crate::load::LoadParams`]).
//!
//! | # | Journey | Default weight | HTTP calls |
//! |---|---|---|---|
//! | 1 | Validate | 70 | `POST /introspect` (expect `active:true`) |
//! | 2 | Session lookup | 12 | `GET /userinfo` (session-lookup proxy, CTO Option A) |
//! | 3 | User lookup | 8 | `GET /admin/users/{id}` |
//! | 4 | Issuance | 8 | `POST /token` (ROPC password grant) |
//! | 5 | Revoke→re-validate | 2 | `POST /token` → `POST /revoke` → `POST /introspect` (expect `active:false`) |
//!
//! ## How the corpus reaches the journeys
//!
//! Goose transactions are plain `async fn(&mut GooseUser)` functions with no
//! per-run state channel, so the seeded corpus (realm, client, live tokens,
//! user IDs) is published once into a process-global [`LoadContext`] before the
//! attack starts and read back by every transaction. The context is derived
//! from the JSON seed-handle produced by the seed step (HEA-1789); it inherently
//! carries **live bearer tokens**, so it is never logged.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use goose::goose::GooseResponse;
use goose::prelude::*;

use crate::handle::SeedHandle;
use crate::latency;

/// Realm-scoping header every Hearth request carries.
const REALM_HEADER: &str = "X-Realm-ID";

/// Process-global corpus shared with every Goose transaction. Published by
/// [`set_context`] before the attack starts.
static CONTEXT: OnceLock<Arc<LoadContext>> = OnceLock::new();

/// The seeded corpus a load run draws from, derived from a [`SeedHandle`].
///
/// Holds live bearer tokens; it MUST NOT be logged or `Debug`-printed. No
/// `Debug` is derived deliberately.
pub struct LoadContext {
    /// Realm every journey targets (`X-Realm-ID`).
    realm_id: String,
    /// Public OAuth client that authenticates the introspect/revoke calls and
    /// owns the ROPC issuance grant.
    client_id: String,
    /// Live (non-revoked) access tokens for the validate + session journeys.
    live_tokens: Vec<String>,
    /// Seeded user IDs for the admin user-lookup journey.
    user_ids: Vec<String>,
    /// ROPC subject for the issuance + revoke journeys (dev admin).
    ropc_username: String,
    /// ROPC password for the issuance + revoke journeys (dev admin).
    ropc_password: String,
    /// Round-robins token/user selection so load spreads across the corpus.
    cursor: AtomicUsize,
}

/// Why a [`LoadContext`] could not be built from a seed-handle.
#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // "No<thing>" reads clearest for empty-corpus cases
pub enum ContextError {
    /// The handle has no realms.
    NoRealms,
    /// The realm has no live (non-revoked) tokens — the validate/session/user
    /// journeys have nothing to draw from.
    NoLiveTokens,
    /// The realm has no seeded users — the user-lookup journey has no target.
    NoUsers,
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRealms => write!(f, "seed handle has no realms; run the seed step first"),
            Self::NoLiveTokens => write!(
                f,
                "seed handle has no live (non-revoked) tokens; increase --sessions-frac when seeding"
            ),
            Self::NoUsers => write!(f, "seed handle has no seeded users; increase --users-per-realm"),
        }
    }
}

impl std::error::Error for ContextError {}

impl LoadContext {
    /// Builds a context from the first realm of a seed-handle.
    ///
    /// The boot-local seed populates a single realm (see [`crate::seed`]); the
    /// first realm is used. `ropc_username`/`ropc_password` are the credentials
    /// the issuance + revoke journeys authenticate with (the dev admin, whose
    /// password is not in the handle).
    ///
    /// # Errors
    /// Returns a [`ContextError`] if the handle lacks realms, live tokens, or
    /// users — each journey needs real corpus to exercise the hot path rather
    /// than the reject path.
    pub fn from_handle(
        handle: &SeedHandle,
        ropc_username: &str,
        ropc_password: &str,
    ) -> Result<Self, ContextError> {
        let realm = handle.realms.first().ok_or(ContextError::NoRealms)?;
        let live_tokens: Vec<String> = realm
            .tokens
            .iter()
            .filter(|t| !t.revoked)
            .map(|t| t.access_token.clone())
            .collect();
        if live_tokens.is_empty() {
            return Err(ContextError::NoLiveTokens);
        }
        let user_ids: Vec<String> = realm.users.iter().map(|u| u.id.clone()).collect();
        if user_ids.is_empty() {
            return Err(ContextError::NoUsers);
        }
        Ok(Self {
            realm_id: realm.realm_id.clone(),
            client_id: realm.client_id.clone(),
            live_tokens,
            user_ids,
            ropc_username: ropc_username.to_string(),
            ropc_password: ropc_password.to_string(),
            cursor: AtomicUsize::new(0),
        })
    }

    /// Monotonic round-robin index, wrapped by the caller against a slice len.
    fn next(&self) -> usize {
        self.cursor.fetch_add(1, Ordering::Relaxed)
    }

    /// A live access token, round-robined across the corpus.
    fn live_token(&self) -> &str {
        &self.live_tokens[self.next() % self.live_tokens.len()]
    }

    /// A seeded user ID, round-robined across the corpus.
    fn user_id(&self) -> &str {
        &self.user_ids[self.next() % self.user_ids.len()]
    }

    /// The ROPC request body the `/token` password grant expects.
    fn ropc_body(&self) -> serde_json::Value {
        serde_json::json!({
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.ropc_username,
            "password": self.ropc_password,
        })
    }

    // ── Accessors for the open-loop saturate driver (C4, HEA-1872) ──────────

    /// Realm ID the corpus was seeded into.
    pub fn realm_id(&self) -> &str {
        &self.realm_id
    }

    /// OAuth client ID registered for this realm.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Number of live (non-revoked) access tokens in the pool.
    pub fn live_tokens_len(&self) -> usize {
        self.live_tokens.len()
    }

    /// Clones and returns a live token, round-robined across the pool.
    ///
    /// Returning an owned `String` allows the caller to hold the token across
    /// `await` points without lifetime issues. Safe to call from concurrent
    /// tasks — the cursor is atomic.
    pub fn live_token_cloned(&self) -> String {
        self.live_tokens[self.next() % self.live_tokens.len()].clone()
    }

    /// Clones and returns a seeded user ID, round-robined across the pool.
    ///
    /// Returns an owned `String` for the same reason as [`Self::live_token_cloned`].
    pub fn user_id_cloned(&self) -> String {
        self.user_ids[self.next() % self.user_ids.len()].clone()
    }
}

/// Publishes the corpus for the transactions to read. Call once before the
/// attack starts; subsequent calls are ignored (the corpus is immutable).
pub fn set_context(ctx: Arc<LoadContext>) {
    let _ = CONTEXT.set(ctx);
}

/// Reads the process-global corpus.
#[allow(clippy::expect_used)]
fn ctx() -> &'static Arc<LoadContext> {
    // INVARIANT: `set_context` is called in `crate::load::run_load` before
    // `GooseAttack::execute`, so the cell is always populated when a
    // transaction runs.
    CONTEXT
        .get()
        .expect("load context must be set before the attack starts")
}

/// Issues `req` and records its wall-clock latency under `name` at microsecond
/// resolution ([`crate::latency`]) before returning Goose's response, so the
/// report can surface a sub-ms min/max that Goose's whole-ms aggregation loses.
async fn request_timed(
    user: &mut GooseUser,
    req: GooseRequest<'_>,
    name: &str,
) -> Result<GooseResponse, Box<TransactionError>> {
    let start = Instant::now();
    let result = user.request(req).await;
    latency::record(name, start.elapsed());
    result
}

// ===== Journey 1 — Validate (introspect a live token) =====

/// `POST /introspect` on a pre-seeded live token, asserting `active:true`.
///
/// Introspection returns `200` even for inactive tokens, so a status check is
/// not enough — the body's `active` flag is what proves we exercised the live
/// validate path rather than the reject path.
async fn journey_validate(user: &mut GooseUser) -> TransactionResult {
    let ctx = ctx();
    let body = serde_json::json!({ "token": ctx.live_token(), "client_id": ctx.client_id });
    let rb = user
        .get_request_builder(&GooseMethod::Post, "/introspect")?
        .header(REALM_HEADER, &ctx.realm_id)
        .json(&body);
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name("validate")
        .build();
    let goose = request_timed(user, req, "validate").await?;
    expect_active(user, goose, true, "validate").await
}

// ===== Journey 2 — Session lookup (userinfo proxy) =====

/// `GET /userinfo` with a live bearer — the CTO-approved Option A proxy for the
/// session-lookup hot path (no public get-session-by-id route exists).
async fn journey_session_lookup(user: &mut GooseUser) -> TransactionResult {
    let ctx = ctx();
    let rb = user
        .get_request_builder(&GooseMethod::Get, "/userinfo")?
        .header(REALM_HEADER, &ctx.realm_id)
        .bearer_auth(ctx.live_token());
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name("session_lookup")
        .build();
    let goose = request_timed(user, req, "session_lookup").await?;
    expect_ok(user, goose, "session_lookup").await
}

// ===== Journey 3 — User lookup (admin) =====

/// `GET /admin/users/{id}` with an admin-authority bearer (the seeded dev-admin
/// token). Exercises the user-lookup hot path over the admin surface.
async fn journey_user_lookup(user: &mut GooseUser) -> TransactionResult {
    let ctx = ctx();
    let path = format!("/admin/users/{}", ctx.user_id());
    let rb = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header(REALM_HEADER, &ctx.realm_id)
        .bearer_auth(ctx.live_token());
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name("user_lookup")
        .build();
    let goose = request_timed(user, req, "user_lookup").await?;
    expect_ok(user, goose, "user_lookup").await
}

// ===== Journey 4 — Issuance (login → token) =====

/// `POST /token` ROPC password grant — the full issuance hot path.
async fn journey_issuance(user: &mut GooseUser) -> TransactionResult {
    mint_token(user, "issuance").await.map(|_| ())
}

// ===== Journey 5 — Revoke → re-validate =====

/// Mints a fresh token, revokes it, then introspects expecting `active:false` —
/// exercising the 64-shard revoke cache end-to-end. A fresh token is minted (not
/// a seeded one) so the run does not deplete the validate journey's corpus.
async fn journey_revoke_revalidate(user: &mut GooseUser) -> TransactionResult {
    let ctx = ctx();

    // 1. Mint a throwaway token (mint_token marks its own failure metric).
    let token = mint_token(user, "revoke_mint").await?;

    // 2. Revoke it.
    let revoke_body = serde_json::json!({
        "token": token,
        "token_type_hint": "access_token",
        "client_id": ctx.client_id,
    });
    let rb = user
        .get_request_builder(&GooseMethod::Post, "/revoke")?
        .header(REALM_HEADER, &ctx.realm_id)
        .json(&revoke_body);
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name("revoke")
        .build();
    let goose = request_timed(user, req, "revoke").await?;
    expect_ok(user, goose, "revoke").await?;

    // 3. Re-validate — the token must now read `active:false`.
    let introspect_body = serde_json::json!({ "token": token, "client_id": ctx.client_id });
    let rb = user
        .get_request_builder(&GooseMethod::Post, "/introspect")?
        .header(REALM_HEADER, &ctx.realm_id)
        .json(&introspect_body);
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name("revoke_revalidate")
        .build();
    let goose = request_timed(user, req, "revoke_revalidate").await?;
    expect_active(user, goose, false, "revoke_revalidate").await
}

// ===== Shared helpers =====

/// Runs a ROPC `POST /token` and returns the minted access token.
///
/// The request's own success metric is recorded by Goose; on any non-2xx,
/// missing token, or transport error this marks the metric failed (via
/// `set_failure`) and returns the resulting `Err`, so the caller can simply
/// propagate with `?`.
async fn mint_token(
    user: &mut GooseUser,
    name: &'static str,
) -> Result<String, Box<TransactionError>> {
    let ctx = ctx();
    let rb = user
        .get_request_builder(&GooseMethod::Post, "/token")?
        .header(REALM_HEADER, &ctx.realm_id)
        .json(&ctx.ropc_body());
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name(name)
        .build();
    let GooseResponse {
        mut request,
        response,
    } = request_timed(user, req, name).await?;

    let resp = match response {
        Ok(r) => r,
        Err(e) => {
            return Err(fail(
                user,
                &mut request,
                &format!("{name}: transport error: {e}"),
            ))
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(fail(user, &mut request, &format!("{name}: HTTP {status}")));
    }
    let json = match resp.json::<serde_json::Value>().await {
        Ok(j) => j,
        Err(e) => {
            return Err(fail(
                user,
                &mut request,
                &format!("{name}: invalid JSON: {e}"),
            ))
        }
    };
    match json.get("access_token").and_then(serde_json::Value::as_str) {
        Some(t) if !t.is_empty() => Ok(t.to_string()),
        _ => Err(fail(
            user,
            &mut request,
            &format!("{name}: no access_token in response"),
        )),
    }
}

/// Marks `request` failed with `tag` and returns the resulting boxed error.
/// `set_failure` always returns `Err`, so the `Ok` arm is unreachable.
fn fail(
    user: &GooseUser,
    request: &mut goose::metrics::GooseRequestMetric,
    tag: &str,
) -> Box<TransactionError> {
    match user.set_failure(tag, request, None, None) {
        Err(e) => e,
        Ok(()) => Box::new(TransactionError::RequestFailed {
            raw_request: request.clone(),
        }),
    }
}

/// Marks the request failed unless the response is a 2xx.
async fn expect_ok(user: &GooseUser, goose: GooseResponse, tag: &str) -> TransactionResult {
    let GooseResponse {
        mut request,
        response,
    } = goose;
    match response {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status();
            user.set_failure(&format!("{tag}: HTTP {status}"), &mut request, None, None)
        }
        Err(e) => user.set_failure(
            &format!("{tag}: transport error: {e}"),
            &mut request,
            None,
            None,
        ),
    }
}

/// Marks the request failed unless the response is 200 and its JSON `active`
/// flag equals `expected`.
async fn expect_active(
    user: &GooseUser,
    goose: GooseResponse,
    expected: bool,
    tag: &str,
) -> TransactionResult {
    let GooseResponse {
        mut request,
        response,
    } = goose;
    let resp = match response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("{tag}: transport error: {e}"),
                &mut request,
                None,
                None,
            )
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        return user.set_failure(&format!("{tag}: HTTP {status}"), &mut request, None, None);
    }
    let json = match resp.json::<serde_json::Value>().await {
        Ok(j) => j,
        Err(e) => {
            return user.set_failure(
                &format!("{tag}: invalid JSON: {e}"),
                &mut request,
                None,
                None,
            )
        }
    };
    let active = json.get("active").and_then(serde_json::Value::as_bool);
    if active == Some(expected) {
        Ok(())
    } else {
        user.set_failure(
            &format!("{tag}: expected active={expected}, got {active:?}"),
            &mut request,
            None,
            None,
        )
    }
}

// ===== Tier-miss lookup profile (HEA-1801) =====

/// Process-global tier-miss corpus, published by [`set_tier_context`] before a
/// tier-miss attack starts. Separate from [`CONTEXT`] because the tier-miss
/// profile addresses the server-seeded bulk demo corpus by index rather than a
/// seed-handle's live tokens.
static TIER_CONTEXT: OnceLock<Arc<TierMissContext>> = OnceLock::new();

/// The bulk demo corpus a tier-miss run draws lookups from, addressed by index.
///
/// Every seeded bulk user shares one password and has a deterministic email
/// `user<7-digit-index>@<domain>` (see `examples/large-scale-demo/`), so the
/// generator can address any point in the corpus by index and know **by
/// construction** whether a request is a resident "hot" hit or a uniform "cold"
/// draw. Holds the shared demo password; it MUST NOT be logged (no `Debug`).
pub struct TierMissContext {
    /// Realm every lookup targets (`X-Realm-ID`); a real (v4) UUID string.
    realm_id: String,
    /// Public OAuth client owning the ROPC password grant (`bulk-app`).
    client_id: String,
    /// Email domain of the bulk corpus (`user<idx>@<domain>`).
    email_domain: String,
    /// Shared password every bulk user authenticates with.
    password: String,
    /// Total addressable corpus size — the cold draw spans `1..=corpus_size`.
    corpus_size: u64,
    /// Size of the resident hot working set — hot draws span `1..=hot_set_size`.
    hot_set_size: u64,
    /// Monotonic counter driving deterministic index selection.
    cursor: AtomicU64,
}

impl TierMissContext {
    /// Builds a tier-miss context. `corpus_size` and `hot_set_size` are assumed
    /// validated by the caller ([`crate::load`]): both `>= 1` and
    /// `hot_set_size <= corpus_size`.
    #[must_use]
    pub fn new(
        realm_id: String,
        client_id: String,
        email_domain: String,
        password: String,
        corpus_size: u64,
        hot_set_size: u64,
    ) -> Self {
        Self {
            realm_id,
            client_id,
            email_domain,
            password,
            corpus_size,
            hot_set_size,
            cursor: AtomicU64::new(0),
        }
    }

    /// Deterministic email for the bulk user at 1-based `index`, matching the
    /// bulk seeder's `user<7-digit-index>@<domain>` format.
    fn email(&self, index: u64) -> String {
        format!("user{index:07}@{}", self.email_domain)
    }

    /// Next hot-working-set index: cycles through `1..=hot_set_size`, so the
    /// same small set of users is hit repeatedly and stays resident in the hot
    /// tier.
    fn hot_index(&self) -> u64 {
        let n = self.cursor.fetch_add(1, Ordering::Relaxed);
        (n % self.hot_set_size) + 1
    }

    /// Next cold index: a splitmix-spread draw across the whole `1..=corpus_size`
    /// corpus, so with a hot tier sized below the corpus most cold draws fall
    /// through to the cold/SST read path. Deterministic (seeded by the cursor),
    /// so a run is reproducible without a RNG dependency.
    fn cold_index(&self) -> u64 {
        let n = self.cursor.fetch_add(1, Ordering::Relaxed);
        (splitmix64(n) % self.corpus_size) + 1
    }

    /// The ROPC `/token` body for a bulk user at `index`.
    fn ropc_body(&self, index: u64) -> serde_json::Value {
        serde_json::json!({
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.email(index),
            "password": self.password,
        })
    }
}

/// Publishes the tier-miss corpus. Call once before the tier-miss attack starts.
pub fn set_tier_context(ctx: Arc<TierMissContext>) {
    let _ = TIER_CONTEXT.set(ctx);
}

/// Reads the process-global tier-miss corpus.
#[allow(clippy::expect_used)]
fn tier_ctx() -> &'static Arc<TierMissContext> {
    // INVARIANT: `set_tier_context` is called in `crate::load::run_tier_miss`
    // before `GooseAttack::execute`, so the cell is populated when a tier
    // transaction runs.
    TIER_CONTEXT
        .get()
        .expect("tier-miss context must be set before the attack starts")
}

/// Dependency-free deterministic bit mixer (Vigna's splitmix64), used to spread
/// cold draws uniformly across the corpus without pulling in a RNG crate.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Runs one ROPC `/token` lookup for the bulk user at `index` and asserts a 2xx
/// with an `access_token`, recording its latency under `name` (`lookup_hot` or
/// `lookup_cold`). The first step of the password grant is `lookup_user` — the
/// storage lookup whose tier (hot vs cold/SST) this profile isolates.
async fn tier_lookup(user: &mut GooseUser, index: u64, name: &'static str) -> TransactionResult {
    let ctx = tier_ctx();
    let rb = user
        .get_request_builder(&GooseMethod::Post, "/token")?
        .header(REALM_HEADER, &ctx.realm_id)
        .json(&ctx.ropc_body(index));
    let req = GooseRequest::builder()
        .set_request_builder(rb)
        .name(name)
        .build();
    let GooseResponse {
        mut request,
        response,
    } = request_timed(user, req, name).await?;
    match response {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status();
            user.set_failure(&format!("{name}: HTTP {status}"), &mut request, None, None)
        }
        Err(e) => user.set_failure(
            &format!("{name}: transport error: {e}"),
            &mut request,
            None,
            None,
        ),
    }
}

/// Hot-tier journey: repeatedly hits the small resident working set.
async fn journey_lookup_hot(user: &mut GooseUser) -> TransactionResult {
    let index = tier_ctx().hot_index();
    tier_lookup(user, index, "lookup_hot").await
}

/// Cold-tier journey: uniform draw across the whole corpus (mostly SST misses).
async fn journey_lookup_cold(user: &mut GooseUser) -> TransactionResult {
    let index = tier_ctx().cold_index();
    tier_lookup(user, index, "lookup_cold").await
}

/// Builds the tier-miss scenario from the hot/cold request weights.
///
/// Registers only the tiers with weight > 0. A weight of `0` drops that tier
/// (e.g. `--tier-miss-weight-hot 0` runs a pure cold sweep).
///
/// # Errors
/// Returns a [`GooseError`] if both weights are `0` (nothing to run) or Goose
/// rejects a weight.
pub fn build_tier_scenario(hot_weight: usize, cold_weight: usize) -> Result<Scenario, GooseError> {
    if hot_weight + cold_weight == 0 {
        return Err(GooseError::InvalidWeight {
            weight: 0,
            detail: "both tier-miss weights are 0; at least one tier must have weight >= 1"
                .to_string(),
        });
    }
    let tiers: [(usize, Transaction, &str); 2] = [
        (hot_weight, transaction!(journey_lookup_hot), "lookup_hot"),
        (
            cold_weight,
            transaction!(journey_lookup_cold),
            "lookup_cold",
        ),
    ];
    let mut scenario = scenario!("HearthTierMiss");
    for (weight, transaction, name) in tiers {
        if weight == 0 {
            continue;
        }
        scenario = scenario.register_transaction(transaction.set_name(name).set_weight(weight)?);
    }
    Ok(scenario)
}

// ===== Scenario assembly =====

/// Per-journey weights (Goose relative transaction weights). A weight of `0`
/// drops that journey from the run entirely.
#[derive(Debug, Clone, Copy)]
pub struct Weights {
    /// Journey 1 — validate.
    pub validate: usize,
    /// Journey 2 — session lookup.
    pub session: usize,
    /// Journey 3 — user lookup.
    pub user: usize,
    /// Journey 4 — issuance.
    pub issuance: usize,
    /// Journey 5 — revoke → re-validate.
    pub revoke: usize,
}

impl Weights {
    /// Total weight across the five journeys.
    #[must_use]
    pub fn total(&self) -> usize {
        self.validate + self.session + self.user + self.issuance + self.revoke
    }
}

/// Builds the load scenario, registering only the journeys with weight > 0.
///
/// # Errors
/// Returns a [`GooseError`] if every weight is `0` (nothing to run) or if Goose
/// rejects a weight.
pub fn build_scenario(weights: &Weights) -> Result<Scenario, GooseError> {
    if weights.total() == 0 {
        return Err(GooseError::InvalidWeight {
            weight: 0,
            detail: "all journey weights are 0; at least one journey must have weight >= 1"
                .to_string(),
        });
    }

    // (weight, transaction, name). We set explicit human-readable transaction
    // names so per-transaction metrics match the report table.
    let journeys: [(usize, Transaction, &str); 5] = [
        (weights.validate, transaction!(journey_validate), "validate"),
        (
            weights.session,
            transaction!(journey_session_lookup),
            "session_lookup",
        ),
        (
            weights.user,
            transaction!(journey_user_lookup),
            "user_lookup",
        ),
        (weights.issuance, transaction!(journey_issuance), "issuance"),
        (
            weights.revoke,
            transaction!(journey_revoke_revalidate),
            "revoke_revalidate",
        ),
    ];

    let mut scenario = scenario!("HearthJourneys");
    for (weight, transaction, name) in journeys {
        if weight == 0 {
            continue;
        }
        scenario = scenario.register_transaction(transaction.set_name(name).set_weight(weight)?);
    }
    Ok(scenario)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{SeededRealm, SeededToken, SeededUser};

    fn handle_with(live: usize, revoked: usize, users: usize) -> SeedHandle {
        let mut tokens = Vec::new();
        for i in 0..live {
            tokens.push(SeededToken {
                user_email: "admin@dev.local".into(),
                access_token: format!("live-{i}"),
                revoked: false,
            });
        }
        for i in 0..revoked {
            tokens.push(SeededToken {
                user_email: "admin@dev.local".into(),
                access_token: format!("revoked-{i}"),
                revoked: true,
            });
        }
        let users = (0..users)
            .map(|i| SeededUser {
                id: format!("user-{i}"),
                email: format!("u{i}@loadtest.test"),
            })
            .collect();
        SeedHandle {
            target_host: "http://127.0.0.1:8420".into(),
            seed: 1,
            dataset_shape: "test".into(),
            realms: vec![SeededRealm {
                realm_id: "realm-1".into(),
                client_id: "client-1".into(),
                users,
                tokens,
            }],
        }
    }

    #[test]
    fn context_selects_only_live_tokens() {
        let h = handle_with(3, 2, 4);
        let ctx = LoadContext::from_handle(&h, "admin@dev.local", "pw").expect("context");
        assert_eq!(ctx.live_tokens.len(), 3, "revoked tokens must be excluded");
        assert!(ctx.live_tokens.iter().all(|t| t.starts_with("live-")));
        assert_eq!(ctx.user_ids.len(), 4);
    }

    #[test]
    fn context_round_robins_across_the_corpus() {
        let h = handle_with(2, 0, 3);
        let ctx = LoadContext::from_handle(&h, "admin@dev.local", "pw").expect("context");
        // live_token and user_id share one cursor; assert each wraps its own slice.
        let t0 = ctx.live_token().to_string();
        let t1 = ctx.live_token().to_string();
        assert_ne!(t0, t1, "consecutive picks should advance");
        // Both are valid members of the corpus.
        assert!(ctx.live_tokens.contains(&t0));
        assert!(ctx.user_ids.contains(&ctx.user_id().to_string()));
    }

    #[test]
    fn context_requires_live_tokens() {
        let h = handle_with(0, 3, 4);
        assert!(matches!(
            LoadContext::from_handle(&h, "a", "b"),
            Err(ContextError::NoLiveTokens)
        ));
    }

    #[test]
    fn context_requires_users() {
        let h = handle_with(2, 0, 0);
        assert!(matches!(
            LoadContext::from_handle(&h, "a", "b"),
            Err(ContextError::NoUsers)
        ));
    }

    #[test]
    fn context_requires_a_realm() {
        let mut h = handle_with(2, 0, 2);
        h.realms.clear();
        assert!(matches!(
            LoadContext::from_handle(&h, "a", "b"),
            Err(ContextError::NoRealms)
        ));
    }

    #[test]
    fn ropc_body_carries_the_grant() {
        let h = handle_with(1, 0, 1);
        let ctx =
            LoadContext::from_handle(&h, "admin@dev.local", "HearthDev123!").expect("context");
        let body = ctx.ropc_body();
        assert_eq!(body["grant_type"], "password");
        assert_eq!(body["client_id"], "client-1");
        assert_eq!(body["username"], "admin@dev.local");
        assert_eq!(body["password"], "HearthDev123!");
    }

    #[test]
    fn default_weights_register_all_five_journeys() {
        let w = Weights {
            validate: 70,
            session: 12,
            user: 8,
            issuance: 8,
            revoke: 2,
        };
        assert_eq!(w.total(), 100);
        let scenario = build_scenario(&w).expect("scenario");
        assert_eq!(
            scenario.transactions.len(),
            5,
            "all five journeys should be registered"
        );
    }

    #[test]
    fn zero_weight_journeys_are_dropped() {
        let w = Weights {
            validate: 100,
            session: 0,
            user: 0,
            issuance: 0,
            revoke: 0,
        };
        let scenario = build_scenario(&w).expect("scenario");
        assert_eq!(
            scenario.transactions.len(),
            1,
            "only the weighted journey should be registered"
        );
    }

    #[test]
    fn all_zero_weights_are_rejected() {
        let w = Weights {
            validate: 0,
            session: 0,
            user: 0,
            issuance: 0,
            revoke: 0,
        };
        assert!(build_scenario(&w).is_err(), "empty run must be rejected");
    }

    fn tier_ctx_for(corpus: u64, hot: u64) -> TierMissContext {
        TierMissContext::new(
            "realm-1".into(),
            "bulk-app".into(),
            "bulk.demo".into(),
            "DemoPassw0rd!".into(),
            corpus,
            hot,
        )
    }

    #[test]
    fn tier_email_matches_the_bulk_seeder_format() {
        let ctx = tier_ctx_for(1_000_000, 1_000);
        assert_eq!(ctx.email(1), "user0000001@bulk.demo");
        assert_eq!(ctx.email(1_000_000), "user1000000@bulk.demo");
    }

    #[test]
    fn hot_index_stays_within_the_resident_working_set() {
        let ctx = tier_ctx_for(1_000_000, 4);
        // Every hot draw must land in 1..=hot_set_size, and the set must cycle so
        // the same users are hit repeatedly (stay resident).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let idx = ctx.hot_index();
            assert!((1..=4).contains(&idx), "hot index {idx} out of working set");
            seen.insert(idx);
        }
        assert_eq!(seen.len(), 4, "hot draw should cycle the whole working set");
    }

    #[test]
    fn cold_index_spans_the_whole_corpus() {
        let ctx = tier_ctx_for(1_000_000, 1_000);
        // Cold draws must stay in-range and spread widely (not clustered in the
        // resident hot set), so most fall outside a below-corpus hot tier.
        let mut max_seen = 0;
        for _ in 0..2_000 {
            let idx = ctx.cold_index();
            assert!(
                (1..=1_000_000).contains(&idx),
                "cold index {idx} out of range"
            );
            max_seen = max_seen.max(idx);
        }
        assert!(
            max_seen > 1_000,
            "cold draw should reach well past the hot working set, got max {max_seen}"
        );
    }

    #[test]
    fn ropc_body_addresses_a_bulk_user_by_index() {
        let ctx = tier_ctx_for(1_000_000, 1_000);
        let body = ctx.ropc_body(42);
        assert_eq!(body["grant_type"], "password");
        assert_eq!(body["client_id"], "bulk-app");
        assert_eq!(body["username"], "user0000042@bulk.demo");
        assert_eq!(body["password"], "DemoPassw0rd!");
    }

    #[test]
    fn tier_scenario_registers_both_tiers_by_default() {
        let scenario = build_tier_scenario(50, 50).expect("scenario");
        assert_eq!(scenario.transactions.len(), 2);
    }

    #[test]
    fn tier_scenario_drops_a_zero_weight_tier() {
        // A pure cold sweep drops the hot tier.
        let scenario = build_tier_scenario(0, 100).expect("scenario");
        assert_eq!(scenario.transactions.len(), 1);
    }

    #[test]
    fn tier_scenario_rejects_all_zero_weights() {
        assert!(
            build_tier_scenario(0, 0).is_err(),
            "an empty tier-miss run must be rejected"
        );
    }
}

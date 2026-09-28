//! Async entry points for OAuth client authentication.
//!
//! A client secret is verified by one of two hashes: the fast
//! `$hearth-sha256$` format every Hearth-generated secret uses, or Argon2id for
//! a caller-chosen or legacy secret. The Argon2id arm must run behind the
//! process-wide KDF admission gate, and the gate must be waited on
//! ASYNCHRONOUSLY. The first gated version waited from inside the synchronous
//! engine call (`block_in_place` + `block_on`): every waiter took a
//! blocking-pool thread before it waited, so a burst of Argon2id client
//! authentications larger than `max_blocking_threads` left the handed-off
//! worker cores without a thread, nothing drove the timer that sheds a waiter,
//! and the runtime hung at 0 % CPU.
//!
//! Every protocol surface that authenticates a client by secret therefore
//! calls one of the functions here instead of the engine method directly.
//! When the caller presented a secret, each:
//!
//! 1. refuses it at once in a FAPI 2.0 Advanced realm, which accepts only
//!    `private_key_jwt` — before any gate, so the answer (and its latency)
//!    depends on the realm alone, never on whether the client exists or holds
//!    an Argon2id hash;
//! 2. if the client's stored hash is Argon2id, verifies the secret against it
//!    inside [`KdfGate::run`] — which awaits a permit (bounded by
//!    `max_queue_wait`, then shed) holding no thread — and runs ONLY that
//!    verification under the permit;
//! 3. runs the engine call synchronously on the caller's task inside a
//!    *client-secret scope* carrying that pre-verified result. The engine's
//!    Argon2id arm consumes it instead of hashing. Everything else the call
//!    does (token signing, issuance, storage) runs without a permit.
//!
//! If the engine meets an Argon2id hash the scope holds no result for — the
//! secret was rotated between step 2 and step 3 — it does not hash on the
//! caller's (worker) thread: it reports the hash and fails the call, and the
//! entry point verifies against that hash through the gate and runs the call
//! again. A fast-format secret, an unknown client (fast dummy) and a public
//! client never touch the gate.
//!
//! [`KdfGate::run`]: crate::identity::KdfGate::run

use std::sync::Arc;

use crate::core::{ClientId, RealmId};
use crate::identity::oidc::{ClientCredentialsRequest, ClientCredentialsResponse};
use crate::identity::{IdentityEngine, IdentityError, KdfGateError};

/// `client_assertion_type` for `private_key_jwt` (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Classifies the `private_key_jwt` fields of a request (RFC 7523 §2.2).
///
/// A blank field counts as absent. With neither field present the request
/// did not attempt assertion authentication: `Ok(None)`. A request that
/// carries EITHER field did, and must never fall through to another method
/// (a secret, `none`) or be ignored: it is `Ok(Some(assertion))` only when the
/// type is exactly [`CLIENT_ASSERTION_TYPE_JWT_BEARER`] and the assertion is
/// present — the caller then MUST verify it — and
/// [`IdentityError::InvalidClientAssertion`] otherwise.
///
/// # Errors
///
/// [`IdentityError::InvalidClientAssertion`] for a wrong or missing type, or
/// a type with no assertion.
pub fn presented_client_assertion<'a>(
    assertion_type: Option<&'a str>,
    assertion: Option<&'a str>,
) -> Result<Option<&'a str>, IdentityError> {
    let present = |field: Option<&'a str>| field.filter(|v| !v.trim().is_empty());
    match (present(assertion_type), present(assertion)) {
        (None, None) => Ok(None),
        (Some(CLIENT_ASSERTION_TYPE_JWT_BEARER), Some(jwt)) => Ok(Some(jwt)),
        _ => Err(IdentityError::InvalidClientAssertion {
            reason: format!(
                "client authentication by assertion requires client_assertion_type \
                 {CLIENT_ASSERTION_TYPE_JWT_BEARER} and a client_assertion"
            ),
        }),
    }
}

/// How often one entry-point call re-verifies after the stored hash changed
/// under it before shedding.
const MAX_SECRET_DISPATCHES: usize = 3;

/// An Argon2id verification the entry point ran through the gate for the
/// engine call it is about to make.
struct PreVerified {
    /// The stored hash the secret was verified against.
    hash: String,
    /// SHA-256 of the presented secret, so the result is only ever used for
    /// the secret it was computed for.
    secret_digest: [u8; 32],
    /// Whether the secret matched `hash`.
    matched: bool,
}

/// The client-secret scope of one synchronous engine call.
struct SecretScope {
    preverified: Option<PreVerified>,
    /// The Argon2id hash the engine met with no pre-verified result.
    unverified_hash: Option<String>,
}

thread_local! {
    /// Set while an entry point here runs an engine call on this thread.
    static SCOPE: std::cell::RefCell<Option<SecretScope>> =
        const { std::cell::RefCell::new(None) };
}

/// What the engine's Argon2id arm should do with a presented secret.
pub(crate) enum ScopedArgon2 {
    /// Not inside an entry point's scope (a direct engine call): the engine
    /// takes a permit only if one is free right now, else sheds.
    NotScoped,
    /// The entry point verified this secret against this hash: the result.
    Verified(bool),
    /// Inside a scope with no result for this hash: do NOT hash here — fail
    /// the call; the entry point verifies through the gate and runs it again.
    Redispatch,
}

/// Consulted by the engine before an Argon2id client-secret verification.
pub(crate) fn scoped_argon2_verification(hash: &str, presented: &[u8]) -> ScopedArgon2 {
    SCOPE.with_borrow_mut(|scope| {
        let Some(scope) = scope.as_mut() else {
            return ScopedArgon2::NotScoped;
        };
        if let Some(pre) = &scope.preverified {
            let digest = sha256(presented);
            if pre.hash == hash
                && bool::from(subtle::ConstantTimeEq::ct_eq(
                    &pre.secret_digest[..],
                    &digest[..],
                ))
            {
                return ScopedArgon2::Verified(pre.matched);
            }
        }
        scope.unverified_hash = Some(hash.to_string());
        ScopedArgon2::Redispatch
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

/// Runs `call` on this thread inside a client-secret scope; returns its
/// result and the Argon2id hash it met unverified, if any.
fn run_scoped<T>(
    preverified: Option<PreVerified>,
    call: impl FnOnce() -> Result<T, IdentityError>,
) -> (Result<T, IdentityError>, Option<String>) {
    struct Restore(Option<SecretScope>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCOPE.set(self.0.take());
        }
    }
    let _restore = Restore(SCOPE.replace(Some(SecretScope {
        preverified,
        unverified_hash: None,
    })));
    let result = call();
    let unverified = SCOPE.with_borrow_mut(|scope| scope.as_mut()?.unverified_hash.take());
    (result, unverified)
}

/// Verifies `secret` against the Argon2id `hash` inside the KDF gate: the only
/// work that holds a permit.
async fn preverify(
    secret: &zeroize::Zeroizing<Vec<u8>>,
    hash: String,
) -> Result<PreVerified, IdentityError> {
    let (for_gate, hash_for_gate) = (secret.clone(), hash.clone());
    let matched = match crate::identity::gate()
        .run(move || crate::identity::credentials::verify_raw_secret(&for_gate, &hash_for_gate))
        .await
    {
        Ok(result) => result?,
        Err(KdfGateError::Overloaded { retry_after }) => {
            return Err(IdentityError::KdfOverloaded { retry_after })
        }
        Err(e) => {
            return Err(IdentityError::Internal {
                reason: format!("client secret verification failed: {e}"),
            })
        }
    };
    Ok(PreVerified {
        hash,
        secret_digest: sha256(secret),
        matched,
    })
}

/// Runs `call` against `engine` for a request that presented `secret` (the
/// caller's own input: with none, nothing is hashed on any arm and the call
/// just runs).
///
/// See the module documentation: a FAPI 2.0 Advanced realm refuses a secret
/// first; an Argon2id verification runs alone inside the gate; the engine call
/// runs on the caller's task and is re-run (at most
/// [`MAX_SECRET_DISPATCHES`] times) if the stored hash changed under it.
///
/// # Errors
///
/// Whatever `call` returns; [`IdentityError::PrivateKeyJwtRequired`] in a
/// FAPI 2.0 Advanced realm; [`IdentityError::KdfOverloaded`] when the gate
/// shed the verification; [`IdentityError::Internal`] when the blocking task
/// failed.
pub async fn with_client_secret_gate<T, F>(
    engine: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    client_id: &ClientId,
    secret: Option<&str>,
    call: F,
) -> Result<T, IdentityError>
where
    F: Fn(&dyn IdentityEngine) -> Result<T, IdentityError>,
{
    let Some(secret) = secret else {
        return call(engine.as_ref());
    };
    // 1. The realm decides before any gate (review L3).
    if engine.get_realm(realm_id)?.is_some_and(|realm| {
        realm.config().fapi_profile == Some(crate::identity::FapiProfile::Advanced)
    }) {
        return Err(IdentityError::PrivateKeyJwtRequired);
    }
    let secret = zeroize::Zeroizing::new(secret.as_bytes().to_vec());
    // 2. Pre-verify against a stored Argon2id hash, inside the gate.
    let stored_argon2 = engine
        .get_client(realm_id, client_id)?
        .and_then(|client| client.client_secret_hash().map(str::to_string))
        .filter(|hash| !crate::identity::credentials::is_fast_client_secret_hash(hash));
    let mut preverified = match stored_argon2 {
        Some(hash) => Some(preverify(&secret, hash).await?),
        None => None,
    };
    // 3. The engine call, on this task, consuming the pre-verified result.
    for _ in 0..MAX_SECRET_DISPATCHES {
        let (result, unverified) = run_scoped(preverified.take(), || call(engine.as_ref()));
        match unverified {
            None => return result,
            // The hash changed since step 2 (a rotation): verify against the
            // one the engine met, through the gate, and run the call again.
            Some(hash) => preverified = Some(preverify(&secret, hash).await?),
        }
    }
    Err(IdentityError::KdfOverloaded {
        retry_after: std::time::Duration::from_secs(1),
    })
}

/// [`IdentityEngine::authenticate_client`] behind the async KDF gate.
///
/// # Errors
///
/// As [`IdentityEngine::authenticate_client`], plus
/// [`IdentityError::KdfOverloaded`] when an Argon2id verification was shed.
pub async fn authenticate_client(
    engine: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    client_id: &ClientId,
    client_secret: Option<&str>,
) -> Result<(), IdentityError> {
    with_client_secret_gate(engine, realm_id, client_id, client_secret, |e| {
        e.authenticate_client(realm_id, client_id, client_secret)
    })
    .await
}

/// [`IdentityEngine::authenticate_confidential_client`] behind the async KDF
/// gate.
///
/// # Errors
///
/// As [`IdentityEngine::authenticate_confidential_client`], plus
/// [`IdentityError::KdfOverloaded`] when an Argon2id verification was shed.
pub async fn authenticate_confidential_client(
    engine: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    client_id: &ClientId,
    client_secret: Option<&str>,
) -> Result<(), IdentityError> {
    with_client_secret_gate(engine, realm_id, client_id, client_secret, |e| {
        e.authenticate_confidential_client(realm_id, client_id, client_secret)
    })
    .await
}

/// [`IdentityEngine::client_credentials_token`] behind the async KDF gate.
///
/// # Errors
///
/// As [`IdentityEngine::client_credentials_token`], plus
/// [`IdentityError::KdfOverloaded`] when an Argon2id verification was shed.
pub async fn client_credentials_token(
    engine: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    request: ClientCredentialsRequest,
) -> Result<ClientCredentialsResponse, IdentityError> {
    // A request that attempted an assertion hashes nothing: the engine
    // verifies (or refuses) the assertion and never reaches the secret.
    let assertion_attempted = !matches!(
        presented_client_assertion(
            request.client_assertion_type.as_deref(),
            request.client_assertion.as_deref(),
        ),
        Ok(None)
    );
    let secret = request
        .client_secret
        .as_deref()
        .filter(|_| !assertion_attempted);
    with_client_secret_gate(engine, realm_id, &request.client_id, secret, |e| {
        e.client_credentials_token(realm_id, &request)
    })
    .await
}

#[cfg(test)]
mod tests {
    //! Where the Argon2id work of a client-secret check runs (KDF/PAR review
    //! L2, L4): only inside the gate's admitted closure, and nothing else
    //! there.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::audit::{AuditEngine, EmbeddedAuditEngine};
    use crate::core::{Clock, FakeClock, Timestamp};
    use crate::identity::credentials::{hash_verification_count, CredentialConfig};
    use crate::identity::{
        ClientTrustLevel, CreateRealmRequest, EmbeddedIdentityEngine, IdentityConfig,
        ImportClientRequest, RegisterClientRequest,
    };
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    const SECRET: &str = "caller-chosen-client-secret-1!";

    fn engine() -> (tempfile::TempDir, Arc<dyn IdentityEngine>, RealmId) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).unwrap(),
        ) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000))) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        let engine = EmbeddedIdentityEngine::new(
            storage,
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit,
        )
        .unwrap();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: format!("client-auth-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .unwrap()
            .id()
            .clone();
        (dir, Arc::new(engine), realm)
    }

    fn argon2_client(engine: &Arc<dyn IdentityEngine>, realm: &RealmId) -> ClientId {
        engine
            .register_client(
                realm,
                &RegisterClientRequest {
                    client_name: "argon2".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: Some(SECRET.to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                    trust_level: ClientTrustLevel::FirstParty,
                    ..Default::default()
                },
            )
            .unwrap()
            .client_id()
            .clone()
    }

    /// L4: the permit is held only while Argon2id runs — the rest of the
    /// engine call (for `client_credentials`: signing, issuance, storage) runs
    /// without it.
    #[tokio::test]
    async fn the_engine_call_runs_without_holding_a_kdf_permit() {
        let (_dir, engine, realm) = engine();
        let client = argon2_client(&engine, &realm);
        let (r, c) = (realm.clone(), client.clone());
        let permit_free_during_call =
            with_client_secret_gate(&engine, &realm, &client, Some(SECRET), move |e| {
                let free = crate::identity::gate().available_permits()
                    == crate::identity::gate().permits();
                e.authenticate_client(&r, &c, Some(SECRET))?;
                Ok(free)
            })
            .await
            .expect("the Argon2id client authenticates");
        assert!(
            permit_free_during_call,
            "the engine call must not hold a KDF permit; only the Argon2id verification may"
        );
    }

    /// L2: a secret that becomes Argon2id between the "is it Argon2id?"
    /// pre-check and the engine call (a rotation race — here, the client
    /// appears with an Argon2id secret after an unknown-client pre-check) is
    /// never verified inline on the caller's thread: the call is re-dispatched
    /// through the gate.
    #[tokio::test]
    async fn a_secret_rotated_to_argon2id_mid_call_is_not_verified_inline() {
        let (_dir, engine, realm) = engine();
        let client = ClientId::generate();
        let (r, c) = (realm.clone(), client.clone());
        let outcome = with_client_secret_gate(&engine, &realm, &client, Some(SECRET), move |e| {
            // The rotation lands after the pre-check (idempotent on a retry).
            let _ = e.import_client(
                &r,
                &ImportClientRequest {
                    id: Some(c.clone()),
                    client_name: "rotated".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: Some(SECRET.to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                    slug: None,
                    trust_level: ClientTrustLevel::FirstParty,
                    declared_scopes: vec![],
                    consent_spans_orgs: false,
                    id_token_signed_response_alg: None,
                    ..Default::default()
                },
            );
            let before = hash_verification_count();
            let result = e.authenticate_client(&r, &c, Some(SECRET));
            Ok((result, hash_verification_count() - before))
        })
        .await
        .unwrap();
        let (result, inline_argon2) = outcome;
        result.expect("the rotated client authenticates once re-dispatched");
        assert_eq!(
            inline_argon2, 0,
            "Argon2id must never run inline on the calling (worker) thread"
        );
    }
}

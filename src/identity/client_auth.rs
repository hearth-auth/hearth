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
//! Each first asks the engine whether the presented secret would be verified
//! with Argon2id ([`IdentityEngine::client_secret_needs_kdf`]):
//!
//! * no — the unknown-client dummy, a public client, or a fast-format secret:
//!   the engine call runs synchronously on the caller's task, ungated;
//! * yes — the WHOLE engine call is handed to [`KdfGate::run`], which awaits a
//!   permit (bounded by `max_queue_wait`, then shed) holding no thread, and
//!   runs the call on the blocking pool inside the admitted closure.
//!
//! [`KdfGate::run`]: crate::identity::KdfGate::run

use std::sync::Arc;

use crate::core::{ClientId, RealmId};
use crate::identity::oidc::{ClientCredentialsRequest, ClientCredentialsResponse};
use crate::identity::{IdentityEngine, IdentityError, KdfGateError};

/// Runs `call` against `engine`, first waiting for a KDF-gate permit when a
/// presented secret for `client_id` would be verified with Argon2id.
///
/// `secret_presented` is the caller's own input: with no secret nothing is
/// hashed on any arm, so no permit is needed.
///
/// # Errors
///
/// Whatever `call` returns; [`IdentityError::KdfOverloaded`] when the gate
/// shed the wait; [`IdentityError::Internal`] when the blocking task failed.
pub async fn with_client_secret_gate<T, F>(
    engine: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    client_id: &ClientId,
    secret_presented: bool,
    call: F,
) -> Result<T, IdentityError>
where
    F: FnOnce(&dyn IdentityEngine) -> Result<T, IdentityError> + Send + 'static,
    T: Send + 'static,
{
    if !secret_presented || !engine.client_secret_needs_kdf(realm_id, client_id)? {
        return call(engine.as_ref());
    }
    let engine = Arc::clone(engine);
    match crate::identity::gate()
        .run(move || call(engine.as_ref()))
        .await
    {
        Ok(result) => result,
        Err(KdfGateError::Overloaded { retry_after }) => {
            Err(IdentityError::KdfOverloaded { retry_after })
        }
        Err(e) => Err(IdentityError::Internal {
            reason: format!("client secret verification failed: {e}"),
        }),
    }
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
    let (realm, client, secret) = owned(realm_id, client_id, client_secret);
    with_client_secret_gate(engine, realm_id, client_id, secret.is_some(), move |e| {
        e.authenticate_client(&realm, &client, secret.as_deref().map(|s| s.as_str()))
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
    let (realm, client, secret) = owned(realm_id, client_id, client_secret);
    with_client_secret_gate(engine, realm_id, client_id, secret.is_some(), move |e| {
        e.authenticate_confidential_client(&realm, &client, secret.as_deref().map(|s| s.as_str()))
    })
    .await
}

/// [`IdentityEngine::authenticate_oauth_client`] behind the async KDF gate.
///
/// # Errors
///
/// As [`IdentityEngine::authenticate_oauth_client`], plus
/// [`IdentityError::KdfOverloaded`] when an Argon2id verification was shed.
pub async fn authenticate_oauth_client(
    engine: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    client_id: &ClientId,
    client_secret: &str,
) -> Result<(), IdentityError> {
    let (realm, client, secret) = owned(realm_id, client_id, Some(client_secret));
    with_client_secret_gate(engine, realm_id, client_id, true, move |e| {
        e.authenticate_oauth_client(
            &realm,
            &client,
            secret.as_deref().map_or("", |s| s.as_str()),
        )
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
    // An assertion-authenticated request hashes nothing.
    let secret_presented = request.client_secret.is_some()
        && request.client_assertion_type.as_deref()
            != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    let realm = realm_id.clone();
    let client_id = request.client_id.clone();
    with_client_secret_gate(engine, realm_id, &client_id, secret_presented, move |e| {
        e.client_credentials_token(&realm, &request)
    })
    .await
}

/// Owned copies for a `'static` closure; the secret is zeroized on drop.
fn owned(
    realm_id: &RealmId,
    client_id: &ClientId,
    secret: Option<&str>,
) -> (RealmId, ClientId, Option<zeroize::Zeroizing<String>>) {
    (
        realm_id.clone(),
        client_id.clone(),
        secret.map(|s| zeroize::Zeroizing::new(s.to_string())),
    )
}

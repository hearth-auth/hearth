//! Refresh-token rotation: family coverage, lost updates and consent.
//!
//! Four properties of the refresh grant that the audit of 2026-08-28 found
//! stated but not held:
//!
//! * **18.11 (§4.16#6)** — a refresh token with no `fid` takes a legacy branch
//!   with neither rotation nor reuse detection, so it replays forever and can
//!   never raise a theft event.
//! * **18.10 (§4.16#2)** — `revoke_session`'s grant-family cascade is an
//!   unsynchronised read-modify-write. A rotation already inside its locked
//!   window reads the family, works, and writes it back *after* the cascade's
//!   write, so the revocation is lost and the presenter keeps a live chain.
//! * **18.12 (§4.16#7)** — the RFC 7009 `/revoke` handler has the same shape:
//!   `POST /revoke` answers 200 and the grant survives.
//! * **18.16 (§4.16#11)** — revoking an application's consent leaves its grant
//!   families live, so it keeps refreshing.
//!
//! The two race tests do not sleep and do not hope for an interleaving. They
//! take the engine's own per-family advisory lock as a *probe*: while
//! `try_lock` fails, a rotation is provably between its family read and its
//! family write, which is exactly the window the revoker has to land in. An
//! attempt that fails to observe the window is retried rather than asserted on,
//! so the test is never vacuous and never flaky.

use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::identity::oidc::{StoredGrantFamily, TokenRevocationRequest};
use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

/// How many times a race test may re-run before giving up on observing the
/// rotation window. Each attempt uses a fresh grant family.
const RACE_ATTEMPTS: usize = 64;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Reads the stored grant family for `fid`, or `None` when it is gone.
fn load_family(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
    fid: &str,
) -> Option<StoredGrantFamily> {
    let bytes = engine
        .storage
        .get(realm_id, &keys::encode_grant_family(fid))
        .expect("family read")?;
    Some(serde_json::from_slice(&bytes).expect("family decode"))
}

/// Returns the `fid` carried by `refresh_token`.
fn fid_of(refresh_token: &str) -> String {
    crate::identity::tokens::decode_claims_unverified(refresh_token)
        .expect("decode refresh")
        .fid
        .expect("refresh token must carry a grant family")
}

/// Creates a realm, user, session and one refresh token belonging to a family.
fn seed_family(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
) -> (UserId, SessionId, String, String) {
    let user = create_test_user(engine, realm_id);
    let session = engine
        .create_session(realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(realm_id, user.id(), session.id())
        .expect("issue tokens");
    let refresh = pair.refresh_token().to_string();
    let fid = fid_of(&refresh);
    (user.id().clone(), session.id().clone(), refresh, fid)
}

/// Runs `revoker` from the main thread while a rotation of `fid` is provably
/// inside its locked read-modify-write window.
///
/// Returns `true` when the window was observed. The caller retries otherwise;
/// it never asserts on an attempt that did not catch the race.
fn race_revoker_against_rotation<R>(
    engine: &Arc<EmbeddedIdentityEngine>,
    realm_id: &RealmId,
    refresh_token: &str,
    fid: &str,
    revoker: R,
) -> bool
where
    R: FnOnce(),
{
    let rotation_done = Arc::new(AtomicBool::new(false));
    let handle = {
        let engine = Arc::clone(engine);
        let realm_id = realm_id.clone();
        let token = refresh_token.to_string();
        let done = Arc::clone(&rotation_done);
        std::thread::spawn(move || {
            let result = engine.refresh_tokens(&realm_id, &token, None, None);
            done.store(true, Ordering::Release);
            result
        })
    };

    // Spin — without sleeping — until the rotation thread holds the family
    // lock. `try_lock` failing is the observable proof that it is between its
    // family read and its family write.
    let mut caught = false;
    loop {
        let probe = engine.grant_family_lock(realm_id, fid);
        if probe.try_lock().is_err() {
            caught = true;
            break;
        }
        drop(probe);
        if rotation_done.load(Ordering::Acquire) {
            break;
        }
        std::hint::spin_loop();
    }

    if caught {
        revoker();
    }
    let _ = handle.join().expect("rotation thread");
    caught
}

// ---------------------------------------------------------------------------
// 18.11 — every refresh token must belong to a grant family
// ---------------------------------------------------------------------------

/// A refresh token with no `fid` bypassed rotation entirely: `refresh_tokens`
/// took a legacy branch that re-issued a fresh pair without consuming the
/// presented token, so the same token replayed indefinitely and reuse could
/// never be detected (audit 2026-08-28 §4.16#6).
///
/// Every issuance path now mints an `fid`, so a token without one is either
/// pre-upgrade or crafted. Either way it must be refused, not served by a
/// branch with weaker guarantees than the one it skips.
#[test]
fn refresh_token_without_a_grant_family_is_refused() {
    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let (_user, _session, refresh, _fid) = seed_family(&engine, &realm_id);

    // A well-formed, correctly-signed refresh token that simply carries no
    // family — exactly what the pre-8.9 issuance paths minted.
    let mut claims = crate::identity::tokens::decode_claims_unverified(&refresh).expect("decode");
    claims.fid = None;
    claims.jti = Some(uuid::Uuid::new_v4().to_string());
    let legacy = engine
        .get_signing_key_or_default(&realm_id)
        .issue_token(&claims)
        .expect("sign legacy refresh");

    let first = engine.refresh_tokens(&realm_id, &legacy, None, None);
    assert!(
        first.is_err(),
        "a refresh token with no grant family has neither rotation nor reuse \
         detection; it must be refused, not honoured"
    );

    // The defining symptom: the legacy branch consumed nothing, so the very
    // same token worked again. Assert the second presentation fails too, so a
    // fix that only rate-limits the first cannot pass.
    let second = engine.refresh_tokens(&realm_id, &legacy, None, None);
    assert!(
        second.is_err(),
        "a family-less refresh token must never be replayable"
    );
}

// ---------------------------------------------------------------------------
// 18.10 — a session revocation must not be lost to a concurrent rotation
// ---------------------------------------------------------------------------

/// `revoke_session` cascades `revoked = true` onto every grant family issued
/// under the session, but did so without the per-family advisory lock that
/// `rotate_grant_family` holds across its read-modify-write. A rotation already
/// inside that window overwrote the cascade's write with `revoked = false` and
/// a freshly rotated hash — so a holder of a stolen refresh token who lands a
/// redemption while the victim is logging out keeps a live chain, and because
/// the token it presented *was* the current one, no theft event fires
/// (audit 2026-08-28 §4.16#2).
#[test]
fn session_revocation_survives_a_concurrent_rotation() {
    let (_dir, engine, _clock) = setup_engine();
    let engine = Arc::new(engine);
    let realm_id = create_test_realm(&engine);

    let mut observed = false;
    for _ in 0..RACE_ATTEMPTS {
        let (_user, session_id, refresh, fid) = seed_family(&engine, &realm_id);

        let revoked_ok = Arc::new(AtomicBool::new(false));
        let caught = {
            let engine = Arc::clone(&engine);
            let realm = realm_id.clone();
            let sid = session_id.clone();
            let flag = Arc::clone(&revoked_ok);
            race_revoker_against_rotation(&engine.clone(), &realm_id, &refresh, &fid, move || {
                if engine.revoke_session(&realm, &sid).is_ok() {
                    flag.store(true, Ordering::Release);
                }
            })
        };
        if !caught {
            continue;
        }
        observed = true;

        assert!(
            revoked_ok.load(Ordering::Acquire),
            "revoke_session must succeed even while a rotation is in flight"
        );
        let family = load_family(&engine, &realm_id, &fid).expect("family still stored");
        assert!(
            family.revoked,
            "revoke_session cascaded revoked=true onto grant family {fid}, but a \
             rotation that was mid-window wrote the family back un-revoked; the \
             revocation was lost and the grant is still live"
        );
        break;
    }

    assert!(
        observed,
        "never observed a rotation inside its locked window in {RACE_ATTEMPTS} \
         attempts; the test proved nothing"
    );
}

// ---------------------------------------------------------------------------
// 18.12 — an RFC 7009 revocation must not be lost to a concurrent rotation
// ---------------------------------------------------------------------------

/// `POST /revoke` marks the grant family revoked with a bare get/put and no
/// advisory lock, so a rotation holding the family lock re-wrote it as
/// un-revoked. The endpoint answered `200 OK` — which RFC 7009 §2.2 lets the
/// client read as "the token is now invalid" — while the grant kept working
/// (audit 2026-08-28 §4.16#7).
#[test]
fn rfc7009_revocation_survives_a_concurrent_rotation() {
    let (_dir, engine, _clock) = setup_engine();
    let engine = Arc::new(engine);
    let realm_id = create_test_realm(&engine);

    let mut observed = false;
    for _ in 0..RACE_ATTEMPTS {
        let (_user, _session_id, refresh, fid) = seed_family(&engine, &realm_id);

        let revoked_ok = Arc::new(AtomicBool::new(false));
        let caught = {
            let engine = Arc::clone(&engine);
            let realm = realm_id.clone();
            let token = refresh.clone();
            let flag = Arc::clone(&revoked_ok);
            race_revoker_against_rotation(&engine.clone(), &realm_id, &refresh, &fid, move || {
                let request = TokenRevocationRequest {
                    token,
                    token_type_hint: Some("refresh_token".to_string()),
                };
                if engine.revoke_token(&realm, &request).is_ok() {
                    flag.store(true, Ordering::Release);
                }
            })
        };
        if !caught {
            continue;
        }
        observed = true;

        assert!(
            revoked_ok.load(Ordering::Acquire),
            "RFC 7009 revocation must report success"
        );
        let family = load_family(&engine, &realm_id, &fid).expect("family still stored");
        assert!(
            family.revoked,
            "POST /revoke returned 200 for grant family {fid} but a concurrent \
             rotation wrote the family back un-revoked; the grant survived the \
             revocation the client was told had succeeded"
        );
        break;
    }

    assert!(
        observed,
        "never observed a rotation inside its locked window in {RACE_ATTEMPTS} \
         attempts; the test proved nothing"
    );
}

// ---------------------------------------------------------------------------
// 18.16 — revoking consent must stop the application refreshing
// ---------------------------------------------------------------------------

/// Revoking an application's consent deleted the consent record and nothing
/// else. The grant families issued under that consent stayed live, and
/// `rotate_grant_family`'s consent check only compares scope digests *when a
/// record exists* — so deleting the record removed the only thing that check
/// could fail on, and the application kept refreshing forever
/// (audit 2026-08-28 §4.16#11).
#[test]
fn revoking_consent_kills_the_applications_refresh_chain() {
    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);

    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Consent App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    engine
        .grant_consent(
            &realm_id,
            user.id(),
            client.client_id(),
            &["openid".to_string()],
        )
        .expect("grant consent");

    let auth = engine
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                state: "csrf-state".to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                user_id: user.id().clone(),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    let tokens = engine
        .exchange_authorization_code(
            &realm_id,
            &crate::identity::oidc::TokenExchangeRequest {
                code: auth.code().to_string(),
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange");

    let rotated = engine
        .refresh_tokens(&realm_id, tokens.refresh_token(), None, None)
        .expect("refresh before consent revocation must work");

    engine
        .revoke_consent(&realm_id, user.id(), client.client_id())
        .expect("revoke consent");

    let after = engine.refresh_tokens(&realm_id, rotated.refresh_token(), None, None);
    assert!(
        after.is_err(),
        "the user revoked this application's consent; its refresh chain must be \
         dead, but the grant kept rotating"
    );
}

// ---------------------------------------------------------------------------
// 18.15 — disabling a user must fail when the session revocation fails
// ---------------------------------------------------------------------------

/// Storage double that fails writes touching the session record family once
/// armed. Every other key is passed through to the real engine.
struct SessionWriteFailStorage {
    inner: Arc<dyn StorageEngine>,
    armed: AtomicBool,
    /// Keys the double refused, for assertion messages.
    refused: Mutex<Vec<Vec<u8>>>,
}

impl SessionWriteFailStorage {
    fn new(inner: Arc<dyn StorageEngine>) -> Self {
        Self {
            inner,
            armed: AtomicBool::new(false),
            refused: Mutex::new(Vec::new()),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    fn disarm(&self) {
        self.armed.store(false, Ordering::Release);
    }

    fn refuses(&self, key: &[u8]) -> bool {
        self.armed.load(Ordering::Acquire) && key.starts_with(b"ses:id:")
    }

    fn refuse(&self, key: &[u8]) -> StorageError {
        #[allow(clippy::unwrap_used)]
        // INVARIANT: test-only double; a poisoned mutex here fails the test loudly.
        self.refused.lock().unwrap().push(key.to_vec());
        StorageError::Io(std::io::Error::other("injected session write failure"))
    }

    fn refused_count(&self) -> usize {
        #[allow(clippy::unwrap_used)]
        // INVARIANT: test-only double; a poisoned mutex here fails the test loudly.
        self.refused.lock().unwrap().len()
    }
}

impl StorageEngine for SessionWriteFailStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        if self.refuses(key) {
            return Err(self.refuse(key));
        }
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        self.inner.scan(realm_id, start, end)
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        if let Some((key, _)) = entries.iter().find(|(k, _)| self.refuses(k)) {
            return Err(self.refuse(key));
        }
        self.inner.put_batch(realm_id, entries)
    }

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        self.inner.enqueue_batch(realm_id, entries)
    }

    fn await_batch_durable(&self, handle: StorageDurabilityHandle) -> Result<(), StorageError> {
        self.inner.await_batch_durable(handle)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        self.inner.list_realms()
    }

    fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        self.inner.complete_snapshot_restore()
    }
}

/// `POST /revoke` must not answer `200 OK` when the revocation failed.
///
/// RFC 7009 §2.2 lets a client read `200` as "the token is now invalid", so a
/// success returned over a failed revoke tells the client a LIVE credential is
/// dead. `revoke_token_inner` discarded the outcome of both its access-token
/// arms — `revoke_session` and the JTI blocklist write — and returned `Ok(())`
/// regardless. Same class as the swallowed session write below (§4.16#10) and
/// the reset mails that were minted and dropped (§4.24#10).
#[test]
fn revoking_an_access_token_fails_when_the_session_write_fails() {
    use crate::identity::oidc::TokenRevocationRequest;

    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let real =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let failing = Arc::new(SessionWriteFailStorage::new(real));
    let storage = Arc::clone(&failing) as Arc<dyn StorageEngine>;

    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(crate::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        identity_config,
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation");

    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    // Control: with the fault disarmed the revocation succeeds, so the
    // assertion below cannot pass merely because revocation always fails.
    engine
        .revoke_token_inner(
            &realm_id,
            &TokenRevocationRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("an unarmed revocation must succeed");

    let session2 = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("second session");
    let tokens2 = engine
        .issue_tokens(&realm_id, user.id(), session2.id())
        .expect("issue tokens");

    failing.arm();
    let result = engine.revoke_token_inner(
        &realm_id,
        &TokenRevocationRequest {
            token: tokens2.access_token().to_string(),
            token_type_hint: None,
        },
    );
    assert!(
        result.is_err(),
        "a revocation whose session write failed must not report success"
    );
    assert!(
        failing.refused_count() > 0,
        "the fault must actually have fired, or the assertion above is vacuous"
    );
}

/// `update_user(status = Disabled)` revokes every session so the user's live
/// access and refresh tokens stop working — revocation is the *only* mechanism
/// that enforces a disable, because access tokens embed their claims at
/// issuance. The revocation failure was swallowed into a `tracing::warn!` and
/// the call returned `Ok(user)`: the operator saw a disabled user, the audit
/// log recorded a disable, and the user's refresh token kept minting tokens
/// (audit 2026-08-28 §4.16#10).
#[test]
fn disabling_a_user_fails_when_the_session_revocation_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let real =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let failing = Arc::new(SessionWriteFailStorage::new(real));
    let storage = Arc::clone(&failing) as Arc<dyn StorageEngine>;

    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(crate::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        identity_config,
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation");

    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    failing.arm();

    let result = engine.update_user(
        &realm_id,
        user.id(),
        &UpdateUserRequest {
            status: Some(crate::identity::types::UserStatus::Disabled),
            ..Default::default()
        },
    );

    assert!(
        failing.refused_count() > 0,
        "the double never refused a session write; the test would prove nothing"
    );
    assert!(
        result.is_err(),
        "the session revocation that enforces a disable failed, so update_user \
         must report the disable it did not achieve — it returned Ok"
    );

    // And the symptom the caller actually cares about: the user's refresh token
    // is still live, which is precisely why reporting success is wrong. Disarm
    // first — the refresh path writes the session too, so an armed double would
    // fail this for the wrong reason.
    failing.disarm();
    assert!(
        engine
            .refresh_tokens(&realm_id, tokens.refresh_token(), None, None)
            .is_ok(),
        "sanity: the injected failure did leave the session usable, so the \
         reported success would have been a lie"
    );
}

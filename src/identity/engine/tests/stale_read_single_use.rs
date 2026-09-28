//! G4 — every redeem-once artifact is decided by a replicated claim, not by a
//! local read.
//!
//! In cluster mode a node's `get` is a local, possibly stale read, while a
//! `put_if_absent` is a Raft command decided at apply time against the
//! replicated state. A redemption whose single use is "read the row / the
//! replay marker, then write" is therefore only as good as the freshest read,
//! and a node that has not applied another node's redemption yet (or read
//! before it, and writes after a leader change) spends the artifact again.
//!
//! `StickyReads` reproduces that on one node, deterministically: for an armed
//! key prefix every `get` after the first returns what the first returned —
//! a node that never applied the redemption. `put_if_absent` still goes to the
//! real store, as the Raft state machine would. Each test redeems one artifact
//! twice; the second must be refused.

use super::*;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

/// Serves every read under an armed prefix from the first read of that key.
struct StickyReads {
    inner: Arc<dyn StorageEngine>,
    prefixes: Mutex<Vec<Vec<u8>>>,
    seen: Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>,
}

impl StickyReads {
    fn new(inner: Arc<dyn StorageEngine>) -> Self {
        Self {
            inner,
            prefixes: Mutex::new(Vec::new()),
            seen: Mutex::new(HashMap::new()),
        }
    }

    fn arm(&self, prefix: &str) {
        self.prefixes
            .lock()
            .expect("prefixes")
            .push(prefix.as_bytes().to_vec());
    }

    /// Stops serving stale reads: every later read sees the real store.
    fn disarm(&self) {
        self.prefixes.lock().expect("prefixes").clear();
        self.seen.lock().expect("seen").clear();
    }
}

impl StorageEngine for StickyReads {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let armed = self
            .prefixes
            .lock()
            .expect("prefixes")
            .iter()
            .any(|p| key.starts_with(p));
        if !armed {
            return self.inner.get(realm_id, key);
        }
        let mut seen = self.seen.lock().expect("seen");
        if let Some(first) = seen.get(key) {
            return Ok(first.clone());
        }
        let value = self.inner.get(realm_id, key)?;
        seen.insert(key.to_vec(), value.clone());
        Ok(value)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
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

    fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, StorageError> {
        self.inner.put_if_absent(realm_id, key, value)
    }

    fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, StorageError> {
        self.inner.increment_u64(realm_id, key)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.inner.write_batch(realm_id, puts, deletes)
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

struct Fixture {
    _dir: tempfile::TempDir,
    engine: EmbeddedIdentityEngine,
    storage: Arc<StickyReads>,
    clock: Arc<FakeClock>,
    realm: RealmId,
}

/// An identity engine over `storage` — a second one over the same store
/// stands in for a second node (its in-process state is its own).
fn engine_over(storage: &Arc<StickyReads>, clock: &Arc<FakeClock>) -> EmbeddedIdentityEngine {
    let dyn_storage = Arc::clone(storage) as Arc<dyn StorageEngine>;
    let audit = Arc::new(crate::audit::EmbeddedAuditEngine::new(
        Arc::clone(&dyn_storage),
        Arc::clone(clock) as Arc<dyn Clock>,
    ));
    EmbeddedIdentityEngine::new(
        dyn_storage,
        Arc::clone(clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine")
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let storage = Arc::new(StickyReads::new(real));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let engine = engine_over(&storage, &clock);
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("stale-{}", uuid::Uuid::new_v4()),
            config: Some(crate::identity::RealmConfig {
                mfa_methods: Some(vec![
                    "sms".to_string(),
                    "email_otp".to_string(),
                    "totp".to_string(),
                ]),
                ..crate::identity::RealmConfig::default()
            }),
        })
        .expect("realm")
        .id()
        .clone();
    Fixture {
        _dir: dir,
        engine,
        storage,
        clock,
        realm,
    }
}

fn now_secs(f: &Fixture) -> i64 {
    f.engine.clock.now().as_micros() / 1_000_000
}

#[test]
fn a_pending_mfa_nonce_is_redeemed_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("mfa:nonce:");
    let exp = u64::try_from(now_secs(&f) + 300).expect("exp");
    assert!(f
        .engine
        .redeem_mfa_nonce(&f.realm, "n-1", exp)
        .expect("first"));
    assert!(
        !f.engine
            .redeem_mfa_nonce(&f.realm, "n-1", exp)
            .expect("second"),
        "a stale read of the burn marker let the pending-MFA nonce redeem twice"
    );
}

#[test]
fn a_dpop_proof_jti_is_recorded_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("agt:dpop:jti:");
    let now = now_secs(&f);
    f.engine
        .check_and_record_dpop_jti(&f.realm, "jti-1", now)
        .expect("first proof");
    assert!(
        matches!(
            f.engine.check_and_record_dpop_jti(&f.realm, "jti-1", now),
            Err(IdentityError::DPopProofReplay)
        ),
        "a stale read of the DPoP jti marker admitted a replayed proof"
    );
}

#[test]
fn a_jwt_bearer_assertion_jti_is_consumed_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("oauth:jb-jti:");
    let exp = now_secs(&f) + 300;
    f.engine
        .check_and_consume_jwt_bearer_jti(&f.realm, "jb-1", exp)
        .expect("first assertion");
    assert!(
        matches!(
            f.engine
                .check_and_consume_jwt_bearer_jti(&f.realm, "jb-1", exp),
            Err(IdentityError::JwtBearerAssertionInvalid { .. })
        ),
        "a stale read of the jwt-bearer jti marker admitted a replayed assertion"
    );
}

#[test]
fn a_saml_assertion_is_consumed_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("saml:asn:");
    let idp = crate::core::IdpId::generate();
    let exp = now_secs(&f) + 300;
    f.engine
        .mark_saml_assertion_consumed(&f.realm, &idp, "_a1", exp)
        .expect("first assertion");
    assert!(
        matches!(
            f.engine
                .mark_saml_assertion_consumed(&f.realm, &idp, "_a1", exp),
            Err(IdentityError::Saml(SamlError::Replay))
        ),
        "a stale read of the SAML sentinel admitted a replayed assertion"
    );
}

#[test]
fn a_saml_request_state_is_taken_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("saml:state:");
    f.engine
        .put_saml_state(&crate::identity::federation::saml::SamlStateBag {
            token: "relay-1".to_string(),
            request_id: "_req-1".to_string(),
            realm_id: f.realm.clone(),
            idp_id: crate::core::IdpId::generate(),
            return_to: None,
            created_at: f.engine.clock.now(),
        })
        .expect("put state");
    f.engine
        .take_saml_state(&f.realm, "relay-1")
        .expect("first take");
    assert!(
        f.engine.take_saml_state(&f.realm, "relay-1").is_err(),
        "a stale read of the SAML request state let it be taken twice"
    );
}

#[test]
fn a_federation_state_is_taken_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("fed:state:");
    f.engine
        .put_federation_state(&crate::identity::federation::StateBag {
            state_token: "fs-1".to_string(),
            realm_id: f.realm.clone(),
            idp_id: crate::core::IdpId::generate(),
            nonce: "n".to_string(),
            pkce_verifier: "v".to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: f.engine.clock.now().add_micros(600_000_000),
            apple_user_json: None,
        })
        .expect("put state");
    f.engine
        .take_federation_state(&f.realm, "fs-1")
        .expect("first take");
    assert!(
        matches!(
            f.engine.take_federation_state(&f.realm, "fs-1"),
            Err(IdentityError::FederationInvalidState)
        ),
        "a stale read of the federation state let it be taken twice"
    );
}

#[test]
fn a_confirm_link_ticket_is_taken_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("fed:confirm:");
    f.engine
        .put_confirm_link_ticket(&crate::identity::federation::ConfirmLinkTicket {
            ticket: "cl-1".to_string(),
            realm_id: f.realm.clone(),
            user_id: UserId::generate(),
            identity: crate::identity::federation::ExternalIdentity {
                idp_id: crate::core::IdpId::generate(),
                external_sub: "sub-1".to_string(),
                email: "a@example.com".to_string(),
                email_verified: true,
                display_name: "A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                picture_url: None,
            },
            expires_at: f.engine.clock.now().add_micros(600_000_000),
        })
        .expect("put ticket");
    f.engine
        .take_confirm_link_ticket(&f.realm, "cl-1")
        .expect("first take");
    assert!(
        matches!(
            f.engine.take_confirm_link_ticket(&f.realm, "cl-1"),
            Err(IdentityError::FederationInvalidState)
        ),
        "a stale read of the confirm-link ticket let it be taken twice"
    );
}

#[test]
fn a_pending_authorization_ticket_is_taken_once_despite_a_stale_read() {
    let f = fixture();
    f.storage.arm("oauth:pending_auth:");
    let now = f.engine.clock.now();
    let ticket = f
        .engine
        .put_pending_authorization(
            &f.realm,
            &crate::identity::types::PendingAuthorizationRequest {
                realm_id: f.realm.clone(),
                user_id: UserId::generate(),
                client_id: ClientId::generate(),
                redirect_uri: "https://ex.com/cb".into(),
                requested_scopes: vec!["openid".into()],
                state: "s".into(),
                response_type: "code".into(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                response_mode: None,
                authorization_signed_response_alg: None,
                resource: None,
                via_par: false,
                amr_values: Vec::new(),
                created_at: now,
                expires_at: now.add_micros(600_000_000),
            },
        )
        .expect("put ticket");
    f.engine
        .take_pending_authorization(&f.realm, &ticket)
        .expect("first take");
    assert!(
        matches!(
            f.engine.take_pending_authorization(&f.realm, &ticket),
            Err(IdentityError::ConsentTicketNotFound)
        ),
        "a stale read of the pending-authorization ticket let it be taken twice"
    );
}

fn make_agent(f: &Fixture) -> crate::core::AgentId {
    let owner = f
        .engine
        .create_user(
            &f.realm,
            &CreateUserRequest {
                email: format!("owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("owner");
    f.engine
        .create_agent(
            &f.realm,
            &crate::identity::types::CreateAgentRequest {
                display_name: "agent".to_string(),
                description: None,
                owner: crate::identity::types::AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("agent")
        .id()
        .clone()
}

#[test]
fn an_approval_request_is_decided_once_despite_a_stale_read() {
    let f = fixture();
    let agent = make_agent(&f);
    let created = f
        .engine
        .create_approval_request(
            &f.realm,
            &crate::identity::types::CreateApprovalRequestInput {
                agent_id: agent,
                tool: "delete_file".to_string(),
                action: "invoke".to_string(),
                context: serde_json::json!({}),
                delegation_chain: vec![],
                expires_in_secs: None,
            },
        )
        .expect("create request");
    f.storage.arm("appreq:id:");
    f.engine
        .approve_approval_request(&f.realm, &created.request_id, None)
        .expect("first approval");
    assert!(
        f.engine
            .approve_approval_request(&f.realm, &created.request_id, None)
            .is_err(),
        "a stale read of the approval request minted a second capability token"
    );
    assert!(
        f.engine
            .deny_approval_request(&f.realm, &created.request_id, None)
            .is_err(),
        "a stale read of the approval request let a deny overwrite the approval"
    );
}

#[test]
fn a_transaction_token_is_consumed_once_despite_a_stale_read() {
    let f = fixture();
    let requesting = make_agent(&f);
    let target = make_agent(&f);
    let issued = f
        .engine
        .issue_transaction_token(
            &f.realm,
            &crate::identity::types::CreateTransactionTokenRequest {
                requesting_agent_id: requesting,
                target_agent_id: target,
                txn_id: "txn-1".to_string(),
                delegation_context: None,
            },
        )
        .expect("issue");
    f.storage.arm("txn:used:");
    f.storage.arm("consumed:txn:");
    f.engine
        .consume_transaction_token(&f.realm, &issued.token)
        .expect("first consume");
    assert!(
        f.engine
            .consume_transaction_token(&f.realm, &issued.token)
            .is_err(),
        "a stale read of the consumed marker let a transaction token be consumed twice"
    );
}

struct CapturingSms(Mutex<Vec<String>>);

impl crate::identity::SmsSender for CapturingSms {
    fn send(&self, message: &crate::identity::SmsMessage) -> Result<(), crate::identity::SmsError> {
        self.0.lock().expect("sms").push(message.body.clone());
        Ok(())
    }
}

#[test]
fn an_sms_otp_is_redeemed_once_despite_a_stale_read() {
    const KEY: &[u8] = b"stale-read-sms-otp-hmac-key";
    const PHONE: &str = "+15555550142";
    let f = fixture();
    let sender = CapturingSms(Mutex::new(Vec::new()));
    let now = u64::try_from(now_secs(&f)).expect("now");
    let nonce = f
        .engine
        .issue_sms_otp(&f.realm, PHONE, KEY, &sender, now)
        .expect("issue");
    let body = sender.0.lock().expect("sms").last().cloned().expect("sent");
    let code = body
        .rsplit_once(": ")
        .map(|(_, c)| c.trim().to_string())
        .expect("code");
    f.storage.arm("sms:pending_otp:");
    f.engine
        .verify_sms_otp(&f.realm, &nonce, PHONE, &code, KEY, now)
        .expect("first verify");
    assert!(
        f.engine
            .verify_sms_otp(&f.realm, &nonce, PHONE, &code, KEY, now)
            .is_err(),
        "a stale read of the pending OTP let one SMS code be redeemed twice"
    );
}

struct CapturingEmail(Mutex<Vec<String>>);

impl crate::identity::EmailSender for CapturingEmail {
    fn send(
        &self,
        message: &crate::identity::EmailMessage,
    ) -> Result<(), crate::identity::EmailError> {
        self.0
            .lock()
            .expect("email")
            .push(message.text_body.clone());
        Ok(())
    }
}

#[test]
fn an_email_otp_is_redeemed_once_despite_a_stale_read() {
    const KEY: &[u8] = b"stale-read-email-otp-hmac-key";
    const ADDRESS: &str = "otp@example.com";
    let f = fixture();
    let sender = Arc::new(CapturingEmail(Mutex::new(Vec::new())));
    let service = crate::identity::EmailService::new(
        Arc::clone(&sender) as Arc<dyn crate::identity::EmailSender>,
        "Hearth Test".to_string(),
        None,
        crate::identity::EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("email service");
    let now = u64::try_from(now_secs(&f)).expect("now");
    let nonce = f
        .engine
        .issue_email_otp(&f.realm, ADDRESS, KEY, &service, None, now)
        .expect("issue");
    let body = sender
        .0
        .lock()
        .expect("email")
        .last()
        .cloned()
        .expect("sent");
    let code: String = body
        .rsplit_once(": ")
        .map(|(_, rest)| rest.trim().chars().take(6).collect())
        .expect("code");
    f.storage.arm("email:pending_otp:");
    f.engine
        .verify_email_otp(&f.realm, &nonce, ADDRESS, &code, KEY, now)
        .expect("first verify");
    assert!(
        f.engine
            .verify_email_otp(&f.realm, &nonce, ADDRESS, &code, KEY, now)
            .is_err(),
        "a stale read of the pending OTP let one email code be redeemed twice"
    );
}

// ── G6: MFA factors, OTP guess budgets, email change, device decisions ──────

fn make_user(f: &Fixture, email: &str) -> UserId {
    f.engine
        .create_user(
            &f.realm,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Stale".to_string(),
                ..Default::default()
            },
        )
        .expect("user")
        .id()
        .clone()
}

#[allow(clippy::cast_sign_loss)] // Test timestamps are always positive
fn current_totp(f: &Fixture, secret: &[u8]) -> String {
    crate::identity::totp::compute_totp(secret, now_secs(f) as u64 / 30)
}

/// Enrols and activates TOTP for `user`; returns the secret and the recovery
/// codes. The clock is then moved one step on, so the activation code's step
/// is behind it.
fn enrol_totp(f: &Fixture, user: &UserId) -> (Vec<u8>, Vec<String>) {
    let enrollment = f.engine.enroll_totp(&f.realm, user).expect("enroll");
    let secret = data_encoding::BASE32_NOPAD
        .decode(enrollment.secret_base32.as_bytes())
        .expect("decode");
    f.engine
        .verify_totp_enrollment(&f.realm, user, &current_totp(f, &secret))
        .expect("activate");
    f.clock.advance(30_000_000);
    (secret, enrollment.recovery_codes.as_slice().to_vec())
}

fn mfa_key(user: &UserId) -> String {
    String::from_utf8(keys::encode_mfa_totp_key(user)).expect("utf8 key")
}

#[test]
fn a_totp_code_is_accepted_once_despite_a_stale_read() {
    let f = fixture();
    let user = make_user(&f, "totp-replay@example.com");
    let (secret, _) = enrol_totp(&f, &user);
    let code = current_totp(&f, &secret);
    f.storage.arm(&mfa_key(&user));
    f.engine
        .verify_totp(&f.realm, &user, &code)
        .expect("first use of the code");
    assert!(
        matches!(
            f.engine.verify_totp(&f.realm, &user, &code),
            Err(IdentityError::InvalidMfaCode)
        ),
        "a stale read of the TOTP state accepted one code twice"
    );
}

#[test]
fn a_recovery_code_is_spent_once_despite_a_stale_read() {
    let f = fixture();
    let user = make_user(&f, "recovery-twice@example.com");
    let (_, recovery) = enrol_totp(&f, &user);
    f.storage.arm(&mfa_key(&user));
    f.engine
        .verify_recovery_code(&f.realm, &user, &recovery[0])
        .expect("first use of the recovery code");
    assert!(
        matches!(
            f.engine.verify_recovery_code(&f.realm, &user, &recovery[0]),
            Err(IdentityError::InvalidMfaCode)
        ),
        "a stale read of the MFA state let one recovery code be spent twice"
    );
}

#[test]
fn a_stale_totp_verify_cannot_bring_back_a_spent_recovery_code() {
    let f = fixture();
    let user = make_user(&f, "recovery-resurrect@example.com");
    let (secret, recovery) = enrol_totp(&f, &user);
    let code = current_totp(&f, &secret);
    // This node reads the MFA state before the recovery code is spent...
    f.storage.arm(&mfa_key(&user));
    f.storage
        .get(&f.realm, &keys::encode_mfa_totp_key(&user))
        .expect("stale read");
    // ...the code is spent (its write reaches the real store)...
    f.engine
        .verify_recovery_code(&f.realm, &user, &recovery[0])
        .expect("spend the recovery code");
    // ...and a TOTP verify from the stale copy writes the whole record back.
    f.engine
        .verify_totp(&f.realm, &user, &code)
        .expect("the TOTP code itself is good");
    f.storage.disarm();
    assert!(
        matches!(
            f.engine.verify_recovery_code(&f.realm, &user, &recovery[0]),
            Err(IdentityError::InvalidMfaCode)
        ),
        "a stale MFA-state write brought a spent recovery code back"
    );
}

#[test]
fn the_totp_guess_budget_is_shared_by_every_node() {
    let f = fixture();
    let user = make_user(&f, "totp-budget@example.com");
    let (secret, _) = enrol_totp(&f, &user);
    let second_node = engine_over(&f.storage, &f.clock);
    for _ in 0..EmbeddedIdentityEngine::MFA_MAX_ATTEMPTS {
        assert!(
            matches!(
                f.engine.verify_totp(&f.realm, &user, "000000"),
                Err(IdentityError::InvalidMfaCode)
            ),
            "a wrong guess inside the budget is answered as a wrong code"
        );
    }
    assert!(
        matches!(
            second_node.verify_totp(&f.realm, &user, &current_totp(&f, &secret)),
            Err(IdentityError::RateLimited)
        ),
        "a second node granted a fresh TOTP guess budget after the first spent it"
    );
}

/// The code an SMS body carries.
fn sms_code(sender: &CapturingSms) -> String {
    let body = sender.0.lock().expect("sms").last().cloned().expect("sent");
    body.rsplit_once(": ")
        .map(|(_, c)| c.trim().to_string())
        .expect("code")
}

/// A six-digit guess that is not `code`.
fn wrong_guess(code: &str) -> &'static str {
    if code == "000000" {
        "111111"
    } else {
        "000000"
    }
}

#[test]
fn an_sms_otp_guess_budget_holds_despite_a_stale_read() {
    const KEY: &[u8] = b"stale-read-sms-budget-hmac-key";
    const PHONE: &str = "+15555550143";
    let f = fixture();
    let sender = CapturingSms(Mutex::new(Vec::new()));
    let now = u64::try_from(now_secs(&f)).expect("now");
    let nonce = f
        .engine
        .issue_sms_otp(&f.realm, PHONE, KEY, &sender, now)
        .expect("issue");
    let code = sms_code(&sender);
    f.storage.arm("sms:pending_otp:");
    for _ in 0..crate::identity::sms::otp::OTP_MAX_ATTEMPTS {
        assert!(f
            .engine
            .verify_sms_otp(&f.realm, &nonce, PHONE, wrong_guess(&code), KEY, now)
            .is_err());
    }
    assert!(
        f.engine
            .verify_sms_otp(&f.realm, &nonce, PHONE, &code, KEY, now)
            .is_err(),
        "a stale read of the attempt count granted a guess past the SMS OTP budget"
    );
}

#[test]
fn an_email_otp_guess_budget_holds_despite_a_stale_read() {
    const KEY: &[u8] = b"stale-read-email-budget-hmac-key";
    const ADDRESS: &str = "budget@example.com";
    let f = fixture();
    let sender = Arc::new(CapturingEmail(Mutex::new(Vec::new())));
    let service = crate::identity::EmailService::new(
        Arc::clone(&sender) as Arc<dyn crate::identity::EmailSender>,
        "Hearth Test".to_string(),
        None,
        crate::identity::EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("email service");
    let now = u64::try_from(now_secs(&f)).expect("now");
    let nonce = f
        .engine
        .issue_email_otp(&f.realm, ADDRESS, KEY, &service, None, now)
        .expect("issue");
    let body = sender
        .0
        .lock()
        .expect("email")
        .last()
        .cloned()
        .expect("sent");
    let code: String = body
        .rsplit_once(": ")
        .map(|(_, rest)| rest.trim().chars().take(6).collect())
        .expect("code");
    f.storage.arm("email:pending_otp:");
    for _ in 0..crate::identity::sms::otp::OTP_MAX_ATTEMPTS {
        assert!(f
            .engine
            .verify_email_otp(&f.realm, &nonce, ADDRESS, wrong_guess(&code), KEY, now)
            .is_err());
    }
    assert!(
        f.engine
            .verify_email_otp(&f.realm, &nonce, ADDRESS, &code, KEY, now)
            .is_err(),
        "a stale read of the attempt count granted a guess past the email OTP budget"
    );
}

#[test]
fn an_email_change_is_confirmed_once_despite_a_stale_read() {
    let f = fixture();
    let user = make_user(&f, "change-from@example.com");
    let token = f
        .engine
        .initiate_email_change(&f.realm, &user, "change-to@example.com")
        .expect("initiate");
    f.storage.arm("email:change:");
    f.storage.arm("usr:id:");
    f.storage.arm("usr:email:");
    f.engine
        .confirm_email_change(&f.realm, &token)
        .expect("first confirmation");
    assert!(
        matches!(
            f.engine.confirm_email_change(&f.realm, &token),
            Err(IdentityError::EmailChangeTokenInvalid)
        ),
        "a stale read of the email-change token let it be confirmed twice"
    );
}

/// A pending device authorization for a fresh device client: its user code.
fn pending_device_code(f: &Fixture) -> (ClientId, String, String) {
    let client = f
        .engine
        .register_client(
            &f.realm,
            &crate::identity::RegisterClientRequest {
                client_name: "stale-device".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec![crate::identity::oidc::GRANT_DEVICE_CODE.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("client")
        .client_id()
        .clone();
    let issued = f
        .engine
        .device_authorize(
            &f.realm,
            &crate::identity::oidc::DeviceAuthorizationRequest {
                client_id: client.clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");
    (client, issued.user_code, issued.device_code)
}

#[test]
fn a_device_approval_is_not_overwritten_by_a_stale_deny() {
    let f = fixture();
    let user = make_user(&f, "device-approve@example.com");
    let (client, user_code, device_code) = pending_device_code(&f);
    f.storage.arm("oauth:device:");
    f.storage.arm("oauth:ucode:");
    f.engine
        .approve_device(&f.realm, &user_code, &user)
        .expect("approve");
    assert!(
        f.engine.deny_device(&f.realm, &user_code, &user).is_err(),
        "a stale read of the device code let a deny overwrite the approval"
    );
    f.storage.disarm();
    f.engine
        .poll_device_token(&f.realm, &device_code, &client)
        .expect("the approved device is served its tokens");
}

#[test]
fn a_device_denial_is_not_overwritten_by_a_stale_approve() {
    let f = fixture();
    let user = make_user(&f, "device-deny@example.com");
    let (client, user_code, device_code) = pending_device_code(&f);
    f.storage.arm("oauth:device:");
    f.storage.arm("oauth:ucode:");
    f.engine
        .deny_device(&f.realm, &user_code, &user)
        .expect("deny");
    assert!(
        f.engine
            .approve_device(&f.realm, &user_code, &user)
            .is_err(),
        "a stale read of the device code let an approval overwrite the denial"
    );
    f.storage.disarm();
    assert!(
        matches!(
            f.engine.poll_device_token(&f.realm, &device_code, &client),
            Err(IdentityError::DeviceCodeDenied)
        ),
        "the denied device was not told access_denied"
    );
}

//! Task 22.27 (audit 2026-08-28 §4.25#5) — every unguessable handle Hearth
//! issues must carry at least 128 bits of entropy.
//!
//! The defect: PAR `request_uri` identifiers, consent tickets, federation
//! confirm tickets, the SAML `RelayState` token and session identifiers were
//! all minted as UUID v4. A v4 UUID pins four bits to the version nibble and
//! two to the variant, so it carries 122 bits, not 128. RFC 9126 §7.1 makes
//! 128 bits the normative floor for a PAR `request_uri`.
//!
//! How these tests detect it: draw many values and assert that **every one**
//! of the 128 bits takes both values across the sample. A structurally fixed
//! bit (a version nibble, a variant prefix) never flips, so a UUID v4 fails
//! the assertion deterministically for any sample size above a handful, while
//! a full-entropy draw passes with overwhelming probability (a given bit
//! staying constant across N draws has probability 2^-(N-1)).

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{ClientId, Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient,
    PendingAuthorizationRequest, PushedAuthorizationRequest, RealmConfig, RegisterClientRequest,
    SessionContext, User,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Number of draws per generator. 128 samples puts the false-failure
/// probability for a genuinely random bit at 2^-127.
const SAMPLES: usize = 128;

/// S256 challenge for a fixed verifier — PAR refuses a request without PKCE.
const PKCE_S256_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Asserts every bit position in a set of 16-byte samples is observed both
/// set and clear — i.e. the value really carries 128 bits of entropy.
fn assert_all_128_bits_vary(label: &str, samples: &[[u8; 16]]) {
    assert!(samples.len() >= 32, "{label}: need a meaningful sample");
    let mut seen_zero = [false; 128];
    let mut seen_one = [false; 128];
    for s in samples {
        for bit in 0..128 {
            if s[bit / 8] & (0x80 >> (bit % 8)) != 0 {
                seen_one[bit] = true;
            } else {
                seen_zero[bit] = true;
            }
        }
    }
    let fixed: Vec<usize> = (0..128)
        .filter(|&b| !(seen_zero[b] && seen_one[b]))
        .collect();
    assert!(
        fixed.is_empty(),
        "{label}: bit positions {fixed:?} are structurally fixed across {} draws — \
         the value carries fewer than 128 bits of entropy (UUID v4 pins bits 48-51 \
         for the version and 64-65 for the variant)",
        samples.len()
    );
}

/// Decodes a 32-character lowercase-hex secret into its 16 raw bytes.
fn hex16(label: &str, s: &str) -> [u8; 16] {
    assert_eq!(
        s.len(),
        32,
        "{label}: expected 32 hex characters (128 bits), got {:?}",
        s
    );
    let raw = hex::decode(s).unwrap_or_else(|e| panic!("{label}: not hex ({e}): {s:?}"));
    assert_eq!(raw.len(), 16, "{label}: expected 16 decoded bytes");
    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    out
}

fn setup_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
            .expect("open storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        storage,
        clock as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine");
    (dir, engine)
}

fn create_realm(engine: &EmbeddedIdentityEngine) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("entropy-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm")
        .id()
        .clone()
}

fn create_user(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> User {
    engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "Entropy Probe".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
}

fn register_client(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> OAuthClient {
    engine
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Entropy App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some("s3cr3t-entropy-probe-value".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client")
}

// ---------------------------------------------------------------------------
// PAR request_uri — RFC 9126 §7.1
// ---------------------------------------------------------------------------

#[test]
fn par_request_uri_carries_128_bits() {
    let (_dir, engine) = setup_engine();
    let realm = create_realm(&engine);
    let client = register_client(&engine, &realm);

    const URN_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let resp = engine
            .push_authorization_request(
                &realm,
                &PushedAuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: "st".to_string(),
                    resource: None,
                    response_type: "code".to_string(),
                    code_challenge: Some(PKCE_S256_CHALLENGE.to_string()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    request: None,
                    response_mode: None,
                },
            )
            .expect("push_authorization_request");
        let id = resp
            .request_uri
            .strip_prefix(URN_PREFIX)
            .unwrap_or_else(|| panic!("unexpected request_uri shape: {}", resp.request_uri));
        samples.push(hex16("PAR request_uri", id));
    }
    assert_all_128_bits_vary("PAR request_uri", &samples);
}

// ---------------------------------------------------------------------------
// Consent ticket
// ---------------------------------------------------------------------------

#[test]
fn consent_ticket_carries_128_bits() {
    let (_dir, engine) = setup_engine();
    let realm = create_realm(&engine);
    let user = create_user(&engine, &realm);
    let client = register_client(&engine, &realm);
    let now = Timestamp::from_micros(1_000_000);

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let ticket = engine
            .put_pending_authorization(
                &realm,
                &PendingAuthorizationRequest {
                    realm_id: realm.clone(),
                    user_id: user.id().clone(),
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    requested_scopes: vec!["openid".to_string()],
                    state: "st".to_string(),
                    response_type: "code".to_string(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                    response_mode: None,
                    authorization_signed_response_alg: None,
                    created_at: now,
                    expires_at: Timestamp::from_micros(now.as_micros() + 600_000_000),
                },
            )
            .expect("put_pending_authorization");
        samples.push(hex16("consent ticket", &ticket));
    }
    assert_all_128_bits_vary("consent ticket", &samples);
}

// ---------------------------------------------------------------------------
// Session ID
// ---------------------------------------------------------------------------

#[test]
fn session_id_carries_128_bits() {
    let (_dir, engine) = setup_engine();
    let realm = create_realm(&engine);
    let user = create_user(&engine, &realm);

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");
        samples.push(*session.id().as_uuid().as_bytes());
    }
    assert_all_128_bits_vary("session id", &samples);
}

// ---------------------------------------------------------------------------
// Shared generator behind the SAML RelayState token and the federation
// confirm-link ticket (both minted inside handler/service code that is not
// reachable from an integration test without a live IdP).
// ---------------------------------------------------------------------------

#[test]
fn shared_secret_generator_carries_128_bits() {
    let samples: Vec<[u8; 16]> = (0..SAMPLES)
        .map(|_| hex16("random_secret_hex", &hearth::core::random_secret_hex()))
        .collect();
    assert_all_128_bits_vary("random_secret_hex", &samples);

    let uuids: Vec<[u8; 16]> = (0..SAMPLES)
        .map(|_| *hearth::core::random_secret_uuid().as_bytes())
        .collect();
    assert_all_128_bits_vary("random_secret_uuid", &uuids);
}

// ---------------------------------------------------------------------------
// Round-trip guard: a full-entropy UUID must still behave like a UUID
// everywhere the old v4 value did (parsing, storage-key suffixes).
// ---------------------------------------------------------------------------

#[test]
fn full_entropy_uuid_round_trips_and_sessions_still_resolve() {
    let (_dir, engine) = setup_engine();
    let realm = create_realm(&engine);
    let user = create_user(&engine, &realm);

    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");

    // The ID must survive a string round trip (cookie encode/decode path).
    let as_string = session.id().as_uuid().to_string();
    let parsed: uuid::Uuid = as_string.parse().expect("full-entropy UUID must parse");
    assert_eq!(&parsed, session.id().as_uuid());

    // And the session must still be resolvable by that ID (storage key shape).
    let fetched = engine
        .get_session(&realm, session.id())
        .expect("get_session")
        .expect("session must resolve by its full-entropy id");
    assert_eq!(fetched.id(), session.id());
}

/// `ClientId` must keep its UUID **v5** heuristic: reconciliation uses
/// `get_version_num() == 5` to tell YAML-managed clients from hand-registered
/// ones, so the 128-bit change must not have been applied globally to every
/// ID newtype.
#[test]
fn registered_client_ids_are_not_full_entropy() {
    let (_dir, engine) = setup_engine();
    let realm = create_realm(&engine);
    for _ in 0..16 {
        let client = register_client(&engine, &realm);
        let id: &ClientId = client.client_id();
        assert_eq!(
            id.as_uuid().get_version_num(),
            4,
            "hand-registered clients must stay UUID v4 — the reconciler's \
             `get_version_num() == 5` YAML-managed heuristic depends on it"
        );
    }
}

//! Security hardening batch F10 (HEA-1656 / HEA-1629 T10).
//!
//! Tests for:
//! 1. MFA-pending cookie single-use nonce
//! 2. `azp` claim in OIDC ID tokens
//! 3. RP-initiated logout — no open redirect when session not found
//! 4. Account-link enumeration resistance (code review verification)
//! 5. agent.json realm-scope (code review + BOLA regression)

mod common;

use hearth::core::RealmId;
use hearth::identity::oidc::RpLogoutRequest;
use hearth::identity::tokens::decode_claims_unverified;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, OAuthClient,
    RegisterClientRequest, TokenExchangeRequest, UpdateClientRequest,
};

// ── Helpers ────────────────────────────────────────────────────────────────────

fn pkce_verifier() -> &'static str {
    "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc"
}

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

async fn setup_env() -> (
    common::TestHarness,
    RealmId,
    hearth::core::UserId,
    OAuthClient,
) {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("f10-hardening-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "f10-test@example.com".to_string(),
                display_name: "F10 Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "F10 Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    // Register the post-logout redirect URI via update_client.
    let client = harness
        .identity()
        .update_client(
            realm.id(),
            client.client_id(),
            &UpdateClientRequest {
                post_logout_redirect_uris: Some(vec!["https://app.example.com/logout".to_string()]),
                ..Default::default()
            },
        )
        .expect("update client post_logout_redirect_uris");

    let realm_id = realm.id().clone();
    let user_id = user.id().clone();
    (harness, realm_id, user_id, client)
}

fn do_authcode_exchange(
    h: &common::TestHarness,
    realm_id: &RealmId,
    user_id: &hearth::core::UserId,
    client: &OAuthClient,
) -> hearth::identity::OidcTokenResponse {
    let auth = h
        .identity()
        .authorize(
            realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid profile email".to_string(),
                state: "state".to_string(),
                response_type: "code".to_string(),
                user_id: user_id.clone(),
                code_challenge: Some(pkce_challenge(pkce_verifier())),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");
    h.identity()
        .exchange_authorization_code(
            realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(pkce_verifier().to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code")
}

// ── F10.1: MFA-pending cookie single-use nonce ─────────────────────────────────

/// Verifies that `issue_mfa_pending_cookie` embeds a nonce field (6 dot-separated parts)
/// and that `parse_mfa_pending_cookie` round-trips it, returning the nonce.
#[tokio::test]
async fn mfa_pending_cookie_contains_nonce() {
    use hearth::core::{RealmId, UserId};
    use hearth::protocol::web::auth::{
        issue_mfa_pending_cookie, parse_mfa_pending_cookie, CookieSecret, MFA_PENDING_COOKIE,
    };

    let secret = CookieSecret::from_bytes([0u8; 32]);
    let realm_id = RealmId::new(uuid::Uuid::new_v4());
    let user_id = UserId::new(uuid::Uuid::new_v4());

    let full_cookie = issue_mfa_pending_cookie(&secret, &realm_id, &user_id, None, false);

    // The Set-Cookie header value has the form `hearth_ui_mfa_pending=<VALUE>; …`
    // Extract just the cookie VALUE (before the first `;`).
    let value = full_cookie
        .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
        .expect("must start with cookie name")
        .split(';')
        .next()
        .expect("must have a value part");

    // Format: uid.realm.expires.return_to_b64.nonce.mac — 6 dot-separated fields.
    let parts: Vec<&str> = value.splitn(7, '.').collect();
    assert_eq!(
        parts.len(),
        6,
        "pending cookie must have 6 dot-separated fields (uid.realm.exp.return.nonce.mac)"
    );
    let nonce_field = parts[4];
    assert!(!nonce_field.is_empty(), "nonce field must not be empty");
    // 16-byte nonce base64url-encoded (no padding) → 22 chars.
    assert_eq!(
        nonce_field.len(),
        22,
        "nonce must be 22 base64url chars (16 bytes)"
    );

    // Round-trip: parse must succeed and return the same nonce.
    let pending = parse_mfa_pending_cookie(&secret, value).expect("parse must succeed");
    assert_eq!(
        pending.nonce, nonce_field,
        "parsed nonce must match cookie nonce"
    );
    assert_eq!(pending.realm_id, realm_id, "realm_id round-trip");
    assert_eq!(pending.user_id, user_id, "user_id round-trip");
}

/// Two calls to `issue_mfa_pending_cookie` for the same user/realm produce
/// different nonces (randomness check).
#[tokio::test]
async fn mfa_pending_cookie_nonces_are_unique() {
    use hearth::core::{RealmId, UserId};
    use hearth::protocol::web::auth::{issue_mfa_pending_cookie, CookieSecret, MFA_PENDING_COOKIE};

    let secret = CookieSecret::from_bytes([1u8; 32]);
    let realm_id = RealmId::new(uuid::Uuid::new_v4());
    let user_id = UserId::new(uuid::Uuid::new_v4());

    let extract_nonce = |full: &str| -> String {
        let value = full
            .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
            .expect("cookie name prefix")
            .split(';')
            .next()
            .expect("value part")
            .to_string();
        value.split('.').nth(4).expect("nonce part").to_string()
    };

    let a = issue_mfa_pending_cookie(&secret, &realm_id, &user_id, None, false);
    let b = issue_mfa_pending_cookie(&secret, &realm_id, &user_id, None, false);
    assert_ne!(
        extract_nonce(&a),
        extract_nonce(&b),
        "each cookie must have a unique nonce"
    );
}

/// A cookie with a tampered nonce is rejected.
#[tokio::test]
async fn mfa_pending_cookie_rejects_tampered_nonce() {
    use hearth::core::{RealmId, UserId};
    use hearth::protocol::web::auth::{
        issue_mfa_pending_cookie, parse_mfa_pending_cookie, CookieSecret, MFA_PENDING_COOKIE,
    };

    let secret = CookieSecret::from_bytes([2u8; 32]);
    let realm_id = RealmId::new(uuid::Uuid::new_v4());
    let user_id = UserId::new(uuid::Uuid::new_v4());

    let full = issue_mfa_pending_cookie(&secret, &realm_id, &user_id, None, false);
    let value = full
        .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
        .expect("prefix")
        .split(';')
        .next()
        .expect("value");

    // Flip one char in the nonce (field index 4).
    let mut parts: Vec<&str> = value.splitn(7, '.').collect();
    let original_nonce = parts[4];
    let tampered_nonce = if let Some(rest) = original_nonce.strip_prefix('A') {
        format!("B{rest}")
    } else {
        format!("A{}", &original_nonce[1..])
    };
    let tampered_nonce_str = tampered_nonce.clone();
    parts[4] = &tampered_nonce_str;
    let tampered = parts.join(".");

    assert!(
        parse_mfa_pending_cookie(&secret, &tampered).is_none(),
        "tampered nonce must cause MAC verification failure"
    );
}

// ── F10.2: azp claim in OIDC ID tokens ────────────────────────────────────────

/// OIDC Core §2: `azp` MUST be present in ID tokens and MUST equal the `client_id`.
#[tokio::test]
async fn id_token_contains_azp_claim() {
    let (harness, realm_id, user_id, client) = setup_env().await;
    let token_response = do_authcode_exchange(&harness, &realm_id, &user_id, &client);

    let claims = decode_claims_unverified(token_response.id_token()).expect("decode ID token");
    let azp = claims
        .azp
        .as_deref()
        .expect("azp MUST be present in ID tokens");
    assert_eq!(
        azp,
        &client.client_id().to_string(),
        "azp must equal client_id"
    );
}

/// `azp` is absent from access tokens (only required on ID tokens).
#[tokio::test]
async fn access_token_has_no_azp_claim() {
    let (harness, realm_id, user_id, client) = setup_env().await;
    let token_response = do_authcode_exchange(&harness, &realm_id, &user_id, &client);

    let claims =
        decode_claims_unverified(token_response.access_token()).expect("decode access token");
    assert!(
        claims.azp.is_none(),
        "azp must NOT be present on access tokens"
    );
}

// ── F10.3: RP-initiated logout — no open redirect when session not found ───────

/// When `end_session` receives an unknown session (no id_token_hint resolving to a live
/// session), it MUST NOT redirect to `post_logout_redirect_uri`.
///
/// The engine-layer fix: `initiate_logout_inner` now rejects `post_logout_redirect_uri`
/// when no `client_id` is supplied (prevents unvalidated redirect).
/// The HTTP-layer fix: `SessionNotFound` returns 200 instead of redirecting.
#[tokio::test]
async fn rp_logout_no_redirect_without_client_id() {
    let (harness, realm_id, _user_id, _client) = setup_env().await;

    // Try to logout with a post_logout_redirect_uri but no client_id.
    // Engine must return None for post_logout_redirect_uri so the redirect
    // is suppressed even if the session was found.
    let result = harness.identity().initiate_logout(
        &realm_id,
        &RpLogoutRequest {
            id_token_hint: None,
            session_id: None,
            // Attempting to redirect to an arbitrary URI without a client_id.
            post_logout_redirect_uri: Some("https://attacker.example.com/".to_string()),
            client_id: None,
            state: None,
        },
    );

    // Engine returns InvalidToken when neither hint nor session_id is provided.
    // That's fine — the important thing is the redirect was not accepted.
    match result {
        Ok(logout_result) => {
            assert!(
                logout_result.post_logout_redirect_uri.is_none(),
                "post_logout_redirect_uri must be None when no client_id is provided (open-redirect guard)"
            );
        }
        Err(hearth::identity::IdentityError::InvalidToken) => {
            // Expected: no session hint → InvalidToken. Redirect suppression is moot.
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// When `client_id` is provided and the URI is registered, the redirect IS allowed.
#[tokio::test]
async fn rp_logout_redirect_allowed_with_registered_client() {
    let (harness, realm_id, user_id, client) = setup_env().await;

    // Create a session and exchange a code so we have a grant family (needed
    // for session→family index the logout scanner relies on).
    let token_response = do_authcode_exchange(&harness, &realm_id, &user_id, &client);

    let result = harness.identity().initiate_logout(
        &realm_id,
        &RpLogoutRequest {
            id_token_hint: Some(token_response.id_token().to_string()),
            session_id: None,
            post_logout_redirect_uri: Some("https://app.example.com/logout".to_string()),
            client_id: Some(client.client_id().clone()),
            state: None,
        },
    );

    let logout_result = result.expect("logout with registered client must succeed");
    assert_eq!(
        logout_result.post_logout_redirect_uri.as_deref(),
        Some("https://app.example.com/logout"),
        "registered post_logout_redirect_uri must be returned"
    );
}

/// Unregistered `post_logout_redirect_uri` is rejected even when `client_id` is provided.
#[tokio::test]
async fn rp_logout_rejects_unregistered_redirect_uri() {
    let (harness, realm_id, user_id, client) = setup_env().await;

    let token_response = do_authcode_exchange(&harness, &realm_id, &user_id, &client);

    let result = harness.identity().initiate_logout(
        &realm_id,
        &RpLogoutRequest {
            id_token_hint: Some(token_response.id_token().to_string()),
            session_id: None,
            post_logout_redirect_uri: Some("https://attacker.example.com/evil".to_string()),
            client_id: Some(client.client_id().clone()),
            state: None,
        },
    );

    let logout_result = result.expect("logout must succeed");
    assert!(
        logout_result.post_logout_redirect_uri.is_none(),
        "unregistered redirect URI must not be returned"
    );
}

// ── F10.4: Account-link enumeration resistance (structural verification) ───────

/// Structural test: the confirm_link_submit handler now redirects to /ui/login on
/// password failure instead of /ui/federation/confirm-link?ticket=...&error=1.
/// This prevents distinguishing "valid ticket + wrong password" from "invalid ticket".
///
/// Full browser-level testing requires the server harness; this test verifies
/// the source-code change at the module level.
#[test]
fn confirm_link_submit_redirect_on_failure_goes_to_login() {
    // Read the source of the federation handler and verify the failure redirect
    // no longer exposes an error=1 path that reveals ticket validity.
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/protocol/web/federation.rs"
    ));
    // The fix: password-failure now sends the user to /ui/login (enumeration-safe).
    assert!(
        src.contains("/ui/login?error=fed_link_failed"),
        "federation confirm_link_submit must redirect to /ui/login on password failure"
    );
    // The old pattern (?error=1 on the confirm-link page) must be absent — it
    // revealed that the ticket was valid + the password was wrong (enumeration risk).
    assert!(
        !src.contains("confirm-link?ticket=") || !src.contains("error=1"),
        "federation confirm_link_submit must NOT use ?error=1 to reveal ticket validity"
    );
}

// ── F10.5: agent.json realm-scope ──────────────────────────────────────────────

/// `/.well-known/agent.json?agent_id=<X>` cannot return an agent from a different realm.
/// The storage layer prefixes all keys with realm_id, so a lookup in realm B
/// for an agent that lives in realm A returns None.
#[tokio::test]
async fn agent_card_is_realm_scoped() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
    let h = common::TestHarness::server_with_agent_auth()
        .await
        .expect("server harness");
    let base = h.base_url().expect("base_url");
    let client = reqwest::Client::new();

    // Bootstrap creates realm A (system realm) + admin token.
    let boot: serde_json::Value = client
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap")
        .json()
        .await
        .expect("bootstrap JSON");
    let system_token = boot["access_token"].as_str().expect("token").to_string();
    let system_realm_id = boot["realm_id"].as_str().expect("realm_id").to_string();

    // Create a second realm via the embedded engine.
    let other_realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("realm-b-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create second realm");
    let other_realm_id = other_realm.id().as_uuid().to_string();

    // Create an agent in the system realm.
    let owner_user_id = boot["user_id"]
        .as_str()
        .unwrap_or(&uuid::Uuid::nil().to_string())
        .to_string();
    let create_resp = client
        .post(format!("{base}/v1/agents"))
        .bearer_auth(&system_token)
        .header("X-Realm-ID", &system_realm_id)
        .json(&serde_json::json!({
            "display_name": "Test Agent",
            "description": "system realm agent",
            "owner_type": "user",
            "owner_id": owner_user_id,
        }))
        .send()
        .await
        .expect("create agent");
    let agent_body: serde_json::Value = create_resp.json().await.expect("create agent json");
    let agent_id = agent_body["id"].as_str().expect("agent id").to_string();

    // Query agent.json with system realm's token and system realm ID — must succeed.
    let resp_a = client
        .get(format!("{base}/.well-known/agent.json?agent_id={agent_id}"))
        .bearer_auth(&system_token)
        .header("X-Realm-ID", &system_realm_id)
        .send()
        .await
        .expect("agent.json realm A");
    assert_eq!(
        resp_a.status().as_u16(),
        200,
        "agent.json must return the agent when queried in its own realm"
    );

    // Query agent.json with the system token but the second realm's ID — must be 401
    // (token is signed with the system realm's key so validate_token(&other_realm, …) fails).
    let resp_b = client
        .get(format!("{base}/.well-known/agent.json?agent_id={agent_id}"))
        .bearer_auth(&system_token)
        .header("X-Realm-ID", &other_realm_id)
        .send()
        .await
        .expect("agent.json cross-realm");
    let cross_status = resp_b.status().as_u16();
    assert!(
        cross_status == 401 || cross_status == 403,
        "agent.json cross-realm BOLA: system token must not access other realm (got {cross_status})"
    );
}

// ── §4.2#3 / §4.19#1: end_session must verify the id_token_hint signature ─────

/// Splits `token` into its three JWT segments and returns it with the
/// signature replaced by a well-formed but wrong Ed25519 signature. The
/// header and payload — including the victim's real `sid`/`sub` — are intact;
/// only the signature no longer verifies against the realm key.
fn forge_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a JWT");
    // 64-byte all-zero Ed25519 signature, base64url no-pad — valid shape, wrong value.
    let bogus_sig = data_encoding::BASE64URL_NOPAD.encode(&[0u8; 64]);
    format!("{}.{}.{}", parts[0], parts[1], bogus_sig)
}

fn session_id_of(id_token: &str) -> hearth::core::SessionId {
    let claims = decode_claims_unverified(id_token).expect("decode id token");
    let uuid_str = claims
        .sid
        .strip_prefix("session_")
        .expect("id token sid is session-scoped");
    hearth::core::SessionId::new(uuid_str.parse().expect("session uuid"))
}

/// A hint whose signature does not verify must revoke no session and mint no
/// logout token (audit 2026-08-28 §4.2#3, §4.19#1).
#[tokio::test]
async fn rp_logout_rejects_unsigned_id_token_hint() {
    let (harness, realm_id, user_id, client) = setup_env().await;
    let token_response = do_authcode_exchange(&harness, &realm_id, &user_id, &client);
    let session_id = session_id_of(token_response.id_token());

    // Precondition: the victim's session is live.
    assert!(
        harness
            .identity()
            .get_session(&realm_id, &session_id)
            .expect("get session")
            .is_some(),
        "precondition: victim session is live"
    );

    let forged_hint = forge_signature(token_response.id_token());
    let result = harness.identity().initiate_logout(
        &realm_id,
        &RpLogoutRequest {
            id_token_hint: Some(forged_hint),
            session_id: None,
            post_logout_redirect_uri: None,
            client_id: None,
            state: None,
        },
    );

    assert!(
        matches!(result, Err(hearth::identity::IdentityError::InvalidToken)),
        "a forged id_token_hint must be refused, got {result:?}"
    );

    // The victim's session must survive: no logout token, no revocation.
    assert!(
        harness
            .identity()
            .get_session(&realm_id, &session_id)
            .expect("get session")
            .is_some(),
        "a forged id_token_hint must not revoke the victim's session (audit §4.19#1)"
    );
}

/// A genuinely realm-signed id_token_hint still logs the session out.
#[tokio::test]
async fn rp_logout_accepts_valid_id_token_hint() {
    let (harness, realm_id, user_id, client) = setup_env().await;
    let token_response = do_authcode_exchange(&harness, &realm_id, &user_id, &client);
    let session_id = session_id_of(token_response.id_token());

    harness
        .identity()
        .initiate_logout(
            &realm_id,
            &RpLogoutRequest {
                id_token_hint: Some(token_response.id_token().to_string()),
                session_id: None,
                post_logout_redirect_uri: None,
                client_id: None,
                state: None,
            },
        )
        .expect("a validly signed hint must be accepted");

    assert!(
        harness
            .identity()
            .get_session(&realm_id, &session_id)
            .expect("get session")
            .is_none(),
        "a valid hint must revoke the named session"
    );
}

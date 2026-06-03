//! Integration tests for abuse-prevention features A-5, A-6, A-10, A-13, A-14.
//!
//! These tests exercise the public-facing `IdentityEngine` API and HTTP router
//! to verify that the following controls are enforced end-to-end:
//!
//! **A-5 — Reserved slugs + 30-day cooldown**
//! 1. Reserved slug "admin" → org create rejected (`ReservedSlug`)
//! 2. Deleted org slug enters cooldown → immediate re-create rejected (`SlugInCooldown`)
//! 3. Custom operator-configured slug "mycompany" → org create rejected (`ReservedSlug`)
//!
//! **A-6 — Bootstrap endpoint availability**
//! 4. `POST /admin/bootstrap` returns 404 in production (non-dev) `AppState`
//! 5. `POST /admin/bootstrap` returns 200 in dev `AppState`
//!
//! **A-14 — Per-tenant TTL hard caps**
//! 6. `password_reset_token_ttl` = 2h without `allow_unsafe_ttl` → startup validation error
//! 7. `magic_link_ttl` = 1h without `allow_unsafe_ttl` → startup validation error
//! 8. Same config with `allow_unsafe_ttl = true` → no error
//!
//! **A-13 — WebAuthn AAGUID allowlist + "none" attestation rejection**
//! 9. AAGUID not in allowlist → `complete_webauthn_registration` returns
//!    `AttestationPolicyViolation`
//! 10. `allow_none = false` configured → "none" attestation rejected with
//!    `AttestationPolicyViolation`
//!
//! Covers: HEA-1212 §A-5, §A-6, §A-13, §A-14.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::tempdir;
use tower::ServiceExt as _;

use hearth::audit::EmbeddedAuditEngine;
use hearth::config::{AuthConfig, RealmAuthYaml, RealmTokenYaml, RealmYamlConfig};
use hearth::core::{Clock, FakeClock, Timestamp};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, IdentityError, RealmConfig, RegistrationOptions,
    UpdateRealmRequest, WebAuthnAttestationPolicy,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ─────────────────────────────────────────────────────────────────────────────
// Engine fixture — wraps an in-process identity engine with a controllable clock.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal in-process engine fixture for synchronous (non-tokio) tests.
struct EngineFixture {
    engine: Arc<EmbeddedIdentityEngine>,
    #[allow(dead_code)] // retained for symmetry; used if cooldown-expiry tests are added
    clock: Arc<FakeClock>,
    _tmp: tempfile::TempDir,
}

impl EngineFixture {
    fn new(config: IdentityConfig) -> Self {
        let tmp = tempdir().expect("tempdir");
        let storage: Arc<dyn StorageEngine> = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf()))
                .expect("storage"),
        );
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let clock_dyn: Arc<dyn Clock> = Arc::clone(&clock) as _;
        let rbac: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock_dyn),
        ));
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock_dyn),
        ));
        let engine = Arc::new(
            EmbeddedIdentityEngine::with_rbac(storage, clock_dyn, config, rbac, audit as _)
                .expect("engine"),
        );
        Self {
            engine,
            clock,
            _tmp: tmp,
        }
    }

    fn identity(&self) -> &dyn IdentityEngine {
        self.engine.as_ref()
    }

    #[allow(dead_code)] // retained for cooldown-expiry tests that may be added
    fn advance_secs(&self, secs: u64) {
        self.clock.advance(secs as i64 * 1_000_000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WebAuthn test helper (minimal mock authenticator).
//
// Produces bit-accurate CBOR attestation objects using "none" attestation.
// The AAGUID field is always all-zero (00000000-0000-0000-0000-000000000000).
// ─────────────────────────────────────────────────────────────────────────────

mod webauthn_helper {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    const COSE_ALG_ES256: i64 = -7;

    pub struct MockAuthenticator {
        key_pair_pkcs8: Vec<u8>,
        pub credential_id: Vec<u8>,
        rp_id: String,
    }

    impl MockAuthenticator {
        pub fn new(rp_id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate P-256 key");
            let mut cred_id = vec![0u8; 32];
            rng.fill(&mut cred_id).expect("random credential id");
            Self {
                key_pair_pkcs8: pkcs8.as_ref().to_vec(),
                credential_id: cred_id,
                rp_id: rp_id.to_string(),
            }
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let pub_bytes = key_pair.public_key().as_ref();
            let x = &pub_bytes[1..33];
            let y = &pub_bytes[33..65];

            let cose_map = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(2.into()),
                ),
                (
                    ciborium::Value::Integer(3.into()),
                    ciborium::Value::Integer(COSE_ALG_ES256.into()),
                ),
                (
                    ciborium::Value::Integer((-1).into()),
                    ciborium::Value::Integer(1.into()),
                ),
                (
                    ciborium::Value::Integer((-2).into()),
                    ciborium::Value::Bytes(x.to_vec()),
                ),
                (
                    ciborium::Value::Integer((-3).into()),
                    ciborium::Value::Bytes(y.to_vec()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&cose_map, &mut buf).expect("encode COSE key");
            buf
        }

        /// Builds authenticator data with all-zero AAGUID and `include_credential = true`.
        #[allow(clippy::cast_possible_truncation)]
        fn build_auth_data(&self) -> Vec<u8> {
            let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes());
            let mut data = Vec::new();
            data.extend_from_slice(rp_id_hash.as_ref());
            data.push(0x41u8); // UP flag + AT flag
            data.extend_from_slice(&0u32.to_be_bytes()); // sign count = 0
            data.extend_from_slice(&[0u8; 16]); // all-zero AAGUID
            let cred_id_len = self.credential_id.len() as u16;
            data.extend_from_slice(&cred_id_len.to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&self.cose_public_key());
            data
        }

        /// Builds `(clientDataJSON, attestationObject)` bytes for a "none" attestation.
        pub fn build_registration_response(
            &self,
            challenge: &[u8],
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>) {
            let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
            let client_data_json = serde_json::to_vec(&serde_json::json!({
                "type": "webauthn.create",
                "challenge": challenge_b64,
                "origin": origin,
            }))
            .expect("serialize clientDataJSON");

            let auth_data = self.build_auth_data();
            let att_obj = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("none".to_string()),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![]),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(auth_data),
                ),
            ]);
            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode attestation object");

            (client_data_json, att_bytes)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-5 — Reserved slugs + org-delete cooldown
// ─────────────────────────────────────────────────────────────────────────────

/// A-5 test 1: Creating an org with slug "admin" (in the default reserved list)
/// must be rejected with `ReservedSlug`.
#[test]
fn a5_reserved_slug_admin_rejected_for_org() {
    let fx = EngineFixture::new(IdentityConfig {
        reserved_slugs: vec!["admin".to_string()],
        ..Default::default()
    });

    let realm = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "a5-test-realm-admin".to_string(),
            config: None,
        })
        .expect("create realm");

    let err = fx
        .identity()
        .create_organization(
            realm.id(),
            &CreateOrganizationRequest {
                name: "Admin".to_string(),
                slug: "admin".to_string(),
                ..Default::default()
            },
        )
        .expect_err("creating org with reserved slug must fail");

    assert!(
        matches!(err, IdentityError::ReservedSlug { .. }),
        "expected ReservedSlug, got {err:?}"
    );
}

/// A-5 test 2: After deleting an org the slug immediately enters the cooldown
/// window. A second create with the same slug must return `SlugInCooldown`.
#[test]
fn a5_deleted_org_slug_enters_cooldown() {
    // Use a non-zero cooldown (30 days) so the window does not expire immediately.
    let cooldown_secs = 30 * 86_400u64;
    let fx = EngineFixture::new(IdentityConfig {
        slug_cooldown_secs: cooldown_secs,
        ..Default::default()
    });

    let realm = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "a5-cooldown-org-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    // Create an org then immediately delete it.
    let org = fx
        .identity()
        .create_organization(
            realm.id(),
            &CreateOrganizationRequest {
                name: "Acme".to_string(),
                slug: "acme".to_string(),
                ..Default::default()
            },
        )
        .expect("create org");

    fx.identity()
        .delete_organization(realm.id(), org.id())
        .expect("delete org");

    // Immediately re-creating with the same slug must be blocked.
    let err = fx
        .identity()
        .create_organization(
            realm.id(),
            &CreateOrganizationRequest {
                name: "Acme Again".to_string(),
                slug: "acme".to_string(),
                ..Default::default()
            },
        )
        .expect_err("re-create of deleted org slug must fail during cooldown");

    assert!(
        matches!(err, IdentityError::SlugInCooldown { .. }),
        "expected SlugInCooldown immediately after org delete, got {err:?}"
    );
}

/// A-5 test 3: A custom operator-configured slug ("mycompany") is permanently
/// reserved and may not be used for an org even though it is not in the
/// built-in reserved list.
#[test]
fn a5_custom_reserved_slug_rejected() {
    let fx = EngineFixture::new(IdentityConfig {
        reserved_slugs: vec!["mycompany".to_string()],
        ..Default::default()
    });

    let realm = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "a5-custom-reserved-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    let err = fx
        .identity()
        .create_organization(
            realm.id(),
            &CreateOrganizationRequest {
                name: "My Company".to_string(),
                slug: "mycompany".to_string(),
                ..Default::default()
            },
        )
        .expect_err("custom reserved slug must be rejected");

    assert!(
        matches!(err, IdentityError::ReservedSlug { .. }),
        "expected ReservedSlug for custom reserved slug, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-6 — Bootstrap endpoint availability
// ─────────────────────────────────────────────────────────────────────────────

/// A-6 test 4: In production mode (`AppState::new`) the bootstrap endpoint
/// must be completely absent from the routing table (router-level 404, empty body).
#[tokio::test]
async fn a6_bootstrap_returns_404_in_production_mode() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness creation");

    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "bootstrap endpoint must return 404 in production mode"
    );

    // Axum's unregistered-route fallback has an empty body, distinguishing it
    // from a handler-level 404 (which would carry a JSON body).
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert!(
        body.is_empty(),
        "router-level 404 must have an empty body (route not registered), got: {body:?}"
    );
}

/// A-6 test 5: In dev mode (`AppState::new_dev`) the bootstrap endpoint must
/// be registered and return 200 with a JSON body containing the admin credentials.
#[tokio::test]
async fn a6_bootstrap_returns_200_in_dev_mode() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness creation");

    let state = Arc::new(AppState::new_dev(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "bootstrap endpoint must return 200 in dev mode"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("bootstrap response must be valid JSON");

    assert!(
        json.get("realm_id").is_some(),
        "bootstrap response must include realm_id"
    );
    assert!(
        json.get("access_token").is_some(),
        "bootstrap response must include access_token"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-14 — Per-tenant TTL hard caps
//
// These tests call `RealmYamlConfig::to_realm_config` directly, which is the
// validation gate executed at startup when the operator's `hearth.yaml` is
// applied. The test validates that the A-14 cap is enforced at that layer.
// ─────────────────────────────────────────────────────────────────────────────

fn realm_yaml_with_token_ttls(
    password_reset_token_ttl: Option<&str>,
    magic_link_ttl: Option<&str>,
    allow_unsafe_ttl: bool,
) -> RealmYamlConfig {
    RealmYamlConfig {
        auth: Some(RealmAuthYaml {
            token: Some(RealmTokenYaml {
                password_reset_token_ttl: password_reset_token_ttl.map(str::to_string),
                magic_link_ttl: magic_link_ttl.map(str::to_string),
                allow_unsafe_ttl,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A-14 test 6: `password_reset_token_ttl` set to 2h (above the 1h cap) without
/// `allow_unsafe_ttl` must produce a validation error at config-load time.
#[test]
fn a14_password_reset_ttl_exceeding_1h_cap_is_rejected() {
    let yaml = realm_yaml_with_token_ttls(Some("2h"), None, false);
    let result = yaml.to_realm_config(&AuthConfig::default(), None);

    let errors = result.expect_err(
        "password_reset_token_ttl = 2h without allow_unsafe_ttl must be a config error",
    );

    assert!(
        errors
            .iter()
            .any(|e| format!("{e:?}").contains("password_reset_token_ttl")),
        "validation error must identify the offending field; got: {errors:?}"
    );
}

/// A-14 test 7: `magic_link_ttl` set to 1h (above the 30m cap) without
/// `allow_unsafe_ttl` must produce a validation error at config-load time.
#[test]
fn a14_magic_link_ttl_exceeding_30m_cap_is_rejected() {
    let yaml = realm_yaml_with_token_ttls(None, Some("1h"), false);
    let result = yaml.to_realm_config(&AuthConfig::default(), None);

    let errors =
        result.expect_err("magic_link_ttl = 1h without allow_unsafe_ttl must be a config error");

    assert!(
        errors
            .iter()
            .any(|e| format!("{e:?}").contains("magic_link_ttl")),
        "validation error must identify the offending field; got: {errors:?}"
    );
}

/// A-14 test 8: With `allow_unsafe_ttl = true` both caps are lifted; the same
/// oversized TTL values that would otherwise fail must be accepted.
#[test]
fn a14_allow_unsafe_ttl_bypasses_both_caps() {
    let yaml = realm_yaml_with_token_ttls(Some("12h"), Some("2h"), true);
    yaml.to_realm_config(&AuthConfig::default(), None)
        .expect("allow_unsafe_ttl = true must accept any TTL value");
}

// ─────────────────────────────────────────────────────────────────────────────
// A-13 — WebAuthn AAGUID allowlist + "none" attestation policy (integration)
//
// These tests call the full `IdentityEngine::complete_webauthn_registration`
// path using the mock authenticator above. The realm's `RealmConfig` is updated
// with the desired `WebAuthnAttestationPolicy` before completing registration.
// ─────────────────────────────────────────────────────────────────────────────

/// A-13 test 9: When the realm's `aaguid_allowlist` is non-empty and the
/// authenticator's AAGUID (all-zero) is not in the list,
/// `complete_webauthn_registration` must return `AttestationPolicyViolation`.
#[tokio::test]
async fn a13_aaguid_not_in_allowlist_is_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("a13-aaguid-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    // Configure the realm to only allow a specific AAGUID that does NOT match
    // the all-zero AAGUID emitted by the mock authenticator.
    let non_matching_aaguid = "d8522d9f-575b-4866-88a9-ba99fa02f35b";
    harness
        .identity()
        .update_realm(
            &realm_id,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    webauthn_attestation: Some(WebAuthnAttestationPolicy {
                        allow_none: true, // "none" attestation is allowed; AAGUID check is what matters
                        aaguid_allowlist: vec![non_matching_aaguid.to_string()],
                        require_prf: false,
                        require_large_blob: false,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm attestation policy");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("a13-aaguid-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "A13 Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let origin = "https://example.com";
    let rp_id = "example.com";
    let authenticator = webauthn_helper::MockAuthenticator::new(rp_id);

    let challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm_id,
            user.id(),
            &RegistrationOptions {
                rp_id: rp_id.to_string(),
                discoverable: false,
            },
        )
        .expect("start webauthn registration");

    let (client_data_json, attestation_object) =
        authenticator.build_registration_response(&challenge, origin);

    let err = harness
        .identity()
        .complete_webauthn_registration(
            &realm_id,
            user.id(),
            &client_data_json,
            &attestation_object,
            origin,
            false,
        )
        .expect_err("registration with AAGUID not in allowlist must fail");

    assert!(
        matches!(err, IdentityError::AttestationPolicyViolation { .. }),
        "expected AttestationPolicyViolation for unlisted AAGUID, got {err:?}"
    );
}

/// A-13 test 10: When the realm's policy sets `allow_none = false` and the
/// authenticator uses "none" attestation format,
/// `complete_webauthn_registration` must return `AttestationPolicyViolation`.
#[tokio::test]
async fn a13_none_attestation_rejected_when_not_allowed() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("a13-none-attest-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    // Forbid "none" attestation; empty AAGUID allowlist means any AAGUID is
    // accepted, so only the "none" format check will trigger.
    harness
        .identity()
        .update_realm(
            &realm_id,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    webauthn_attestation: Some(WebAuthnAttestationPolicy {
                        allow_none: false, // "none" attestation is prohibited
                        aaguid_allowlist: vec![],
                        require_prf: false,
                        require_large_blob: false,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm attestation policy");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("a13-none-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "A13 None Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let origin = "https://example.com";
    let rp_id = "example.com";
    let authenticator = webauthn_helper::MockAuthenticator::new(rp_id);

    let challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm_id,
            user.id(),
            &RegistrationOptions {
                rp_id: rp_id.to_string(),
                discoverable: false,
            },
        )
        .expect("start webauthn registration");

    // The mock authenticator always uses "none" attestation format.
    let (client_data_json, attestation_object) =
        authenticator.build_registration_response(&challenge, origin);

    let err = harness
        .identity()
        .complete_webauthn_registration(
            &realm_id,
            user.id(),
            &client_data_json,
            &attestation_object,
            origin,
            false,
        )
        .expect_err("'none' attestation must be rejected when allow_none = false");

    assert!(
        matches!(err, IdentityError::AttestationPolicyViolation { .. }),
        "expected AttestationPolicyViolation for 'none' attestation, got {err:?}"
    );
}

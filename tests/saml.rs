//! Integration tests for SAML 2.0 SP + IdP.
//!
//! Exercises the full SP-initiated SSO flow and the IdP-side response
//! issuing path using the embedded engine.

mod common;

use std::collections::BTreeMap;

use common::TestHarness;
use hearth::core::{IdpId, Timestamp};
use hearth::identity::federation::saml::{
    build_post_form_html, build_response_xml, sign_element, verify_signed_element, ResponseBuilder,
    SamlIdpConfig, SamlNameIdFormat, SamlServiceProvider, SamlSpOutcome, SamlSpService,
};
use hearth::identity::tokens::RsaSigningKey;
use hearth::identity::CreateRealmRequest;

fn cert_der_to_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let b64 = B64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is valid utf8"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[tokio::test]
async fn sp_happy_path_accepts_well_formed_assertion() {
    let h = TestHarness::embedded().await.expect("harness");

    // Set up: create a realm to host the SP side.
    let _realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "acme".into(),
            config: None,
        })
        .expect("create realm");

    // Simulate an external IdP by generating its own RSA keypair.
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cert_pem = cert_der_to_pem(idp_key.cert_der());

    // Build the SP-side IdP config.
    let idp_id = IdpId::generate();
    let sp_entity_id = "https://hearth.example/ui/realms/acme";
    let acs_url = "https://hearth.example/ui/realms/acme/federation/saml/acs";
    let idp_cfg = SamlIdpConfig {
        idp_id: idp_id.clone(),
        name: "test-idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![idp_cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: false,
        attribute_map: {
            let mut m = BTreeMap::new();
            m.insert("email".into(), "NameID".into());
            m
        },
    };

    // IdP builds + signs a Response.
    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let response_id = "_r1";
    let xml = build_response_xml(&ResponseBuilder {
        response_id,
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: acs_url,
        issuer: "https://idp.example",
        audience: sp_entity_id,
        assertion_id: "_a1",
        subject_name_id: "alice@example.com",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let signed = sign_element(xml.as_bytes(), response_id, &idp_key).expect("sign");

    // SP consumes.
    let outcome =
        SamlSpService::complete(&idp_cfg, sp_entity_id, acs_url, Some("_req1"), now, &signed);
    match outcome {
        SamlSpOutcome::Accepted { identity, .. } => {
            assert_eq!(identity.email, "alice@example.com");
        }
        SamlSpOutcome::Rejected { error } => panic!("expected accept, got {error:?}"),
    }
}

#[tokio::test]
async fn sp_rejects_tampered_assertion() {
    let _h = TestHarness::embedded().await.expect("harness");
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let cert_pem = cert_der_to_pem(idp_key.cert_der());

    let idp_cfg = SamlIdpConfig {
        idp_id: IdpId::generate(),
        name: "idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: false,
        attribute_map: BTreeMap::new(),
    };

    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_r",
        in_response_to: Some("_req"),
        issue_instant: now,
        destination: "https://sp/acs",
        issuer: "https://idp.example",
        audience: "https://sp",
        assertion_id: "_a",
        subject_name_id: "a@example.com",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "s",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let mut signed = sign_element(xml.as_bytes(), "_r", &idp_key).expect("sign");

    // Tamper: replace the email character.
    let pos = signed
        .windows(1)
        .position(|w| w == b"a")
        .expect("byte found");
    signed[pos] = b'X';

    let outcome = SamlSpService::complete(
        &idp_cfg,
        "https://sp",
        "https://sp/acs",
        Some("_req"),
        now,
        &signed,
    );
    assert!(matches!(outcome, SamlSpOutcome::Rejected { .. }));
}

#[tokio::test]
async fn sp_rejects_audience_mismatch() {
    let _h = TestHarness::embedded().await.expect("harness");
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let cert_pem = cert_der_to_pem(idp_key.cert_der());

    let idp_cfg = SamlIdpConfig {
        idp_id: IdpId::generate(),
        name: "idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: false,
        attribute_map: BTreeMap::new(),
    };

    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_r",
        in_response_to: Some("_req"),
        issue_instant: now,
        destination: "https://sp/acs",
        issuer: "https://idp.example",
        audience: "https://wrong-sp",
        assertion_id: "_a",
        subject_name_id: "a@example.com",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "s",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let signed = sign_element(xml.as_bytes(), "_r", &idp_key).expect("sign");

    let outcome = SamlSpService::complete(
        &idp_cfg,
        "https://sp",
        "https://sp/acs",
        Some("_req"),
        now,
        &signed,
    );
    match outcome {
        SamlSpOutcome::Rejected { error } => {
            assert!(matches!(
                error,
                hearth::identity::IdentityError::SamlAudienceMismatch
            ));
        }
        _ => panic!("expected rejection"),
    }
}

#[tokio::test]
async fn engine_stores_and_retrieves_saml_sp() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "acme".into(),
            config: None,
        })
        .expect("create");

    let sp = SamlServiceProvider {
        sp_key: "my-crm".into(),
        entity_id: "https://crm.example".into(),
        acs_url: "https://crm.example/acs".into(),
        slo_url: None,
        sp_certificate_pem: None,
        sign_assertions: true,
        sign_responses: true,
        want_authn_requests_signed: false,
        nameid_format: SamlNameIdFormat::EmailAddress,
        attribute_map: BTreeMap::new(),
    };
    h.identity()
        .register_saml_sp(realm.id(), &sp)
        .expect("register");

    let got = h
        .identity()
        .get_saml_sp_by_entity_id(realm.id(), "https://crm.example")
        .expect("get")
        .expect("some");
    assert_eq!(got.sp_key, "my-crm");

    let listed = h.identity().list_saml_sps(realm.id()).expect("list");
    assert_eq!(listed.len(), 1);
}

#[tokio::test]
async fn engine_replay_protection_works() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "acme".into(),
            config: None,
        })
        .expect("create");
    let idp = IdpId::generate();
    // expires_at well in the future so the record is still live on the second call.
    let far_future = Timestamp::from_micros(i64::MAX / 2);
    h.identity()
        .mark_saml_assertion_consumed(realm.id(), &idp, "_a1", far_future)
        .expect("first");
    let err = h
        .identity()
        .mark_saml_assertion_consumed(realm.id(), &idp, "_a1", far_future)
        .expect_err("second should reject");
    assert!(matches!(err, hearth::identity::IdentityError::SamlReplay));
}

/// Verifies that consumed assertion records with a past `expires_at` are
/// lazily cleaned up and do not block reuse (the assertion's own
/// `NotOnOrAfter` check provides the second line of defence).
#[tokio::test]
async fn engine_replay_guard_expired_record_allows_reuse() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "expired-ttl".into(),
            config: None,
        })
        .expect("create");
    let idp = IdpId::generate();

    // Store a consumed record whose TTL is in the distant past.
    let ancient = Timestamp::from_micros(1_000); // 1 µs after epoch — always expired
    h.identity()
        .mark_saml_assertion_consumed(realm.id(), &idp, "_a_old", ancient)
        .expect("initial store");

    // A second call should succeed: the stored record is expired, so the
    // engine lazily removes it and writes a fresh one.
    let far_future = Timestamp::from_micros(i64::MAX / 2);
    h.identity()
        .mark_saml_assertion_consumed(realm.id(), &idp, "_a_old", far_future)
        .expect("expired record must not block reuse");
}

/// Full SP ACS path replay test: simulate the web-handler sequence of
/// `SamlSpService::complete` followed by `mark_saml_assertion_consumed`,
/// then replay the identical assertion and confirm the second mark returns
/// `SamlReplay`.
#[tokio::test]
async fn sp_acs_replay_prevention() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "acs-replay".into(),
            config: None,
        })
        .expect("create realm");

    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cert_pem = cert_der_to_pem(idp_key.cert_der());
    let idp_id = IdpId::generate();
    let sp_entity_id = "https://hearth.example/ui/realms/acs-replay";
    let acs_url = "https://hearth.example/ui/realms/acs-replay/federation/saml/acs";

    let idp_cfg = SamlIdpConfig {
        idp_id: idp_id.clone(),
        name: "test-idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![idp_cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: false,
        attribute_map: {
            let mut m = BTreeMap::new();
            m.insert("email".into(), "NameID".into());
            m
        },
    };

    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let not_on_or_after = Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000);
    // Use far-future expires_at so the replay guard record is live when the
    // real wall clock is checked by the engine. (not_on_or_after is 2023
    // which is already past; using it would trigger lazy expiry instead.)
    let expires_at = Timestamp::from_micros(i64::MAX / 2);

    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_r1",
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: acs_url,
        issuer: "https://idp.example",
        audience: sp_entity_id,
        assertion_id: "_a1",
        subject_name_id: "alice@example.com",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after,
        attributes: &BTreeMap::new(),
    });
    let signed = sign_element(xml.as_bytes(), "_r1", &idp_key).expect("sign");

    // First auth: complete + mark consumed — must succeed.
    let outcome =
        SamlSpService::complete(&idp_cfg, sp_entity_id, acs_url, Some("_req1"), now, &signed);
    assert!(
        matches!(outcome, SamlSpOutcome::Accepted { .. }),
        "expected first assertion to be accepted"
    );
    h.identity()
        .mark_saml_assertion_consumed(realm.id(), &idp_id, "_a1", expires_at)
        .expect("first mark must succeed");

    // Replay: identical assertion submitted a second time — complete still
    // validates (it has no storage), but mark_consumed must reject it.
    let outcome2 =
        SamlSpService::complete(&idp_cfg, sp_entity_id, acs_url, Some("_req1"), now, &signed);
    assert!(
        matches!(outcome2, SamlSpOutcome::Accepted { .. }),
        "complete() itself cannot detect replay — engine guard is the barrier"
    );
    let err = h
        .identity()
        .mark_saml_assertion_consumed(realm.id(), &idp_id, "_a1", expires_at)
        .expect_err("replayed assertion must be rejected");
    assert!(
        matches!(err, hearth::identity::IdentityError::SamlReplay),
        "expected SamlReplay, got {err:?}"
    );
}

#[tokio::test]
async fn engine_lazy_creates_saml_signing_key() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "acme".into(),
            config: None,
        })
        .expect("create");
    let k1 = h
        .identity()
        .get_or_create_saml_signing_key(realm.id(), "https://hearth/realms/acme")
        .expect("k1");
    let k2 = h
        .identity()
        .get_or_create_saml_signing_key(realm.id(), "https://hearth/realms/acme")
        .expect("k2");
    // Deterministic: same cert DER + same key id.
    assert_eq!(k1.cert_der(), k2.cert_der());
    assert_eq!(k1.key_id(), k2.key_id());
}

#[tokio::test]
async fn idp_can_issue_signed_response() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "acme".into(),
            config: None,
        })
        .expect("create");
    let key = h
        .identity()
        .get_or_create_saml_signing_key(realm.id(), "https://idp.test")
        .expect("key");

    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_r",
        in_response_to: Some("_req"),
        issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
        destination: "https://sp/acs",
        issuer: "https://idp.test",
        audience: "https://sp",
        assertion_id: "_a",
        subject_name_id: "user@test",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "s",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let signed = sign_element(xml.as_bytes(), "_r", &key).expect("sign");

    // Verify with the same realm's cert.
    let cert_pem = cert_der_to_pem(key.cert_der());
    let verified = verify_signed_element(&signed, "Response", &cert_pem).expect("verify");
    assert_eq!(verified.id, "_r");

    // HTML POST form wraps a base64 payload.
    let html = build_post_form_html("https://sp/acs", "SAMLResponse", &signed, Some("rs"));
    assert!(html.contains("action=\"https://sp/acs\""));
}

/// Concurrent replay guard: N threads race to mark the same assertion ID
/// consumed.  Exactly one must succeed; all others must receive `SamlReplay`.
///
/// This exercises the `put_if_absent` atomicity fix for SEC-2026-002 (HEA-1282).
#[tokio::test]
async fn engine_replay_guard_concurrent_mark_is_atomic() {
    use std::sync::{Arc, Barrier};

    let h = Arc::new(TestHarness::embedded().await.expect("harness"));
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "concurrent-replay".into(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let idp = IdpId::generate();
    let far_future = Timestamp::from_micros(i64::MAX / 2);

    const THREADS: usize = 16;
    // Barrier ensures all threads enter mark_saml_assertion_consumed simultaneously.
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let h2 = Arc::clone(&h);
        let rid = realm_id.clone();
        let idp2 = idp.clone();
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            h2.identity()
                .mark_saml_assertion_consumed(&rid, &idp2, "_concurrent_a1", far_future)
        }));
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread did not panic"))
        .collect();

    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    let replay_count = results
        .iter()
        .filter(|r| matches!(r, Err(hearth::identity::IdentityError::SamlReplay)))
        .count();

    assert_eq!(ok_count, 1, "exactly one thread must write the guard record");
    assert_eq!(
        replay_count,
        THREADS - 1,
        "all other threads must be rejected as replays"
    );
}

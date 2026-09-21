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
        trust_asserted_email: false,
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
        trust_asserted_email: false,
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
        trust_asserted_email: false,
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
                hearth::identity::IdentityError::Saml(
                    hearth::identity::federation::saml::SamlError::AudienceMismatch
                )
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
    // 22.11: the sentinel now records when the guarded assertion stops being
    // replayable, so the cleanup sweeper can reclaim it.
    let expires_at_secs = 4_102_444_800; // 2100-01-01, well past any sweep
    h.identity()
        .mark_saml_assertion_consumed(realm.id(), &idp, "_a1", expires_at_secs)
        .expect("first");
    let err = h
        .identity()
        .mark_saml_assertion_consumed(realm.id(), &idp, "_a1", expires_at_secs)
        .expect_err("second should reject");
    assert!(matches!(
        err,
        hearth::identity::IdentityError::Saml(
            hearth::identity::federation::saml::SamlError::Replay
        )
    ));
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
    let html = build_post_form_html("https://sp/acs", "SAMLResponse", &signed, Some("rs"), None);
    assert!(html.contains("action=\"https://sp/acs\""));
}

/// Extracts the `<saml:Assertion>…</saml:Assertion>` substring from a
/// built `<samlp:Response>`.
fn extract_assertion(response_xml: &str) -> String {
    let start = response_xml
        .find("<saml:Assertion ")
        .expect("assertion start");
    let end = response_xml
        .find("</saml:Assertion>")
        .expect("assertion end")
        + "</saml:Assertion>".len();
    response_xml[start..end].to_string()
}

/// Builds a `<saml:Assertion>` for `subject` with the given ID, valid for
/// `audience` at `now`.
fn assertion_for(id: &str, subject: &str, audience: &str, acs_url: &str, now: Timestamp) -> String {
    let response = build_response_xml(&ResponseBuilder {
        response_id: "_ignored",
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: acs_url,
        issuer: "https://idp.example",
        audience,
        assertion_id: id,
        subject_name_id: subject,
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    extract_assertion(&response)
}

/// B5 — XML Signature Wrapping.
///
/// The IdP signs an assertion for `mallory@corp.example`. The attacker,
/// who holds that legitimate upstream account, hides a second assertion
/// for `ceo@corp.example` **inside the signed assertion's
/// `<ds:Signature>` element**. The enveloped-signature transform strips
/// that element before digesting, so the signature still verifies — while
/// the response parser, which collects every `<saml:Assertion>` in the
/// document, consumes the attacker's.
///
/// The element whose signature was verified MUST be the element that is
/// consumed.
#[test]
fn sp_rejects_wrapped_assertion_signed_elsewhere_in_the_document() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cert_pem = cert_der_to_pem(idp_key.cert_der());

    let sp_entity_id = "https://hearth.example/ui/realms/acme";
    let acs_url = "https://hearth.example/ui/realms/acme/federation/saml/acs";
    let idp_cfg = SamlIdpConfig {
        idp_id: IdpId::generate(),
        name: "test-idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![idp_cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: true,
        trust_asserted_email: false,
        attribute_map: {
            let mut m = BTreeMap::new();
            m.insert("email".into(), "NameID".into());
            m
        },
    };

    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);

    // 1. The IdP issues and signs an assertion for the attacker's own account.
    let honest = assertion_for(
        "_signed1",
        "mallory@corp.example",
        sp_entity_id,
        acs_url,
        now,
    );
    let signed_assertion =
        sign_element(honest.as_bytes(), "_signed1", &idp_key).expect("sign assertion");
    let signed_assertion = String::from_utf8(signed_assertion).expect("utf8");

    // 2. The attacker forges an assertion for the victim.
    let evil = assertion_for("_evil1", "ceo@corp.example", sp_entity_id, acs_url, now);

    // 3. …and hides it inside the signed assertion's <ds:Signature>, which
    //    the enveloped transform removes before the digest is computed.
    let wrapped = signed_assertion.replace("</ds:Signature>", &format!("{evil}</ds:Signature>"));
    assert!(
        wrapped.contains("_evil1"),
        "wrapping step did not inject the forged assertion"
    );

    // 4. The wrapped assertion is delivered inside an otherwise ordinary Response.
    let carrier = build_response_xml(&ResponseBuilder {
        response_id: "_r1",
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: acs_url,
        issuer: "https://idp.example",
        audience: sp_entity_id,
        assertion_id: "_signed1",
        subject_name_id: "mallory@corp.example",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let original = extract_assertion(&carrier);
    let attack = carrier.replace(&original, &wrapped);

    let outcome = SamlSpService::complete(
        &idp_cfg,
        sp_entity_id,
        acs_url,
        Some("_req1"),
        now,
        attack.as_bytes(),
    );

    match outcome {
        SamlSpOutcome::Rejected { .. } => {}
        SamlSpOutcome::Accepted {
            identity, assertion, ..
        } => panic!(
            "XSW -> ACCEPTED  consumed assertion.id={}  identity.email={}  (IdP signed mallory@corp.example)",
            assertion.id, identity.email
        ),
    }
}

// ============================================================================
// 19.4 (audit 2026-08-28 §4.10#5) — the signed `<SubjectConfirmationData>`
// bindings, end-to-end through the signature-verifying SP service.
// ============================================================================

/// Builds a signed `<Response>` for `https://sp.example`, optionally rewriting
/// the bearer `<SubjectConfirmationData>` attributes *before* signing — so the
/// IdP's signature covers the rewritten value. That is the real attack shape:
/// a legitimately signed assertion minted for a different recipient.
fn signed_response_with_rewritten_confirmation(
    key: &RsaSigningKey,
    rewrite: &[(&str, &str)],
) -> Vec<u8> {
    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let mut xml = build_response_xml(&ResponseBuilder {
        response_id: "_r1",
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: "https://sp.example/acs",
        issuer: "https://idp.example",
        audience: "https://sp.example",
        assertion_id: "_a1",
        subject_name_id: "alice@example.com",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    for (from, to) in rewrite {
        assert!(xml.contains(from), "fixture must contain {from}");
        xml = xml.replace(from, to);
    }
    sign_element(xml.as_bytes(), "_r1", key).expect("sign")
}

/// Same fixture, but the bearer `<SubjectConfirmationData NotOnOrAfter>` — and
/// only that copy — is moved into the past. `<Conditions NotOnOrAfter>` keeps
/// the original, still-open instant.
fn signed_response_with_closed_bearer_window(key: &RsaSigningKey) -> Vec<u8> {
    const MARKER: &str = r#"<saml:SubjectConfirmationData NotOnOrAfter=""#;
    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_r1",
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: "https://sp.example/acs",
        issuer: "https://idp.example",
        audience: "https://sp.example",
        assertion_id: "_a1",
        subject_name_id: "alice@example.com",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let start = xml.find(MARKER).expect("fixture has a bearer confirmation") + MARKER.len();
    let end = start + xml[start..].find('"').expect("closing quote");
    let mut rewritten = String::with_capacity(xml.len());
    rewritten.push_str(&xml[..start]);
    rewritten.push_str("2023-11-13T00:00:00.000000000Z");
    rewritten.push_str(&xml[end..]);
    assert!(
        rewritten.contains("<saml:Conditions NotBefore="),
        "Conditions must be untouched"
    );
    sign_element(rewritten.as_bytes(), "_r1", key).expect("sign")
}

fn sp_idp_config(cert_pem: String) -> SamlIdpConfig {
    SamlIdpConfig {
        idp_id: IdpId::generate(),
        name: "corp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: false,
        trust_asserted_email: false,
        attribute_map: BTreeMap::new(),
    }
}

/// Control: the unmodified fixture is accepted, so the rejections below are
/// caused by the rewritten binding and nothing else.
#[tokio::test]
async fn sp_accepts_well_bound_subject_confirmation() {
    let _h = TestHarness::embedded().await.expect("harness");
    let key = RsaSigningKey::generate("test-idp", 365).expect("key");
    let signed = signed_response_with_rewritten_confirmation(&key, &[]);
    let outcome = SamlSpService::complete(
        &sp_idp_config(cert_der_to_pem(key.cert_der())),
        "https://sp.example",
        "https://sp.example/acs",
        Some("_req1"),
        Timestamp::from_micros(1_700_000_000 * 1_000_000),
        &signed,
    );
    assert!(
        matches!(outcome, SamlSpOutcome::Accepted { .. }),
        "a correctly bound bearer assertion must be accepted"
    );
}

/// §4.10#5: an assertion the IdP legitimately signed for **another** service
/// provider — its `Recipient` names that SP's ACS — must be refused when
/// replayed here, even though the outer `<Response Destination=…>` is ours.
#[tokio::test]
async fn sp_rejects_assertion_minted_for_another_recipient() {
    let _h = TestHarness::embedded().await.expect("harness");
    let key = RsaSigningKey::generate("test-idp", 365).expect("key");
    let signed = signed_response_with_rewritten_confirmation(
        &key,
        &[(
            r#"Recipient="https://sp.example/acs""#,
            r#"Recipient="https://other-sp.example/acs""#,
        )],
    );
    let outcome = SamlSpService::complete(
        &sp_idp_config(cert_der_to_pem(key.cert_der())),
        "https://sp.example",
        "https://sp.example/acs",
        Some("_req1"),
        Timestamp::from_micros(1_700_000_000 * 1_000_000),
        &signed,
    );
    match outcome {
        SamlSpOutcome::Rejected { error } => assert!(
            matches!(
                error,
                hearth::identity::IdentityError::Saml(
                    hearth::identity::federation::saml::SamlError::DestinationMismatch
                )
            ),
            "expected a Recipient/destination rejection, got {error:?}"
        ),
        SamlSpOutcome::Accepted { .. } => {
            panic!("an assertion minted for another SP's ACS was accepted")
        }
    }
}

/// §4.10#5: the bearer `NotOnOrAfter` is its own window. An assertion whose
/// `<Conditions>` are still open but whose bearer window has closed must be
/// refused.
#[tokio::test]
async fn sp_rejects_closed_bearer_window() {
    let _h = TestHarness::embedded().await.expect("harness");
    let key = RsaSigningKey::generate("test-idp", 365).expect("key");
    // Conditions/NotOnOrAfter stays open; only the bearer copy (inside
    // SubjectConfirmationData) is pulled back into the past. The builder emits
    // the same instant in both places, so rewrite it positionally.
    let signed = signed_response_with_closed_bearer_window(&key);
    let outcome = SamlSpService::complete(
        &sp_idp_config(cert_der_to_pem(key.cert_der())),
        "https://sp.example",
        "https://sp.example/acs",
        Some("_req1"),
        Timestamp::from_micros(1_700_000_000 * 1_000_000),
        &signed,
    );
    match outcome {
        SamlSpOutcome::Rejected { error } => assert!(
            matches!(
                error,
                hearth::identity::IdentityError::Saml(
                    hearth::identity::federation::saml::SamlError::Expired
                )
            ),
            "expected an Expired rejection from the bearer window, got {error:?}"
        ),
        SamlSpOutcome::Accepted { .. } => {
            panic!("an assertion whose bearer window had closed was accepted")
        }
    }
}

/// §4.10#5: `InResponseTo` inside the signed element must name the
/// `AuthnRequest` this SP issued.
#[tokio::test]
async fn sp_rejects_signed_in_response_to_mismatch() {
    let _h = TestHarness::embedded().await.expect("harness");
    let key = RsaSigningKey::generate("test-idp", 365).expect("key");
    // Rewrite only the copy inside <SubjectConfirmationData>; the
    // <Response InResponseTo="_req1"> envelope still says the right thing,
    // which is precisely why the envelope copy is not enough.
    let signed = signed_response_with_rewritten_confirmation(
        &key,
        &[(
            r#"Recipient="https://sp.example/acs" InResponseTo="_req1""#,
            r#"Recipient="https://sp.example/acs" InResponseTo="_attacker""#,
        )],
    );
    let outcome = SamlSpService::complete(
        &sp_idp_config(cert_der_to_pem(key.cert_der())),
        "https://sp.example",
        "https://sp.example/acs",
        Some("_req1"),
        Timestamp::from_micros(1_700_000_000 * 1_000_000),
        &signed,
    );
    match outcome {
        SamlSpOutcome::Rejected { error } => assert!(
            matches!(
                error,
                hearth::identity::IdentityError::Saml(
                    hearth::identity::federation::saml::SamlError::InvalidAuthnRequest { .. }
                )
            ),
            "expected an InResponseTo rejection, got {error:?}"
        ),
        SamlSpOutcome::Accepted { .. } => {
            panic!("a signed InResponseTo mismatch was accepted")
        }
    }
}

// ============================================================================
// 22.11 (audit 2026-08-28 §4.10#9) — the `saml:state:` key space is written by
// an unauthenticated GET and must not grow without bound.
// ============================================================================

/// Counts live `saml:state:` rows in a realm. The prefix is asserted non-empty
/// by the caller first, so a drifted key format fails loudly rather than making
/// the reclamation assertion pass vacuously.
fn count_saml_state_rows(h: &TestHarness, realm: &hearth::core::RealmId) -> usize {
    h.storage()
        .scan(realm, b"saml:state:", b"saml:state;")
        .expect("scan saml state")
        .len()
}

/// The unauthenticated `…/federation/saml/begin` writer reclaims what has aged
/// out before it writes, so an abandoned login cannot leak a row for the life
/// of the store.
#[tokio::test]
async fn put_saml_state_reclaims_expired_bags() {
    use hearth::identity::federation::saml::SamlStateBag;

    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "saml-cap".into(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let idp_id = IdpId::generate();

    let now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_micros() as i64;

    // An abandoned login from an hour ago: past the 600 s TTL.
    h.identity()
        .put_saml_state(&SamlStateBag {
            token: "abandoned".into(),
            request_id: "_req-abandoned".into(),
            realm_id: realm_id.clone(),
            idp_id: idp_id.clone(),
            return_to: None,
            created_at: Timestamp::from_micros(now_micros - 3_600 * 1_000_000),
        })
        .expect("seed abandoned bag");
    assert_eq!(
        count_saml_state_rows(&h, &realm_id),
        1,
        "the seeded bag must be visible under the saml:state: prefix — if this \
         is 0 the key format drifted and the reclamation check below would be \
         vacuous"
    );

    // A fresh login. Writing it must first reclaim the stale row.
    h.identity()
        .put_saml_state(&SamlStateBag {
            token: "in-flight".into(),
            request_id: "_req-in-flight".into(),
            realm_id: realm_id.clone(),
            idp_id,
            return_to: None,
            created_at: Timestamp::from_micros(now_micros),
        })
        .expect("write fresh bag");

    assert_eq!(
        count_saml_state_rows(&h, &realm_id),
        1,
        "the abandoned bag must have been reclaimed, leaving only the live one"
    );
    h.identity()
        .take_saml_state(&realm_id, "in-flight")
        .expect("the live bag is the survivor");
}

/// Task 25.27 — the SAML `ConfirmLinkRequired` branch, end to end.
///
/// SAML carries no `email_verified` signal, so `assertion_to_external_identity`
/// hard-coded `email_verified: false` — and its own comment promised an opt-in
/// "via YAML" that did not exist. The consequence was not merely "auto-link is
/// off". With that field false, `ExternalIdentity::is_linkable_by_email` is
/// false for EVERY SAML identity, so `resolve_identity` skips its whole
/// email-match arm: `LinkMode::Confirm` and `LinkMode::Auto` alike are
/// unreachable, and a SAML login by a user who already exists locally falls
/// through to just-in-time provisioning, which detects the email collision and
/// silently creates a SECOND account under a synthetic address.
///
/// The `trust_asserted_email` connector field is that opt-in. This test drives
/// a real signed assertion through the SP service and then through
/// `resolve_identity` against a real engine holding a user with the same
/// address.
///
/// The `false` half is the control: it pins today's default and proves the
/// `true` half is the flag doing the work, not the fixture.
#[tokio::test]
async fn saml_confirm_link_is_reachable_only_when_the_asserted_email_is_trusted() {
    use hearth::identity::federation::{
        FederationOutcome, FederationService, LinkMode, StubFederationTransport,
    };
    use hearth::identity::CreateUserRequest;
    use std::sync::Arc;

    let h = TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("saml-link-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    // The local account the SAML login must be offered a link to.
    h.identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                ..Default::default()
            },
        )
        .expect("create user");

    let service = FederationService::new(
        h.identity_arc(),
        Arc::new(StubFederationTransport::new()),
        "https://hearth.example/federation/callback".to_string(),
    );

    for trust in [false, true] {
        let identity = saml_identity_for("alice@example.com", trust);
        assert_eq!(
            identity.is_linkable_by_email(),
            trust,
            "trust_asserted_email is what makes a SAML identity linkable at all"
        );

        let outcome = service
            .resolve_identity(
                realm.id(),
                identity,
                LinkMode::Confirm,
                Timestamp::from_micros(1_700_000_000 * 1_000_000),
            )
            .expect("resolve identity");

        if trust {
            assert!(
                matches!(outcome, FederationOutcome::ConfirmLinkRequired(_)),
                "with the asserted email trusted, an existing local account must \
                 be offered confirm-to-link; got a different outcome"
            );
        } else {
            assert!(
                matches!(outcome, FederationOutcome::JitProvision(_)),
                "the default must stay as it was: no linking, JIT provisioning"
            );
        }
    }
}

/// Runs a real signed assertion for `email` through the SP service and returns
/// the `ExternalIdentity` it produced.
///
/// Going through `SamlSpService::complete` rather than building the struct by
/// hand is the point: the field under test is set inside that path, so a
/// hand-built identity would test nothing.
fn saml_identity_for(
    email: &str,
    trust_asserted_email: bool,
) -> hearth::identity::federation::ExternalIdentity {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cert_pem = cert_der_to_pem(idp_key.cert_der());
    let sp_entity_id = "https://hearth.example/ui/realms/acme";
    let acs_url = "https://hearth.example/ui/realms/acme/federation/saml/acs";

    let idp_cfg = SamlIdpConfig {
        idp_id: IdpId::generate(),
        name: "test-idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![idp_cert_pem],
        sign_authn_requests: false,
        want_assertions_signed: false,
        trust_asserted_email,
        attribute_map: {
            let mut m = BTreeMap::new();
            m.insert("email".into(), "NameID".into());
            m
        },
    };

    let now = Timestamp::from_micros(1_700_000_000 * 1_000_000);
    let response_id = "_link1";
    let xml = build_response_xml(&ResponseBuilder {
        response_id,
        in_response_to: Some("_req1"),
        issue_instant: now,
        destination: acs_url,
        issuer: "https://idp.example",
        audience: sp_entity_id,
        assertion_id: "_alink1",
        subject_name_id: email,
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes: &BTreeMap::new(),
    });
    let signed = sign_element(xml.as_bytes(), response_id, &idp_key).expect("sign");

    match SamlSpService::complete(&idp_cfg, sp_entity_id, acs_url, Some("_req1"), now, &signed) {
        SamlSpOutcome::Accepted { identity, .. } => identity,
        SamlSpOutcome::Rejected { error } => panic!("expected accept, got {error:?}"),
    }
}

//! Integration tests for SAML 2.0 SP + IdP.
//!
//! Exercises the full SP-initiated SSO flow and the IdP-side response
//! issuing path using the embedded engine.

mod common;

use std::collections::BTreeMap;

use common::TestHarness;
use hearth::core::{IdpId, Timestamp};
use hearth::identity::federation::saml::{
    build_response_xml, sign_element, verify_signed_element, ResponseBuilder, SamlError,
    SamlIdpConfig, SamlNameIdFormat, SamlSpOutcome, SamlSpService,
};
use hearth::identity::tokens::RsaSigningKey;
use hearth::identity::{CreateRealmRequest, IdentityError};

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
    let h = TestHarness::in_process().await.expect("harness");

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
    let _h = TestHarness::in_process().await.expect("harness");
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
    let _h = TestHarness::in_process().await.expect("harness");
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
async fn engine_replay_protection_works() {
    let h = TestHarness::in_process().await.expect("harness");
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
    let h = TestHarness::in_process().await.expect("harness");
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

/// Makes an extracted `<saml:Assertion>` self-contained by declaring the
/// `saml` prefix on it.
///
/// An IdP signs an assertion in context: exclusive C14N renders the
/// `xmlns:saml` it inherits from the `<Response>` on the assertion itself.
/// Signing the bare extracted substring would compute a canonical form no
/// standards-conformant verifier (Hearth included) reproduces.
fn with_saml_ns(assertion: &str) -> String {
    assert!(
        assertion.starts_with("<saml:Assertion "),
        "not an assertion"
    );
    assertion.replacen(
        "<saml:Assertion ",
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
        1,
    )
}

/// Builds a self-contained `<saml:Assertion>` for `subject` with the given
/// ID, valid for `audience` at `now`.
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
    with_saml_ns(&extract_assertion(&response))
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

    // Control: the same carrier with the untouched signed assertion is
    // accepted, so the rejection below is caused by the wrapping.
    match SamlSpService::complete(
        &idp_cfg,
        sp_entity_id,
        acs_url,
        Some("_req1"),
        now,
        carrier.replace(&original, &signed_assertion).as_bytes(),
    ) {
        SamlSpOutcome::Accepted { identity, .. } => {
            assert_eq!(identity.email, "mallory@corp.example", "control identity");
        }
        SamlSpOutcome::Rejected { error } => panic!("control rejected: {error:?}"),
    }

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
    let _h = TestHarness::in_process().await.expect("harness");
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
    let _h = TestHarness::in_process().await.expect("harness");
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
    let _h = TestHarness::in_process().await.expect("harness");
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
    let _h = TestHarness::in_process().await.expect("harness");
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

    let h = TestHarness::in_process().await.expect("harness");
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

    let h = TestHarness::in_process().await.expect("harness");
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

// ============================================================================
// GA sweep 3, G-1 — XML-signature wrapping through the enveloped-signature
// transform.
//
// The enveloped-signature transform removes ONE `<ds:Signature>` from the
// digest input: the one being verified. Hearth's canonicalizer removed EVERY
// direct-child `<ds:Signature>`, the verifier only ever read the first, and
// the response parser read SAML elements wherever they sat — including inside
// a `<ds:Signature>`. An attacker holding any account at the IdP could append
// a second `<ds:Signature>` carrying `<saml:NameID>`, `<saml:Attribute>` or
// `<saml:Conditions>` to an assertion the IdP signed for them: the digest was
// unchanged, and the parser's last-write-wins fields took the forged values.
// ============================================================================

const XSW_SP_ENTITY_ID: &str = "https://hearth.example/ui/realms/acme";
const XSW_ACS_URL: &str = "https://hearth.example/ui/realms/acme/federation/saml/acs";

/// `<saml:Subject>` naming the victim — the payload every wrapping variant
/// below tries to smuggle past the signature.
const XSW_VICTIM_SUBJECT: &str =
    "<saml:Subject><saml:NameID>ceo@corp.example</saml:NameID></saml:Subject>";

fn xsw_now() -> Timestamp {
    Timestamp::from_micros(1_700_000_000 * 1_000_000)
}

/// Wraps `inner` in a `<ds:Signature>` that no verifier will ever look at.
fn xsw_extra_signature(inner: &str) -> String {
    format!(r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{inner}</ds:Signature>"#)
}

/// Inserts `insert` immediately before the first `anchor`, panicking when the
/// anchor is absent so a silently skipped mutation cannot pass a test.
fn xsw_insert_before(xml: &str, anchor: &str, insert: &str) -> String {
    assert!(xml.contains(anchor), "anchor {anchor:?} not present");
    xml.replacen(anchor, &format!("{insert}{anchor}"), 1)
}

/// Inserts `insert` immediately after the first `anchor`.
fn xsw_insert_after(xml: &str, anchor: &str, insert: &str) -> String {
    assert!(xml.contains(anchor), "anchor {anchor:?} not present");
    xml.replacen(anchor, &format!("{anchor}{insert}"), 1)
}

/// An IdP connector trusting `idp_key`, taking the email from `email_source`
/// (`"NameID"` or an attribute name).
fn xsw_idp_config(
    idp_key: &RsaSigningKey,
    email_source: &str,
    want_assertions_signed: bool,
) -> SamlIdpConfig {
    SamlIdpConfig {
        idp_id: IdpId::generate(),
        name: "test-idp".into(),
        entity_id: "https://idp.example".into(),
        sso_url: "https://idp.example/sso".into(),
        slo_url: None,
        idp_certificates_pem: vec![cert_der_to_pem(idp_key.cert_der())],
        sign_authn_requests: false,
        want_assertions_signed,
        trust_asserted_email: false,
        attribute_map: BTreeMap::from([("email".to_string(), email_source.to_string())]),
    }
}

/// An unsigned `<samlp:Response>` asserting `mallory@corp.example`.
fn xsw_response_for_mallory(attributes: &BTreeMap<String, Vec<String>>) -> String {
    build_response_xml(&ResponseBuilder {
        response_id: "_r1",
        in_response_to: Some("_req1"),
        issue_instant: xsw_now(),
        destination: XSW_ACS_URL,
        issuer: "https://idp.example",
        audience: XSW_SP_ENTITY_ID,
        assertion_id: "_signed1",
        subject_name_id: "mallory@corp.example",
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess1",
        not_before: Timestamp::from_micros((1_700_000_000 - 10) * 1_000_000),
        not_on_or_after: Timestamp::from_micros((1_700_000_000 + 300) * 1_000_000),
        attributes,
    })
}

/// A Response whose assertion the IdP signed for mallory — the attacker's own
/// legitimate login. Returns `(response, signed_assertion)` so a test can
/// rewrite the assertion in place.
fn xsw_assertion_signed_for_mallory(
    idp_key: &RsaSigningKey,
    attributes: &BTreeMap<String, Vec<String>>,
) -> (String, String) {
    let response = xsw_response_for_mallory(attributes);
    let assertion = extract_assertion(&response);
    let signed = sign_element(with_saml_ns(&assertion).as_bytes(), "_signed1", idp_key)
        .expect("sign assertion");
    let signed = String::from_utf8(signed).expect("utf8");
    (response.replace(&assertion, &signed), signed)
}

/// Splits a signed element into `(element without its signature, signature)`.
fn xsw_split_signature(signed: &str) -> (String, String) {
    let start = signed.find("<ds:Signature").expect("signature start");
    let end = signed.find("</ds:Signature>").expect("signature end") + "</ds:Signature>".len();
    let without = format!("{}{}", &signed[..start], &signed[end..]);
    (without, signed[start..end].to_string())
}

fn xsw_complete(idp_cfg: &SamlIdpConfig, xml: &str) -> SamlSpOutcome {
    SamlSpService::complete(
        idp_cfg,
        XSW_SP_ENTITY_ID,
        XSW_ACS_URL,
        Some("_req1"),
        xsw_now(),
        xml.as_bytes(),
    )
}

/// Control: the untouched document is accepted as mallory, so a rejection of
/// its tampered twin is caused by the tampering and not by a broken fixture.
fn xsw_assert_accepted_as_mallory(idp_cfg: &SamlIdpConfig, xml: &str, case: &str) {
    match xsw_complete(idp_cfg, xml) {
        SamlSpOutcome::Accepted { identity, .. } => {
            assert_eq!(identity.email, "mallory@corp.example", "{case}: identity");
        }
        SamlSpOutcome::Rejected { error } => panic!("{case}: rejected: {error:?}"),
    }
}

/// The tampered document must be refused as a signature failure.
fn xsw_assert_rejected(idp_cfg: &SamlIdpConfig, xml: &str, case: &str) {
    match xsw_complete(idp_cfg, xml) {
        SamlSpOutcome::Rejected { error } => assert!(
            matches!(error, IdentityError::Saml(SamlError::Signature)),
            "{case}: rejected for the wrong reason: {error:?}"
        ),
        SamlSpOutcome::Accepted {
            identity,
            assertion,
            ..
        } => panic!(
            "{case}: XSW ACCEPTED — consumed assertion.id={} identity.email={} \
             not_on_or_after={:?} (IdP signed mallory@corp.example)",
            assertion.id, identity.email, assertion.not_on_or_after
        ),
    }
}

/// G-1 as reported: a SECOND direct-child `<ds:Signature>`, appended as the
/// signed assertion's last child, carries the victim's NameID. It used to log
/// the attacker in as `ceo@corp.example`.
#[test]
fn sp_rejects_second_signature_carrying_a_forged_name_id() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, _) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &response, "control");

    let attack = xsw_insert_before(
        &response,
        "</saml:Assertion>",
        &xsw_extra_signature(XSW_VICTIM_SUBJECT),
    );
    xsw_assert_rejected(&idp_cfg, &attack, "second <ds:Signature> carrying a NameID");
}

/// The attribute-mapped twin: the connector takes the email from the `mail`
/// attribute, and the second `<ds:Signature>` carries a `mail` attribute.
#[test]
fn sp_rejects_second_signature_carrying_a_forged_attribute() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "mail", true);
    let attrs = BTreeMap::from([("mail".to_string(), vec!["mallory@corp.example".to_string()])]);
    let (response, _) = xsw_assertion_signed_for_mallory(&idp_key, &attrs);
    xsw_assert_accepted_as_mallory(&idp_cfg, &response, "control");

    let forged = concat!(
        r#"<saml:AttributeStatement><saml:Attribute Name="mail">"#,
        "<saml:AttributeValue>ceo@corp.example</saml:AttributeValue>",
        "</saml:Attribute></saml:AttributeStatement>",
    );
    let attack = xsw_insert_before(&response, "</saml:Assertion>", &xsw_extra_signature(forged));
    xsw_assert_rejected(
        &idp_cfg,
        &attack,
        "second <ds:Signature> carrying an attribute",
    );
}

/// A second `<ds:Signature>` carrying `<saml:Conditions>` extended to 2099
/// used to stretch the assertion's validity — and the replay sentinel derived
/// from it — far past what the IdP signed.
#[test]
fn sp_rejects_second_signature_carrying_extended_conditions() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, _) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &response, "control");

    let conditions = format!(
        concat!(
            r#"<saml:Conditions NotBefore="2023-11-14T22:13:10Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
            "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience>",
            "</saml:AudienceRestriction></saml:Conditions>",
        ),
        XSW_SP_ENTITY_ID
    );
    let attack = xsw_insert_before(
        &response,
        "</saml:Assertion>",
        &xsw_extra_signature(&conditions),
    );
    xsw_assert_rejected(
        &idp_cfg,
        &attack,
        "second <ds:Signature> carrying Conditions",
    );
}

/// No second signature at all: the IdP's own `<ds:Signature>` is moved to the
/// end of the assertion (its position is invisible to the digest) and the
/// victim's `<saml:Subject>` is appended inside it, after `</ds:KeyInfo>`.
/// XML-DSIG allows nothing but `SignedInfo`, `SignatureValue` and `KeyInfo`
/// there for a signature Hearth verifies, so the signature is refused.
#[test]
fn sp_rejects_moved_signature_with_elements_after_key_info() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, signed) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &response, "control");

    let (unsigned, signature) = xsw_split_signature(&signed);
    let signature = xsw_insert_after(&signature, "</ds:KeyInfo>", XSW_VICTIM_SUBJECT);
    let moved = xsw_insert_before(&unsigned, "</saml:Assertion>", &signature);
    let attack = response.replace(&signed, &moved);
    xsw_assert_rejected(
        &idp_cfg,
        &attack,
        "moved signature with a Subject after KeyInfo",
    );
}

/// `<ds:KeyInfo>` content is open-ended in XML-DSIG, so a `<saml:Subject>`
/// hidden inside it is not a structural error — but it sits in the one region
/// the digest never covers, and the response parser must never read it. The
/// signature is moved to the end so the hidden Subject comes last, where the
/// old last-write-wins parser took it.
#[test]
fn sp_never_reads_saml_elements_hidden_inside_the_verified_signature() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, signed) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());

    let (unsigned, signature) = xsw_split_signature(&signed);
    let signature = xsw_insert_before(&signature, "</ds:KeyInfo>", XSW_VICTIM_SUBJECT);
    let moved = xsw_insert_before(&unsigned, "</saml:Assertion>", &signature);
    let attack = response.replace(&signed, &moved);
    assert!(attack.contains("ceo@corp.example"), "injection missing");

    xsw_assert_accepted_as_mallory(&idp_cfg, &attack, "Subject hidden inside KeyInfo");
}

/// The Response-level twin (`want_assertions_signed: false`): the IdP signs
/// the whole `<samlp:Response>` and a second direct-child `<ds:Signature>` is
/// appended to it. An element carries exactly one enveloped signature.
#[test]
fn sp_rejects_second_signature_on_a_response_level_signature() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", false);
    let unsigned = xsw_response_for_mallory(&BTreeMap::new());
    let signed = sign_element(unsigned.as_bytes(), "_r1", &idp_key).expect("sign response");
    let signed = String::from_utf8(signed).expect("utf8");
    xsw_assert_accepted_as_mallory(&idp_cfg, &signed, "control");

    let attack = xsw_insert_before(
        &signed,
        "</samlp:Response>",
        &xsw_extra_signature(XSW_VICTIM_SUBJECT),
    );
    xsw_assert_rejected(
        &idp_cfg,
        &attack,
        "Response with two direct-child signatures",
    );
}

// ============================================================================
// GA sweep 3, round 2 — IdP certificate rollover, and signatures/assertions
// that spell their namespaces differently (Entra ID's default-namespace
// `<Signature>`, Keycloak's prefix declared on the `<Response>` only).
// ============================================================================

const XSW_SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const XSW_SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XSW_DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// During rollover the connector lists the outgoing AND the incoming IdP
/// certificate; an assertion signed by the second one must verify. Hearth
/// used to try only the first.
#[test]
fn sp_accepts_an_assertion_signed_by_any_configured_idp_certificate() {
    let old_key = RsaSigningKey::generate("idp-old", 365).expect("old key");
    let new_key = RsaSigningKey::generate("idp-new", 365).expect("new key");
    let mut idp_cfg = xsw_idp_config(&old_key, "NameID", true);
    idp_cfg
        .idp_certificates_pem
        .push(cert_der_to_pem(new_key.cert_der()));

    let (by_old, _) = xsw_assertion_signed_for_mallory(&old_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &by_old, "signed by the first certificate");
    let (by_new, _) = xsw_assertion_signed_for_mallory(&new_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &by_new, "signed by the second certificate");

    // A key in neither slot is still refused, and so is the G-1 shape.
    let stranger = RsaSigningKey::generate("idp-stranger", 365).expect("key");
    let (by_stranger, _) = xsw_assertion_signed_for_mallory(&stranger, &BTreeMap::new());
    xsw_assert_rejected(&idp_cfg, &by_stranger, "signed by an unlisted key");
    let wrapped = xsw_insert_before(
        &by_new,
        "</saml:Assertion>",
        &xsw_extra_signature(XSW_VICTIM_SUBJECT),
    );
    xsw_assert_rejected(&idp_cfg, &wrapped, "second signature with two certificates");
}

/// The Response-level twin of the rollover case.
#[test]
fn sp_accepts_a_response_level_signature_by_the_second_idp_certificate() {
    let old_key = RsaSigningKey::generate("idp-old", 365).expect("old key");
    let new_key = RsaSigningKey::generate("idp-new", 365).expect("new key");
    let mut idp_cfg = xsw_idp_config(&old_key, "NameID", false);
    idp_cfg
        .idp_certificates_pem
        .push(cert_der_to_pem(new_key.cert_der()));

    let unsigned = xsw_response_for_mallory(&BTreeMap::new());
    let signed = sign_element(unsigned.as_bytes(), "_r1", &new_key).expect("sign response");
    let signed = String::from_utf8(signed).expect("utf8");
    xsw_assert_accepted_as_mallory(
        &idp_cfg,
        &signed,
        "Response signed by the second certificate",
    );
}

/// An Entra-ID-shaped assertion: the assertion namespace is the default
/// namespace, and every child is unprefixed.
fn entra_assertion(id: &str, subject: &str) -> String {
    format!(
        concat!(
            r#"<Assertion xmlns="{saml}" ID="{id}" Version="2.0" IssueInstant="2023-11-14T22:13:20Z">"#,
            "<Issuer>https://idp.example</Issuer>",
            "<Subject><NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">{subject}</NameID>",
            r#"<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
            r#"<SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="2023-11-14T22:18:20Z" Recipient="{acs}"/>"#,
            "</SubjectConfirmation></Subject>",
            r#"<Conditions NotBefore="2023-11-14T22:13:10Z" NotOnOrAfter="2023-11-14T22:18:20Z">"#,
            "<AudienceRestriction><Audience>{sp}</Audience></AudienceRestriction></Conditions>",
            r#"<AuthnStatement AuthnInstant="2023-11-14T22:13:20Z" SessionIndex="sess1">"#,
            "<AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            "</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>",
        ),
        saml = XSW_SAML_NS,
        id = id,
        subject = subject,
        acs = XSW_ACS_URL,
        sp = XSW_SP_ENTITY_ID,
    )
}

/// The Entra-ID-shaped `<samlp:Response>` carrying `assertion`.
fn entra_response(assertion: &str) -> String {
    format!(
        concat!(
            r#"<samlp:Response xmlns:samlp="{samlp}" ID="_r1" Version="2.0" "#,
            r#"IssueInstant="2023-11-14T22:13:20Z" Destination="{acs}" InResponseTo="_req1">"#,
            r#"<Issuer xmlns="{saml}">https://idp.example</Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#,
            "</samlp:Status>{assertion}</samlp:Response>",
        ),
        samlp = XSW_SAMLP_NS,
        saml = XSW_SAML_NS,
        acs = XSW_ACS_URL,
        assertion = assertion,
    )
}

/// Signs `element` the way Entra ID does: an unprefixed
/// `<Signature xmlns="…xmldsig#">`, placed after the element's `<Issuer>`,
/// whose children inherit the default namespace.
fn sign_with_default_namespace_signature(element: &str, id: &str, key: &RsaSigningKey) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use hearth::identity::federation::saml::c14n::{canonicalize, EnvelopedSignature};
    use sha2::{Digest, Sha256};

    let exc = "http://www.w3.org/2001/10/xml-exc-c14n#";
    let canonical = canonicalize(element.as_bytes(), EnvelopedSignature::Keep).expect("c14n");
    let digest = B64.encode(Sha256::digest(&canonical));
    // Detached, SignedInfo carries the default-namespace declaration it
    // inherits in place — that is its exclusive-C14N form in context.
    let signed_info = format!(
        concat!(
            r#"<SignedInfo xmlns="{ds}"><CanonicalizationMethod Algorithm="{exc}"></CanonicalizationMethod>"#,
            r#"<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>"#,
            r##"<Reference URI="#{id}"><Transforms>"##,
            r#"<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>"#,
            r#"<Transform Algorithm="{exc}"></Transform></Transforms>"#,
            r#"<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>"#,
            "<DigestValue>{digest}</DigestValue></Reference></SignedInfo>",
        ),
        ds = XSW_DSIG_NS,
        exc = exc,
        id = id,
        digest = digest,
    );
    let canonical_si =
        canonicalize(signed_info.as_bytes(), EnvelopedSignature::Keep).expect("c14n si");
    let signature_value = B64.encode(key.sign(&canonical_si).expect("sign"));
    let in_document = signed_info.replacen(&format!(r#" xmlns="{XSW_DSIG_NS}""#), "", 1);
    let signature = format!(
        concat!(
            r#"<Signature xmlns="{ds}">{si}<SignatureValue>{sv}</SignatureValue>"#,
            "<KeyInfo><X509Data><X509Certificate>{cert}</X509Certificate></X509Data></KeyInfo>",
            "</Signature>",
        ),
        ds = XSW_DSIG_NS,
        si = in_document,
        sv = signature_value,
        cert = B64.encode(key.cert_der()),
    );
    xsw_insert_after(element, "</Issuer>", &signature)
}

/// The verifier accepts an Entra-style default-namespace signature on its
/// own (no response parsing involved).
#[test]
fn verifier_accepts_a_default_namespace_signature() {
    let idp_key = RsaSigningKey::generate("entra", 365).expect("key");
    let signed = sign_with_default_namespace_signature(
        &entra_assertion("_e1", "mallory@corp.example"),
        "_e1",
        &idp_key,
    );
    assert!(
        signed.contains("<SignedInfo>"),
        "fixture must be unprefixed"
    );
    match verify_signed_element(
        entra_response(&signed).as_bytes(),
        "Assertion",
        &cert_der_to_pem(idp_key.cert_der()),
    ) {
        Ok(verified) => assert_eq!(verified.id, "_e1"),
        Err(error) => panic!("default-namespace signature rejected: {error:?}"),
    }
}

/// End to end: an Entra-shaped Response is accepted and its unprefixed
/// fields are read.
#[test]
fn sp_accepts_an_entra_style_default_namespace_response() {
    let idp_key = RsaSigningKey::generate("entra", 365).expect("key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let signed = sign_with_default_namespace_signature(
        &entra_assertion("_signed1", "mallory@corp.example"),
        "_signed1",
        &idp_key,
    );
    xsw_assert_accepted_as_mallory(&idp_cfg, &entra_response(&signed), "Entra-shaped response");
}

/// G-1 still holds in the default-namespace spelling: a second unprefixed
/// `<Signature>` carrying a victim `<Subject>` is refused.
#[test]
fn sp_rejects_a_second_default_namespace_signature() {
    let idp_key = RsaSigningKey::generate("entra", 365).expect("key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let signed = sign_with_default_namespace_signature(
        &entra_assertion("_signed1", "mallory@corp.example"),
        "_signed1",
        &idp_key,
    );
    xsw_assert_accepted_as_mallory(&idp_cfg, &entra_response(&signed), "control");

    let forged = format!(
        r#"<Signature xmlns="{XSW_DSIG_NS}"><Subject xmlns="{XSW_SAML_NS}"><NameID>ceo@corp.example</NameID></Subject></Signature>"#
    );
    let attack = xsw_insert_before(&signed, "</Assertion>", &forged);
    xsw_assert_rejected(
        &idp_cfg,
        &entra_response(&attack),
        "second default-namespace <Signature>",
    );
}

/// …and so does the moved-signature variant: the real unprefixed signature
/// moved to the end with a victim `<Subject>` after its `<KeyInfo>`.
#[test]
fn sp_rejects_a_moved_default_namespace_signature_with_content_after_key_info() {
    let idp_key = RsaSigningKey::generate("entra", 365).expect("key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let signed = sign_with_default_namespace_signature(
        &entra_assertion("_signed1", "mallory@corp.example"),
        "_signed1",
        &idp_key,
    );
    xsw_assert_accepted_as_mallory(&idp_cfg, &entra_response(&signed), "control");
    let start = signed.find("<Signature ").expect("signature");
    let end = signed.find("</Signature>").expect("end") + "</Signature>".len();
    let signature = xsw_insert_after(
        &signed[start..end],
        "</KeyInfo>",
        &format!(r#"<Subject xmlns="{XSW_SAML_NS}"><NameID>ceo@corp.example</NameID></Subject>"#),
    );
    let without = format!("{}{}", &signed[..start], &signed[end..]);
    let attack = xsw_insert_before(&without, "</Assertion>", &signature);
    xsw_assert_rejected(
        &idp_cfg,
        &entra_response(&attack),
        "moved default-namespace signature",
    );
}

/// Keycloak's shape: the `saml` prefix is declared on the `<Response>` only,
/// and the `<saml:Assertion>` relies on it. Exclusive C14N renders an
/// inherited, visibly used declaration on the apex, so a standard signer's
/// canonical form carries `xmlns:saml` — which Hearth, canonicalizing the
/// extracted assertion without its ancestors' declarations, did not.
#[test]
fn sp_accepts_an_assertion_whose_prefix_is_declared_on_the_response() {
    let idp_key = RsaSigningKey::generate("keycloak", 365).expect("key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let response = xsw_response_for_mallory(&BTreeMap::new());
    let assertion = extract_assertion(&response);
    let decl = format!(r#" xmlns:saml="{XSW_SAML_NS}""#);
    // Sign the assertion in its exclusive-C14N form (declaration rendered on
    // the apex), then embed it relying on the Response's declaration.
    let signed =
        sign_element(with_saml_ns(&assertion).as_bytes(), "_signed1", &idp_key).expect("sign");
    let signed = String::from_utf8(signed)
        .expect("utf8")
        .replacen(&decl, "", 1);
    assert!(!signed.starts_with(&format!("<saml:Assertion{decl}")));
    xsw_assert_accepted_as_mallory(
        &idp_cfg,
        &response.replace(&assertion, &signed),
        "prefix declared on the Response",
    );
}

// ============================================================================
// scope-trim-trusted-core, group 3 — the strict SP profile.
//
// Structure is checked before any signature is verified: no DOCTYPE, exactly
// one `<saml:Assertion>`, and a `<ds:Signature>` only where the profile puts
// one — a direct child of the root `<samlp:Response>` or of the assertion, at
// most one each. A signature anywhere else is an unverified region inside a
// signed element; it is refused, never ignored.
// ============================================================================

/// The victim's NameID swapped into a copy of mallory's signed assertion.
fn victim_copy_of(signed_assertion: &str) -> String {
    let (unsigned, _) = xsw_split_signature(signed_assertion);
    let forged = unsigned.replace("mallory@corp.example", "ceo@corp.example");
    assert_ne!(forged, unsigned, "fixture must name mallory");
    forged
}

/// Neither rejected for a non-SAML reason nor — above all — accepted as the
/// victim. Every structural refusal in this section must be a rejection.
fn assert_refused(idp_cfg: &SamlIdpConfig, xml: &str, case: &str) {
    match xsw_complete(idp_cfg, xml) {
        SamlSpOutcome::Rejected { error } => assert!(
            matches!(error, IdentityError::Saml(_)),
            "{case}: rejected for a non-SAML reason: {error:?}"
        ),
        SamlSpOutcome::Accepted { identity, .. } => panic!(
            "{case}: ACCEPTED as {} — the strict profile must refuse it",
            identity.email
        ),
    }
}

#[test]
fn strict_profile_rejects_a_doctype_at_the_acs() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, _) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &response, "control");
    assert_refused(
        &idp_cfg,
        &format!("<!DOCTYPE samlp:Response []>{response}"),
        "doctype",
    );
}

#[test]
fn strict_profile_rejects_a_second_assertion_in_any_position() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, signed) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    let forged = victim_copy_of(&signed);
    for (case, xml) in [
        (
            "sibling before",
            xsw_insert_before(&response, &signed, &forged),
        ),
        (
            "sibling after",
            xsw_insert_after(&response, &signed, &forged),
        ),
        (
            "inside Extensions",
            xsw_insert_before(
                &response,
                "<samlp:Status>",
                &format!("<samlp:Extensions>{forged}</samlp:Extensions>"),
            ),
        ),
    ] {
        assert_refused(&idp_cfg, &xml, case);
    }
}

/// A `<ds:Signature>` outside the two places the profile allows is refused,
/// even when it is empty and the verified signature is intact.
#[test]
fn strict_profile_rejects_a_signature_outside_its_two_allowed_places() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, _) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    xsw_assert_accepted_as_mallory(&idp_cfg, &response, "control");
    let stray = xsw_extra_signature("");
    for (case, xml) in [
        (
            "inside Subject",
            xsw_insert_after(&response, "<saml:Subject>", &stray),
        ),
        (
            "inside Status",
            xsw_insert_after(&response, "<samlp:Status>", &stray),
        ),
        (
            "inside the verified signature's KeyInfo",
            xsw_insert_after(&response, "<ds:KeyInfo>", &stray),
        ),
    ] {
        assert_refused(&idp_cfg, &xml, case);
    }
}

/// Signing both the Response and the Assertion is common (Okta, ADFS). Two
/// signatures, one in each allowed place, must still be accepted.
#[test]
fn strict_profile_accepts_a_response_and_an_assertion_each_signed_once() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let (response, _) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    let both = sign_element(response.as_bytes(), "_r1", &idp_key).expect("sign response");
    let both = String::from_utf8(both).expect("utf8");
    let signatures =
        both.matches("<ds:Signature ").count() + both.matches("<ds:Signature>").count();
    assert_eq!(signatures, 2, "fixture signs twice");
    xsw_assert_accepted_as_mallory(&idp_cfg, &both, "response + assertion signed");
}

/// A Response signed at the Response level only (the assertion unsigned),
/// asserting mallory — the shape XSW1 and XSW2 attack.
fn response_signed_for_mallory(idp_key: &RsaSigningKey) -> String {
    let response = xsw_response_for_mallory(&BTreeMap::new());
    String::from_utf8(sign_element(response.as_bytes(), "_r1", idp_key).expect("sign"))
        .expect("utf8")
}

/// The eight signature-wrapping variants of Somorovsky et al., "On Breaking
/// SAML: Be Whoever You Want to Be" (USENIX Security 2012), built from a real
/// signed document. Each moves the signed original somewhere the verifier
/// still finds it and plants an unsigned copy naming the victim where a naive
/// parser would read it. None may sign anyone in as the victim; under the
/// strict profile every one is refused.
#[test]
fn strict_profile_refuses_the_eight_published_xsw_variants() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let assertion_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let response_cfg = xsw_idp_config(&idp_key, "NameID", false);

    // Response-level signature: XSW1, XSW2.
    let signed_resp = response_signed_for_mallory(&idp_key);
    xsw_assert_accepted_as_mallory(&response_cfg, &signed_resp, "response-signed control");
    let (resp_unsigned, resp_sig) = xsw_split_signature(&signed_resp);
    let forged_response = resp_unsigned
        .replace("mallory@corp.example", "ceo@corp.example")
        .replacen(r#"ID="_r1""#, r#"ID="_evil""#, 1);
    // XSW1: evil Response root; its (copied) signature carries the original
    // signed Response as an <ds:Object>.
    let sig_with_original = resp_sig.replacen(
        "</ds:Signature>",
        &format!("<ds:Object>{signed_resp}</ds:Object></ds:Signature>"),
        1,
    );
    let xsw1 = xsw_insert_after(&forged_response, "</saml:Issuer>", &sig_with_original);
    // XSW2: as XSW1, but the original is a detached sibling before the
    // signature instead of inside it.
    let xsw2 = xsw_insert_after(
        &forged_response,
        "</saml:Issuer>",
        &format!("{signed_resp}{resp_sig}"),
    );

    // Assertion-level signature: XSW3–XSW8.
    let (response, signed) = xsw_assertion_signed_for_mallory(&idp_key, &BTreeMap::new());
    let (_, sig) = xsw_split_signature(&signed);
    let evil = victim_copy_of(&signed).replacen(r#"ID="_signed1""#, r#"ID="_evil""#, 1);
    let evil_open_end = evil.find('>').expect("evil open tag") + 1;
    let (evil_open, evil_rest) = evil.split_at(evil_open_end);
    // XSW3: evil assertion as the previous sibling of the signed original.
    let xsw3 = xsw_insert_before(&response, &signed, &evil);
    // XSW4: evil assertion wraps the signed original as its child.
    let xsw4 = response.replace(&signed, &format!("{evil_open}{signed}{evil_rest}"));
    // XSW5: evil assertion carries the copied signature; the original follows
    // it unsigned.
    let (signed_unsigned, _) = xsw_split_signature(&signed);
    let evil_with_sig = format!("{evil_open}{sig}{evil_rest}");
    let xsw5 = response.replace(&signed, &format!("{evil_with_sig}{signed_unsigned}"));
    // XSW6: evil assertion with the signature; the original inside it as an
    // <ds:Object>.
    let sig_holding_original = sig.replacen(
        "</ds:Signature>",
        &format!("<ds:Object>{signed}</ds:Object></ds:Signature>"),
        1,
    );
    let xsw6 = response.replace(
        &signed,
        &format!("{evil_open}{sig_holding_original}{evil_rest}"),
    );
    // XSW7: original hidden in <samlp:Extensions>; evil assertion in place.
    let xsw7 = xsw_insert_before(
        &response.replace(&signed, &evil),
        "<samlp:Status>",
        &format!("<samlp:Extensions>{signed}</samlp:Extensions>"),
    );
    // XSW8: evil assertion whose signature holds the original, unsigned, in
    // an <ds:Object>.
    let sig_holding_unsigned = sig.replacen(
        "</ds:Signature>",
        &format!("<ds:Object>{signed_unsigned}</ds:Object></ds:Signature>"),
        1,
    );
    let xsw8 = response.replace(
        &signed,
        &format!("{evil_open}{sig_holding_unsigned}{evil_rest}"),
    );

    for (case, cfg, xml) in [
        ("XSW1", &response_cfg, &xsw1),
        ("XSW2", &response_cfg, &xsw2),
        ("XSW3", &assertion_cfg, &xsw3),
        ("XSW4", &assertion_cfg, &xsw4),
        ("XSW5", &assertion_cfg, &xsw5),
        ("XSW6", &assertion_cfg, &xsw6),
        ("XSW7", &assertion_cfg, &xsw7),
        ("XSW8", &assertion_cfg, &xsw8),
    ] {
        assert!(
            xml.contains("ceo@corp.example"),
            "{case}: fixture plants the victim"
        );
        assert_refused(cfg, xml, case);
    }
}

// ── Issuer binding and encrypted content ─────────────────────────────────────

/// A Response for mallory whose assertion is rewritten by `rewrite` and then
/// signed by the IdP, so the rewrite is covered by a valid signature.
fn response_with_signed_rewritten_assertion(
    idp_key: &RsaSigningKey,
    rewrite: impl Fn(&str) -> String,
) -> String {
    let response = xsw_response_for_mallory(&BTreeMap::new());
    let assertion = extract_assertion(&response);
    let rewritten = rewrite(&with_saml_ns(&assertion));
    let signed = sign_element(rewritten.as_bytes(), "_signed1", idp_key).expect("sign assertion");
    let signed = String::from_utf8(signed).expect("utf8");
    response.replace(&assertion, &signed)
}

fn assert_rejected_with(
    idp_cfg: &SamlIdpConfig,
    xml: &str,
    case: &str,
    want: fn(&IdentityError) -> bool,
) {
    match xsw_complete(idp_cfg, xml) {
        SamlSpOutcome::Rejected { error } => {
            assert!(
                want(&error),
                "{case}: rejected for the wrong reason: {error:?}"
            );
        }
        SamlSpOutcome::Accepted { identity, .. } => panic!(
            "{case}: accepted as external_sub={:?} email={:?}",
            identity.external_sub, identity.email
        ),
    }
}

/// The Response names the registered IdP, but the signed assertion's own
/// `<Issuer>` names another entity: the assertion is refused.
#[test]
fn sp_rejects_assertion_issued_by_another_entity() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);

    // Control: the same construction without the rewrite is accepted.
    let control = response_with_signed_rewritten_assertion(&idp_key, str::to_string);
    xsw_assert_accepted_as_mallory(&idp_cfg, &control, "unchanged assertion");

    let xml = response_with_signed_rewritten_assertion(&idp_key, |a| {
        let idp_issuer = "<saml:Issuer>https://idp.example</saml:Issuer>";
        assert!(a.contains(idp_issuer), "assertion names the IdP");
        a.replacen(
            idp_issuer,
            "<saml:Issuer>https://other-idp.example</saml:Issuer>",
            1,
        )
    });
    assert!(
        xml.contains("<saml:Issuer>https://idp.example</saml:Issuer><samlp:Status>"),
        "the Response-level Issuer still names the registered IdP"
    );
    assert_rejected_with(&idp_cfg, &xml, "assertion issuer mismatch", |e| {
        matches!(e, IdentityError::Saml(SamlError::IssuerMismatch))
    });
}

/// A signed assertion that carries its subject as an `<EncryptedID>` and no
/// `<NameID>` is refused rather than accepted with an empty subject.
#[test]
fn sp_rejects_encrypted_subject() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);

    let xml = response_with_signed_rewritten_assertion(&idp_key, |a| {
        let start = a.find("<saml:NameID").expect("NameID start");
        let end = a.find("</saml:NameID>").expect("NameID end") + "</saml:NameID>".len();
        format!(
            "{}<saml:EncryptedID><xenc:EncryptedData \
             xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID>{}",
            &a[..start],
            &a[end..]
        )
    });
    assert!(!xml.contains("<saml:NameID"), "fixture carries no NameID");
    assert_rejected_with(&idp_cfg, &xml, "encrypted subject", |e| {
        matches!(e, IdentityError::Saml(SamlError::Parse { .. }))
    });
}

const ENCRYPTED_ASSERTION: &str = "<saml:EncryptedAssertion><xenc:EncryptedData \
     xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedAssertion>";

/// A Response whose only assertion is an `<EncryptedAssertion>` is refused.
#[test]
fn sp_rejects_encrypted_assertion_only() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", false);
    let response = xsw_response_for_mallory(&BTreeMap::new());
    let assertion = extract_assertion(&response);
    let unsigned = response.replace(&assertion, ENCRYPTED_ASSERTION);
    let xml = String::from_utf8(sign_element(unsigned.as_bytes(), "_r1", &idp_key).expect("sign"))
        .expect("utf8");
    // No cleartext assertion to consume: refused before any field is read.
    assert_rejected_with(&idp_cfg, &xml, "encrypted assertion only", |e| {
        matches!(
            e,
            IdentityError::Saml(SamlError::Signature | SamlError::Parse { .. })
        )
    });
}

/// An `<EncryptedAssertion>` beside a signed cleartext assertion is refused
/// rather than ignored.
#[test]
fn sp_rejects_encrypted_assertion_beside_a_signed_assertion() {
    let idp_key = RsaSigningKey::generate("test-idp", 365).expect("idp key");
    let idp_cfg = xsw_idp_config(&idp_key, "NameID", true);
    let control = response_with_signed_rewritten_assertion(&idp_key, str::to_string);
    xsw_assert_accepted_as_mallory(&idp_cfg, &control, "unchanged assertion");

    let xml = control.replacen(
        "</samlp:Response>",
        &format!("{ENCRYPTED_ASSERTION}</samlp:Response>"),
        1,
    );
    assert_rejected_with(&idp_cfg, &xml, "encrypted assertion beside", |e| {
        matches!(e, IdentityError::Saml(SamlError::Parse { .. }))
    });
}

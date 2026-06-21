//! Phase D.7 integration tests — SPIFFE / workload identity.
//!
//! Covers:
//! - D.7 SPIFFE ID registration (CRUD)
//! - D.7 SPIFFE ID format validation
//! - D.7 Lookup by SPIFFE ID
//! - D.7 Deletion removes mapping
//! - D.7 Adversarial: invalid SPIFFE URI rejected
//! - D.7 Adversarial: duplicate mapping rejected
//! - D.7 Security (HEA-1438): DER extraction uses ASN.1 SAN, not byte scanning
//! - D.7 Security (HEA-1444): expired SVID rejected with SpiffeCertExpired

mod common;

use common::TestHarness;
use hearth::core::RealmId;
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest, IdentityError,
    RegisterSpiffeIdRequest,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_realm(h: &TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("spiffe-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_agent(h: &TestHarness, realm_id: &RealmId) -> hearth::core::AgentId {
    let owner = h
        .identity()
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("spiffe-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "SPIFFE Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");
    h.identity()
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: "spiffe-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec!["urn:hearth:workload".to_string()],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

fn spiffe_id(agent_id: &hearth::core::AgentId) -> String {
    format!("spiffe://example.com/agent/{}", agent_id.as_uuid())
}

// ── D.7.1: Register SPIFFE mapping ───────────────────────────────────────────

#[tokio::test]
async fn register_spiffe_mapping_returns_record() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    let mapping = h
        .identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register SPIFFE mapping");

    assert_eq!(mapping.spiffe_id, sid);
    assert_eq!(mapping.agent_id, agent_id);
    assert_eq!(mapping.trust_domain, "example.com");
}

// ── D.7.2: Lookup by SPIFFE ID ───────────────────────────────────────────────

#[tokio::test]
async fn lookup_agent_by_spiffe_id_returns_mapped_agent() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register");

    let found = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, &sid)
        .expect("lookup")
        .expect("must find agent");

    assert_eq!(found, agent_id, "lookup must return the registered agent");
}

// ── D.7.3: Lookup of unknown SPIFFE ID returns None ──────────────────────────

#[tokio::test]
async fn lookup_unknown_spiffe_id_returns_none() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);

    let result = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, "spiffe://example.com/agent/not-registered")
        .expect("lookup must not fail");

    assert!(result.is_none(), "unknown SPIFFE ID must return None");
}

// ── D.7.4: Delete SPIFFE mapping ─────────────────────────────────────────────

#[tokio::test]
async fn delete_spiffe_mapping_removes_the_mapping() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register");

    h.identity()
        .delete_spiffe_mapping(&realm_id, &agent_id)
        .expect("delete");

    let result = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, &sid)
        .expect("lookup after delete");

    assert!(result.is_none(), "mapping must not exist after deletion");
}

// ── D.7.5: Adversarial — duplicate mapping rejected ─────────────────────────

#[tokio::test]
async fn duplicate_spiffe_mapping_is_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("first registration succeeds");

    let err = h
        .identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid,
                trust_bundle_pem: None,
            },
        )
        .expect_err("duplicate registration must be rejected");

    assert!(
        matches!(err, IdentityError::SpiffeMappingConflict),
        "expected SpiffeMappingConflict, got {err:?}"
    );
}

// ── D.7.6: Adversarial — invalid SPIFFE ID format rejected ───────────────────

#[tokio::test]
async fn invalid_spiffe_id_format_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let invalid_ids = [
        "https://example.com/agent/123", // wrong scheme
        "spiffe://",                     // no domain or path
        "spiffe:///agent/123",           // empty trust domain
        "spiffe://example.com/user/123", // wrong path segment
    ];

    for invalid_id in invalid_ids {
        let err = h
            .identity()
            .register_spiffe_mapping(
                &realm_id,
                &RegisterSpiffeIdRequest {
                    agent_id: agent_id.clone(),
                    spiffe_id: invalid_id.to_string(),
                    trust_bundle_pem: None,
                },
            )
            .expect_err(&format!(
                "invalid SPIFFE ID '{invalid_id}' must be rejected"
            ));

        assert!(
            matches!(err, IdentityError::SpiffeIdInvalid { .. }),
            "expected SpiffeIdInvalid for '{invalid_id}', got {err:?}"
        );
    }
}

// ── D.7.8: Adversarial — cross-agent SPIFFE ID squatting blocked ─────────────
//
// Attack: Agent B registers the same SPIFFE ID already owned by Agent A,
// attempting to overwrite the primary mapping and impersonate Agent A.
// Regression for [HEA-1437](/HEA/issues/HEA-1437) — primary-key guard.

#[tokio::test]
async fn cross_agent_spiffe_id_squatting_blocked() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);

    // Legitimate owner registers first.
    let owner_id = make_agent(&h, &realm_id);
    // Attacker agent attempts to squat on the owner's SPIFFE ID.
    let squatter_id = make_agent(&h, &realm_id);

    let shared_sid = spiffe_id(&owner_id);
    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: owner_id.clone(),
                spiffe_id: shared_sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("owner registration must succeed");

    // Squatter attempts to register the same SPIFFE ID.
    let err = h
        .identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: squatter_id.clone(),
                spiffe_id: shared_sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect_err("cross-agent squatting must be rejected");

    assert!(
        matches!(err, IdentityError::SpiffeMappingConflict),
        "expected SpiffeMappingConflict, got {err:?}"
    );

    // Primary mapping must be unchanged — lookup returns the owner, not the squatter.
    let found = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, &shared_sid)
        .expect("lookup must not error")
        .expect("owner mapping must still exist");

    assert_eq!(
        found, owner_id,
        "lookup must return the original owner after squatting attempt"
    );
}

// ── D.7.7: Delete nonexistent mapping returns error ──────────────────────────

#[tokio::test]
async fn delete_nonexistent_spiffe_mapping_returns_error() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let err = h
        .identity()
        .delete_spiffe_mapping(&realm_id, &agent_id)
        .expect_err("deleting nonexistent mapping must fail");

    assert!(
        matches!(err, IdentityError::SpiffeMappingNotFound),
        "expected SpiffeMappingNotFound, got {err:?}"
    );
}

// ── D.7-SECURITY (HEA-1444): Expired SVID must be rejected ───────────────────

/// Generates a self-signed DER cert with `spiffe_id` as a URI-type SAN but
/// with a validity window entirely in the past (1970-01-01 to 1971-01-01).
fn cert_der_expired_spiffe_uri_san(spiffe_id: &str) -> Vec<u8> {
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("valid IA5 SPIFFE URI"),
    )];
    // Validity window entirely in the past so the cert is always expired.
    params.not_before = time::OffsetDateTime::UNIX_EPOCH;
    params.not_after =
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(365);
    let key = rcgen::KeyPair::generate().expect("keygen");
    params.self_signed(&key).expect("self-signed").der().to_vec()
}

/// An expired SVID must return `SpiffeCertExpired`, not be silently accepted.
///
/// Regression for the no-op stub in `check_cert_not_expired` fixed by
/// [HEA-1444](/HEA/issues/HEA-1444).
#[tokio::test]
async fn expired_svid_is_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    // Register the mapping so the only failure path is cert expiry.
    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register SPIFFE mapping");

    let der = cert_der_expired_spiffe_uri_san(&sid);

    let err = h
        .identity()
        .validate_spiffe_svid(&realm_id, &der)
        .expect_err("expired SVID must be rejected");

    assert!(
        matches!(err, IdentityError::SpiffeCertExpired),
        "expected SpiffeCertExpired, got {err:?}"
    );
}

// ── D.7-SECURITY (HEA-1438): DER extraction must use ASN.1 SAN ───────────────
//
// Regression for Finding D.7-7 from [HEA-1435](/HEA/issues/HEA-1435):
// The naive byte-scanner could be fooled by `spiffe://` in Subject CN or other
// non-SAN fields. These tests encode the attack and verify the ASN.1-aware fix.

/// Generates a self-signed DER cert with `spiffe_id` in the Subject CN only —
/// no URI SAN is added. The old byte-scanner would accept this; the ASN.1
/// parser must reject it because CN is not a valid SPIFFE identity carrier.
fn cert_der_spiffe_in_cn_only(spiffe_id: &str) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, spiffe_id);
    // Deliberately no URI SAN.
    let key = rcgen::KeyPair::generate().expect("keygen");
    params
        .self_signed(&key)
        .expect("self-signed")
        .der()
        .to_vec()
}

/// Generates a self-signed DER cert with `spiffe_id` as a URI-type SAN.
fn cert_der_spiffe_uri_san(spiffe_id: &str) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("valid IA5 SPIFFE URI"),
    )];
    let key = rcgen::KeyPair::generate().expect("keygen");
    params
        .self_signed(&key)
        .expect("self-signed")
        .der()
        .to_vec()
}

/// Generates a self-signed DER cert with two SPIFFE URI SANs (ambiguous identity).
fn cert_der_two_spiffe_uri_sans(id1: &str, id2: &str) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params.subject_alt_names = vec![
        rcgen::SanType::URI(rcgen::Ia5String::try_from(id1).expect("valid IA5 SPIFFE URI")),
        rcgen::SanType::URI(rcgen::Ia5String::try_from(id2).expect("valid IA5 SPIFFE URI")),
    ];
    let key = rcgen::KeyPair::generate().expect("keygen");
    params
        .self_signed(&key)
        .expect("self-signed")
        .der()
        .to_vec()
}

/// Attack: cert with `spiffe://` in CN (not SAN) must be rejected.
///
/// Before [HEA-1438](/HEA/issues/HEA-1438) the byte-scanner would find
/// `spiffe://` in CN bytes and return the attacker-controlled string as the
/// identity. The ASN.1-aware parser correctly sees no URI SAN and rejects the
/// cert.
#[tokio::test]
async fn spiffe_in_cn_not_san_is_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let victim_sid = spiffe_id(&agent_id);

    let der = cert_der_spiffe_in_cn_only(&victim_sid);

    let err = h
        .identity()
        .validate_spiffe_svid(&realm_id, &der)
        .expect_err("cert with SPIFFE ID only in CN must be rejected");

    assert!(
        matches!(err, IdentityError::SpiffeCertInvalid { .. }),
        "expected SpiffeCertInvalid, got {err:?}"
    );
}

/// Happy path: cert with `spiffe://` in a proper URI SAN is accepted when a
/// matching SPIFFE mapping exists.
#[tokio::test]
async fn spiffe_in_proper_uri_san_is_accepted() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register SPIFFE mapping");

    let der = cert_der_spiffe_uri_san(&sid);

    let found = h
        .identity()
        .validate_spiffe_svid(&realm_id, &der)
        .expect("cert with valid URI SAN must be accepted");

    assert_eq!(
        found, agent_id,
        "validate_spiffe_svid must return the registered agent"
    );
}

/// Attack: cert with multiple SPIFFE URI SANs is ambiguous and must be rejected.
///
/// SPIFFE requires exactly one URI SAN per SVID. Accepting a cert with two
/// SPIFFE URIs would allow an attacker to smuggle a second identity into a
/// cert that passes trust-anchor validation on the first.
#[tokio::test]
async fn multiple_spiffe_uri_sans_is_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid1 = spiffe_id(&agent_id);
    let sid2 = format!("spiffe://other.example.com/agent/{}", uuid::Uuid::new_v4());

    let der = cert_der_two_spiffe_uri_sans(&sid1, &sid2);

    let err = h
        .identity()
        .validate_spiffe_svid(&realm_id, &der)
        .expect_err("cert with multiple SPIFFE URI SANs must be rejected");

    assert!(
        matches!(err, IdentityError::SpiffeCertInvalid { .. }),
        "expected SpiffeCertInvalid for ambiguous cert, got {err:?}"
    );
}

//! Adversarial tests for A-29: federation hardening.
//!
//! Covers the four sub-features of plan §4.1 A-29:
//!
//! - **A-29a** — RFC 9207 `iss` authorization-response parameter validation
//!   (IdP-mixup defense).
//! - **A-29b** — Unverified-email account-link policy: `email_verified=false`
//!   must never auto-link to an existing local user regardless of `LinkMode`.
//! - **A-29c** — SAML signature-wrapping rejection: multiple assertions and
//!   Reference-URI/element-ID mismatch are both rejected.
//! - **A-29d** — SAML entity-expansion and XXE regression guard (complements
//!   the A-35b/c tests in `abuse_scim_saml.rs`; this file covers the
//!   `find_element_range` cap used by signature verification).

use hearth::abuse::MAX_SAML_XML_EVENTS;
use hearth::core::{IdpId, Timestamp};
use hearth::identity::federation::saml::response::{
    build_response_xml, extract_and_validate_assertion, parse_response, ResponseBuilder,
    ValidateParams,
};
use hearth::identity::federation::saml::xml::find_element_range;
use hearth::identity::federation::types::ExternalIdentity;
use hearth::identity::federation::verify_iss_param;
use hearth::identity::IdentityError;

use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// A-29a — RFC 9207 `iss` parameter
// ─────────────────────────────────────────────────────────────────────────────

/// Correct `iss` value must be accepted.
#[test]
fn a29a_iss_param_matches_expected_ok() {
    verify_iss_param(
        Some("https://accounts.google.com"),
        "https://accounts.google.com",
    )
    .expect("matching iss must be accepted");
}

/// Mismatched `iss` value must be rejected (IdP-mixup attack vector).
#[test]
fn a29a_iss_param_mismatch_rejected() {
    let result = verify_iss_param(
        Some("https://attacker.example"),
        "https://accounts.google.com",
    );
    assert!(
        matches!(result, Err(IdentityError::FederationIdpMixup)),
        "mismatched iss must produce FederationIdpMixup, got: {result:?}"
    );
}

/// Absent `iss` must be accepted — fail-open (not all authorization servers
/// include it; RFC 9207 makes it optional for the AS side).
#[test]
fn a29a_iss_param_absent_allowed() {
    verify_iss_param(None, "https://accounts.google.com")
        .expect("absent iss must be allowed (fail-open)");
}

/// `iss` must be compared exactly — trailing slashes and near-matches must
/// not satisfy the check.
#[test]
fn a29a_iss_param_trailing_slash_rejected() {
    let result = verify_iss_param(
        Some("https://accounts.google.com/"),
        "https://accounts.google.com",
    );
    assert!(
        matches!(result, Err(IdentityError::FederationIdpMixup)),
        "trailing-slash near-match must be rejected: {result:?}"
    );
}

/// Empty string `iss` must not match a non-empty issuer.
#[test]
fn a29a_iss_param_empty_string_rejected() {
    let result = verify_iss_param(Some(""), "https://accounts.google.com");
    assert!(
        matches!(result, Err(IdentityError::FederationIdpMixup)),
        "empty iss must be rejected: {result:?}"
    );
}

/// `FederationIdpMixup` must have a non-empty, human-readable Display.
#[test]
fn a29a_federation_idp_mixup_display() {
    let display = format!("{}", IdentityError::FederationIdpMixup);
    assert!(!display.is_empty(), "FederationIdpMixup must have Display");
    assert!(
        display.to_lowercase().contains("mixup") || display.to_lowercase().contains("iss"),
        "FederationIdpMixup Display must mention 'mixup' or 'iss': {display}"
    );
}

/// `FederationIdpMixup` must carry the HEARTH_FEDERATION_IDP_MIXUP error code.
#[test]
fn a29a_federation_idp_mixup_wire_error_code() {
    assert_eq!(
        IdentityError::FederationIdpMixup.wire_error_code(),
        Some("HEARTH_FEDERATION_IDP_MIXUP"),
        "FederationIdpMixup must carry the correct wire error code"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-29b — Unverified-email link policy
// ─────────────────────────────────────────────────────────────────────────────

fn sample_identity(verified: bool, email: &str) -> ExternalIdentity {
    ExternalIdentity {
        idp_id: IdpId::generate(),
        external_sub: "sub-adversarial-test".to_string(),
        email: email.to_string(),
        email_verified: verified,
        display_name: "Adversary".to_string(),
        first_name: String::new(),
        last_name: String::new(),
        picture_url: None,
    }
}

/// When `email_verified = false`, `is_linkable_by_email()` MUST return false,
/// preventing any email-based auto-link regardless of realm `LinkMode`.
#[test]
fn a29b_unverified_email_not_linkable_by_email() {
    let identity = sample_identity(false, "victim@example.com");
    assert!(
        !identity.is_linkable_by_email(),
        "email_verified=false must block email-based linking"
    );
}

/// Verified email with a non-empty address is linkable.
#[test]
fn a29b_verified_email_is_linkable_by_email() {
    let identity = sample_identity(true, "user@example.com");
    assert!(
        identity.is_linkable_by_email(),
        "email_verified=true with non-empty email must be linkable"
    );
}

/// Verified but empty email is not linkable (no address to match on).
#[test]
fn a29b_verified_empty_email_not_linkable() {
    let identity = sample_identity(true, "");
    assert!(
        !identity.is_linkable_by_email(),
        "verified but empty email must not be linkable"
    );
}

/// Adversarial: attacker sets `email_verified = false` with a known victim
/// email address — must not be linkable.
#[test]
fn a29b_adversarial_unverified_victim_email_blocked() {
    // An upstream IdP controlled by the attacker returns a token with
    // email="victim@corp.com" but email_verified=false.  The attacker
    // hopes this links to the existing corp account.
    let attacker_identity = sample_identity(false, "victim@corp.com");
    assert!(
        !attacker_identity.is_linkable_by_email(),
        "unverified email must not be linkable regardless of the email value"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-29c — SAML signature-wrapping rejection
// ─────────────────────────────────────────────────────────────────────────────

fn sample_builder_params() -> (String, BTreeMap<String, Vec<String>>) {
    let attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_resp1",
        in_response_to: Some("_req1"),
        issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
        destination: "https://sp.example/acs",
        issuer: "https://idp.example",
        audience: "https://sp.example",
        assertion_id: "_assert1",
        subject_name_id: "alice@example.com",
        subject_name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        session_index: "sess1",
        not_before: Timestamp::from_micros(1_699_999_990 * 1_000_000),
        not_on_or_after: Timestamp::from_micros(1_700_000_300 * 1_000_000),
        attributes: &attrs,
    });
    (xml, attrs)
}

/// A response with more than one assertion MUST be rejected (multi-assertion
/// XSW class: attacker injects a second unsigned assertion into the document).
#[test]
fn a29c_saml_multiple_assertions_rejected() {
    let (xml, _) = sample_builder_params();
    // Inject a second (evil) assertion after the first by splicing XML.
    // The evil assertion shares the same <Assertion> element name but has a
    // different ID and no signature.
    let evil = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil_assert">
        <saml:Issuer>https://evil.idp</saml:Issuer>
        <saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
    </saml:Assertion>"#;
    // Insert before the closing </samlp:Response> tag.
    let crafted = xml.replace("</samlp:Response>", &format!("{evil}</samlp:Response>"));

    let resp = parse_response(crafted.as_bytes()).expect("parse must succeed for this craft");
    let result = extract_and_validate_assertion(
        &resp,
        &ValidateParams {
            sp_entity_id: "https://sp.example",
            acs_url: "https://sp.example/acs",
            idp_entity_id: "https://idp.example",
            expected_in_response_to: None,
            now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            clock_skew_secs: 60,
        },
    );
    assert!(
        result.is_err(),
        "multiple assertions must be rejected, got Ok"
    );
    let err_msg = result.expect_err("must error").to_string();
    assert!(
        err_msg.to_lowercase().contains("multiple")
            || err_msg.to_lowercase().contains("assert")
            || err_msg.to_lowercase().contains("parse"),
        "error must mention multiple assertions: {err_msg}"
    );
}

/// Adversarial: signature Reference URI that does not match the enclosing
/// element's ID must be rejected by `find_element_range` + signature checking.
///
/// This exercises the XML signature wrapping (XSW) defense in `signature.rs`:
/// `verify_signed_element` extracts the element ID, builds `expected_uri =
/// "#<id>"`, and compares it to the Reference URI in the `<ds:Signature>`.
/// A mismatch returns `SamlSignature`.
///
/// We validate the defense indirectly here: `find_element_range` is given an
/// element ID that does NOT exist in the document; it must return `None`,
/// which `verify_signed_element` maps to `SamlSignature`.
#[test]
fn a29c_saml_find_element_range_nonexistent_id_returns_none() {
    let (xml, _) = sample_builder_params();
    // Search for an ID that is not present in the document.
    let range = find_element_range(
        xml.as_bytes(),
        hearth::identity::federation::saml::xml::ns::SAML,
        "Assertion",
        Some("_id_that_does_not_exist"),
    )
    .expect("find_element_range must not error on valid XML");
    assert!(
        range.is_none(),
        "find_element_range must return None for a non-existent ID"
    );
}

/// `find_element_range` must find an assertion by its exact ID.
#[test]
fn a29c_saml_find_element_range_finds_correct_assertion() {
    let (xml, _) = sample_builder_params();
    let range = find_element_range(
        xml.as_bytes(),
        hearth::identity::federation::saml::xml::ns::SAML,
        "Assertion",
        Some("_assert1"),
    )
    .expect("find_element_range must not error");
    assert!(
        range.is_some(),
        "find_element_range must find the assertion by its ID"
    );
    let (start, end) = range.expect("range must be Some after is_some assert");
    let found = &xml.as_bytes()[start..end];
    let found_str = std::str::from_utf8(found).expect("valid utf8");
    assert!(
        found_str.contains("_assert1"),
        "found element must contain the expected assertion ID"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-29d — SAML entity-expansion cap via `find_element_range` (regression)
// ─────────────────────────────────────────────────────────────────────────────

/// `find_element_range` uses the same `MAX_SAML_XML_EVENTS` constant as
/// `parse_response` (tested in `abuse_scim_saml.rs::a35b`), providing
/// belt-and-suspenders event-cap protection on the signature-verification path.
///
/// This sentinel asserts the shared constant value so any change forces an
/// explicit update of ABUSE.md §A-29d and §A-35b together.
#[test]
fn a29d_saml_entity_expansion_cap_constant_sentinel() {
    assert_eq!(
        MAX_SAML_XML_EVENTS, 10_000,
        "MAX_SAML_XML_EVENTS changed — update ABUSE.md §A-29d and §A-35b"
    );
}

/// DOCTYPE in a document passed to `find_element_range` must be rejected
/// (XXE regression guard complementing `abuse_scim_saml.rs::a35c`).
#[test]
fn a29d_saml_doctype_in_find_element_range_rejected() {
    let xml = b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\
          <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
          ID=\"_r1\"></samlp:Response>";
    let result = find_element_range(
        xml,
        hearth::identity::federation::saml::xml::ns::SAML,
        "Assertion",
        None,
    );
    assert!(
        result.is_err(),
        "DOCTYPE in XML must be rejected by find_element_range"
    );
}

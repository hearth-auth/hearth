//! Adversarial tests for A-35: SCIM PATCH bulk-op cap and SAML XML event cap.
//!
//! Covers:
//! - A-35a: SCIM PATCH `Operations` count ≤ `MAX_SCIM_OPERATIONS` (currently 1 000)
//! - A-35b: SAML response XML event cap ≤ `MAX_SAML_XML_EVENTS` (currently 10 000)
//! - A-35c: DOCTYPE/XXE continues to be rejected (regression guard)

use hearth::abuse::{MAX_SAML_XML_EVENTS, MAX_SCIM_OPERATIONS};
use hearth::identity::federation::saml::response::parse_response;
use hearth::identity::federation::saml::SamlError;
use hearth::identity::IdentityError;

// ─────────────────────────────────────────────────────────────────────────────
// A-35a — SCIM PATCH operations cap
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the constant is the expected sentinel value so tests that build
/// payloads from it stay accurate.
#[test]
fn a35a_max_scim_operations_is_1000() {
    assert_eq!(
        MAX_SCIM_OPERATIONS, 1_000,
        "constant changed — update all dependent tests"
    );
}

// NOTE: the handler-level enforcement of `MAX_SCIM_OPERATIONS` — a PATCH whose
// `Operations` array exceeds the cap is rejected with 413 *before* any op is
// applied — is exercised end-to-end by
// `scim_bearer_auth::scim_patch_over_operation_cap_rejected`. The former
// constant-only `a35a_scim_ops_constant_exported` test here gave false
// confidence (it asserted the constant but never the enforcement) and was
// removed in favour of that real integration test.

// ─────────────────────────────────────────────────────────────────────────────
// A-35b — SAML XML event cap
// ─────────────────────────────────────────────────────────────────────────────

/// A well-formed minimal SAML AuthnResponse is parsed without hitting the cap.
#[test]
fn a35b_normal_saml_response_parses_without_hitting_cap() {
    // A real SAML response has O(20) elements — well within the 10 000 cap.
    let xml = include_str!("fixtures/saml_authn_response_minimal.xml");
    let result = parse_response(xml.as_bytes());
    assert!(
        result.is_ok(),
        "minimal SAML response must parse without hitting event cap: {result:?}"
    );
}

/// A crafted SAML response with > MAX_SAML_XML_EVENTS elements must be rejected.
#[test]
fn a35b_oversized_saml_xml_rejected() {
    // Build an XML document with more elements than MAX_SAML_XML_EVENTS inside
    // a dummy wrapper. We wrap in a minimal Response skeleton so the reader
    // gets to the element loop; the count limit fires well before any semantic
    // parsing.
    let inner: String =
        "<saml:AttributeValue>x</saml:AttributeValue>".repeat(MAX_SAML_XML_EVENTS + 1);
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
             ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
          <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
          {inner}
        </samlp:Response>"#
    );
    let result = parse_response(xml.as_bytes());
    assert!(
        result.is_err(),
        "oversized SAML XML must be rejected, got Ok"
    );
    let err = result.expect_err("result must be Err for oversized SAML XML");
    // The event-cap trip is a *parse* rejection, never a semantic variant that
    // might mask the cap regressing into unbounded expansion.
    assert!(
        matches!(err, IdentityError::Saml(SamlError::Parse { .. })),
        "oversized SAML XML must reject as SamlError::Parse, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("exceed") || msg.contains("limit") || msg.contains("parse"),
        "error must mention the limit: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-35c — DOCTYPE / XXE regression guard
// ─────────────────────────────────────────────────────────────────────────────

/// DOCTYPE declarations are still rejected (regression guard — this was
/// implemented in the original xml.rs hardening and must not regress).
#[test]
fn a35c_doctype_in_saml_response_rejected() {
    let xml = b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\
                <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                ID=\"_r1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\">\
                </samlp:Response>";
    let result = parse_response(xml);
    let err = result.expect_err("DOCTYPE in SAML response must be rejected");
    // XXE/DOCTYPE must reject as a *Parse* error specifically — the previous
    // `let _ = err` was vacuous and would have passed even if the guard had
    // regressed into silently accepting (and expanding) the DOCTYPE.
    assert!(
        matches!(err, IdentityError::Saml(SamlError::Parse { .. })),
        "DOCTYPE/XXE must reject as SamlError::Parse, got: {err:?}"
    );
}

/// Positive control for the XXE guard: the *same* Response skeleton WITHOUT a
/// DOCTYPE parses cleanly. Paired with `a35c_doctype_in_saml_response_rejected`
/// this proves the rejection is caused by the DOCTYPE, not the skeleton itself.
#[test]
fn a35c_response_without_doctype_parses() {
    let xml = b"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                ID=\"_r1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\">\
                <samlp:Status><samlp:StatusCode \
                Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>\
                </samlp:Response>";
    parse_response(xml).expect("clean Response skeleton (no DOCTYPE) must parse");
}

/// A DOCTYPE that declares an external entity and *references* it in the body
/// (classic file-disclosure XXE payload) must reject as Parse — the external
/// entity must never be resolved or expanded.
#[test]
fn a35c_external_entity_reference_rejected() {
    let xml = b"<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\
                <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
                ID=\"_r1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\">\
                <samlp:Status><samlp:StatusCode Value=\"&xxe;\"/></samlp:Status>\
                </samlp:Response>";
    let err = parse_response(xml).expect_err("external-entity XXE must be rejected");
    assert!(
        matches!(err, IdentityError::Saml(SamlError::Parse { .. })),
        "external-entity XXE must reject as SamlError::Parse, got: {err:?}"
    );
}

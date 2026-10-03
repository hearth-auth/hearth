//! Fuzz target for SAML 2.0 XML parsing.
//!
//! Feeds arbitrary bytes to every SAML XML parser in the stack — these are
//! the highest-risk parsers in Hearth because SAML XML arrives from external
//! IdPs and is therefore fully attacker-controlled. Each parser must never
//! panic, only return `Ok` or `Err`.
//!
//! Parsers exercised (Hearth is a SAML service provider only; the IdP-side
//! request and logout parsers were removed in 3.0.0):
//! - `parse_response`     — `<samlp:Response>` + `<saml:Assertion>` (ACS path)
//! - `parse_idp_metadata` — `<md:EntityDescriptor>` (metadata exchange)
//!
//! The seeds keep their AuthnRequest and logout shapes: to these parsers they
//! are hostile, near-miss documents, which is exactly what fuzzing wants.
//!
//! Why each of these matters for security:
//! - Signature-wrapping attacks depend on the parser accepting an envelope
//!   with a signed subtree and an unsigned outer element. Fuzzing exercises
//!   the parser's subtree selection logic under adversarial XML shapes.
//! - Namespace prefix confusion (e.g. binding a SAML namespace to an
//!   attacker-chosen prefix) can confuse XML parsers into processing a
//!   different element than the signature covers.
//! - XXE / entity expansion panics are the classic XML-parsing footgun; while
//!   Hearth uses `quick-xml` which does not resolve external entities by
//!   default, confirming this under fuzzing is necessary.

#![no_main]

use hearth::identity::federation::saml::{parse_idp_metadata, parse_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both parsers consume the same raw bytes. Each must handle arbitrary
    // input — including non-UTF-8, deeply nested elements, namespace
    // confusion, and truncated input — without panicking.
    let _ = parse_response(data);
    let _ = parse_idp_metadata(data);
});

//! Fuzz target for the OIDC/OAuth **remote-document** deserializers.
//!
//! ## What changed and why (audit 2026-09-21, task 23.13)
//!
//! The previous version of this target ran four statements, of which two were
//! `serde_json::from_slice::<serde_json::Value>` / `from_str::<Value>` — i.e.
//! it spent half its budget fuzzing `serde_json` rather than Hearth — and a
//! third (`decode_claims_unverified`) duplicated `jwt_parse.rs` verbatim. Its
//! doc comment said "Attempt to parse as `AuthorizationRequest` JSON";
//! `AuthorizationRequest` (`src/identity/oidc.rs:820`) derives only
//! `Debug, Clone`, so no serde path to it exists and none ever ran.
//!
//! What it covers now is the set of OIDC documents Hearth deserializes from a
//! **remote party**, every one of which is genuinely attacker-influenced and
//! none of which any other fuzz target touched:
//!
//! | Type | Where the bytes come from |
//! |---|---|
//! | [`OidcDiscoveryDocument`] | a federated IdP's `/.well-known/openid-configuration` |
//! | [`JwksDocument`] / [`Jwk`] | that IdP's `jwks_uri` — the keys signatures are checked against |
//! | [`JarClaims`] | an RFC 9101 request object, supplied by the client |
//! | [`IntrospectionResponse`] | an upstream AS's introspection reply |
//! | [`TokenClaims`] | the claims segment of any JWT (see the reshaping below) |
//!
//! A JWKS parser is the highest-value of these: it runs *before* any signature
//! is verified, on bytes fetched over the network from a host the operator
//! named but does not control.

#![no_main]

use libfuzzer_sys::fuzz_target;

use hearth::identity::{
    IntrospectionResponse, JarClaims, Jwk, JwksDocument, OidcDiscoveryDocument, TokenClaims,
};

fuzz_target!(|data: &[u8]| {
    // Raw bytes: covers invalid UTF-8, truncation, and deep nesting for every
    // remote document. `from_slice` is what the HTTP client path actually uses.
    let _ = serde_json::from_slice::<OidcDiscoveryDocument>(data);
    let _ = serde_json::from_slice::<JwksDocument>(data);
    let _ = serde_json::from_slice::<Jwk>(data);
    let _ = serde_json::from_slice::<JarClaims>(data);
    let _ = serde_json::from_slice::<IntrospectionResponse>(data);
    let _ = serde_json::from_slice::<TokenClaims>(data);

    // A JWKS carrying the fuzz bytes inside a key: reaches the per-key field
    // decoders behind the document wrapper, which a top-level parse of random
    // bytes never gets to because the outer `{"keys":[...]}` shape fails first.
    let lossy = String::from_utf8_lossy(data);
    let escaped = serde_json::to_string(lossy.as_ref()).unwrap_or_else(|_| "\"\"".to_string());
    let wrapped = format!(
        r#"{{"keys":[{{"kty":{escaped},"crv":{escaped},"x":{escaped},"kid":{escaped},"alg":{escaped},"use":{escaped}}}]}}"#
    );
    let _ = serde_json::from_str::<JwksDocument>(&wrapped);
});

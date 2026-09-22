//! The federation egress path is SSRF-guarded (audit 2026-08-28 §4.6#2).
//!
//! A federation connector's `jwks_uri`, `token_endpoint` and
//! `userinfo_endpoint` come from realm configuration and are dereferenced
//! server-side by Hearth, so they are SSRF sinks in exactly the way a webhook
//! destination or a `backchannel_logout_uri` is. Every one of those fetches
//! goes out through `UreqFederationTransport`, so these tests pin the guard at
//! that single production egress point: a loopback, RFC 1918, link-local
//! (cloud instance-metadata) or plaintext upstream must be refused *by the
//! guard*, before any socket is opened — not merely fail to connect.

use hearth::identity::federation::{
    FedHttpRequest, FederationHttpTransport, UreqFederationTransport,
};

/// Builds a GET request for `url`, the shape a JWKS or userinfo fetch takes.
fn get(url: &str) -> FedHttpRequest {
    FedHttpRequest {
        method: "GET",
        url: url.to_string(),
        headers: vec![],
        body: vec![],
        content_type: None,
    }
}

/// Asserts the transport refused `url` because of the SSRF guard, and says so
/// in the error the caller logs.
fn assert_refused(url: &str, request: &FedHttpRequest) {
    let err = UreqFederationTransport
        .send(request)
        .expect_err("the SSRF guard must refuse this upstream");
    let msg = err.to_string();
    assert!(
        msg.contains("SSRF guard"),
        "expected the SSRF guard to refuse {url}, got: {msg}"
    );
}

/// A loopback upstream must be refused by the guard, not left to the network.
#[test]
fn federation_fetch_refuses_a_loopback_upstream() {
    let url = "https://127.0.0.1:1/jwks";
    assert_refused(url, &get(url));
}

/// The cloud instance-metadata address is the canonical SSRF payoff; RFC 1918
/// hosts are the same class of internal destination.
#[test]
fn federation_fetch_refuses_link_local_and_private_upstreams() {
    for url in [
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/token",
        "https://192.168.1.1/userinfo",
    ] {
        assert_refused(url, &get(url));
    }
}

/// The token exchange is a POST and takes the same guard as a GET.
#[test]
fn federation_token_post_refuses_a_link_local_upstream() {
    let url = "https://169.254.169.254/token";
    assert_refused(
        url,
        &FedHttpRequest {
            method: "POST",
            url: url.to_string(),
            headers: vec![],
            body: b"grant_type=authorization_code".to_vec(),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        },
    );
}

/// A plaintext upstream never reaches the network — a `http://` endpoint can
/// be MITM'd and is refused for the same reason webhook egress refuses it.
#[test]
fn federation_fetch_refuses_a_non_https_upstream() {
    let url = "http://idp.example/jwks";
    assert_refused(url, &get(url));
}

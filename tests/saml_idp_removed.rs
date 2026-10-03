//! scope-trim-trusted-core, group 2: the SAML IdP side is removed.
//!
//! Hearth no longer issues SAML assertions to service providers. Every IdP
//! route must answer exactly like an unknown path, and the config key that
//! registered service providers must stop startup with a named error. The SP
//! side (Hearth consuming an upstream IdP) stays; its routes are checked
//! live as a control.

mod common;

use axum::http::Method;
use common::routes::{assert_route_absent, composed_app, SEEDED_REALM};
use hearth::config::{Config, ConfigError};

#[tokio::test]
async fn idp_routes_are_absent() {
    let app = composed_app();
    let base = format!("/ui/realms/{SEEDED_REALM}/saml");
    for (method, path) in [
        (Method::GET, format!("{base}/metadata")),
        (Method::GET, format!("{base}/sso")),
        (Method::POST, format!("{base}/sso")),
        (Method::GET, format!("{base}/sso/init")),
        (Method::GET, format!("{base}/slo-idp")),
        (Method::POST, format!("{base}/slo-idp")),
    ] {
        assert_route_absent(&app, method, &path).await;
    }
}

#[tokio::test]
#[should_panic(expected = "is still served")]
async fn sp_begin_route_is_still_served() {
    let app = composed_app();
    let path = format!("/ui/realms/{SEEDED_REALM}/federation/saml/begin");
    assert_route_absent(&app, Method::GET, &path).await;
}

const SP_REGISTRY_YAML: &str = "\
realms:
  acme:
    saml_service_providers:
      crm:
        entity_id: https://crm.example/sp
        acs_url: https://crm.example/acs
";

fn assert_names_removed_idp(err: &ConfigError) {
    assert!(
        matches!(err, ConfigError::RemovedKey { .. }),
        "expected RemovedKey, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("'realms.acme.saml_service_providers'"),
        "got: {msg}"
    );
    assert!(msg.contains("SAML IdP"), "got: {msg}");
    assert!(msg.contains("3.0.0"), "got: {msg}");
}

#[test]
fn service_provider_registry_key_stops_the_checked_loader() {
    let err = Config::from_yaml_str(SP_REGISTRY_YAML).expect_err("removed key must fail");
    assert_names_removed_idp(&err);
}

#[test]
fn service_provider_registry_key_stops_the_dev_loader() {
    let err = Config::from_yaml_str_unchecked(SP_REGISTRY_YAML).expect_err("removed key must fail");
    assert_names_removed_idp(&err);
}

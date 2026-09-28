//! RFC 8693 token-exchange targets come from the realm's YAML
//! `protected_resources`.
//!
//! GA audit M8 limited an exchange's `audience` / `resource` to an audience
//! the subject token already carries or the `resource_uri` of a protected
//! resource in the realm's identity registry. Nothing populated that
//! registry: YAML `protected_resources` fed only the RBAC scope bundles, and
//! there is no admin write API. So over the wire an exchange could only
//! narrow.
//!
//! Reconcile now mirrors the YAML entries into the registry at startup and
//! on every config reload, keyed by `resource_uri`: an entry added to YAML
//! becomes an allowed target, and an entry removed from YAML stops being one.

#![allow(clippy::unwrap_used)]

mod common;

use hearth::config::Config;
use hearth::core::{ClientId, RealmId};
use hearth::identity::reconcile::reconcile_realms;
use hearth::identity::{
    ClientTrustLevel, CreateUserRequest, IdentityError, RegisterClientRequest,
    RegisterProtectedResourceRequest, Rfc8693Request, SessionContext, TokenIssuanceContext,
};

const REALM: &str = "texyaml";
const TE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SECRET: &str = "yaml-token-exchange-secret-0123!";
const RS: &str = "https://rs.example.com/api";
const RS2: &str = "https://mcp.example.com/";
const UNLISTED: &str = "https://unlisted.example.com/api";

/// A `hearth.yaml` holding one realm whose `protected_resources` lists
/// `uris` (none → the key is omitted entirely).
fn config(uris: &[&str]) -> Config {
    let resources = if uris.is_empty() {
        String::new()
    } else {
        let mut s = String::from("    protected_resources:\n");
        for uri in uris {
            s.push_str(&format!(
                "      - resource_uri: \"{uri}\"\n        display_name: \"RS {uri}\"\n"
            ));
        }
        s
    };
    let yaml = format!("realms:\n  {REALM}:\n    session_ttl: \"12h\"\n{resources}");
    let mut config = Config::from_yaml_str_unchecked(&yaml).expect("parse yaml");
    config.dev_mode = true;
    config
}

fn reconcile(h: &common::TestHarness, uris: &[&str]) -> RealmId {
    reconcile_realms(h.identity(), h.authz(), &config(uris)).expect("reconcile");
    h.identity()
        .get_realm_by_name(REALM)
        .expect("lookup realm")
        .expect("realm exists")
        .id()
        .clone()
}

fn registered_uris(h: &common::TestHarness, realm: &RealmId) -> Vec<String> {
    let mut uris: Vec<String> = h
        .identity()
        .list_protected_resources(realm)
        .expect("list")
        .into_iter()
        .map(|r| r.resource_uri)
        .collect();
    uris.sort();
    uris
}

fn client(h: &common::TestHarness, realm: &RealmId) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("te-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some(SECRET.to_string()),
                grant_types: vec![TE.to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                require_consent: false,
                ..RegisterClientRequest::default()
            },
        )
        .unwrap()
        .client_id()
        .clone()
}

fn subject_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("te-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "TE".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .unwrap();
    h.identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                granted_scopes: std::iter::once("read".to_string()).collect(),
                ..TokenIssuanceContext::default()
            },
        )
        .unwrap()
        .access_token()
        .to_string()
}

/// Which request parameter carries the target.
#[derive(Clone, Copy, Debug)]
enum Target {
    Audience,
    Resource,
}

fn exchange(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &ClientId,
    via: Target,
    target: &str,
) -> Result<String, IdentityError> {
    let (audience, resource) = match via {
        Target::Audience => (Some(target.to_string()), None),
        Target::Resource => (None, Some(target.to_string())),
    };
    h.identity()
        .rfc8693_token_exchange(
            realm,
            &Rfc8693Request {
                client_id: client.clone(),
                subject_token: subject_token(h, realm),
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: None,
                resource,
                audience,
                dpop_jkt: None,
            },
        )
        .map(|r| r.access_token)
}

fn assert_invalid_target(result: Result<String, IdentityError>, what: &str) {
    match result {
        Err(IdentityError::TokenExchangeRejected { oauth_error, .. }) => {
            assert_eq!(oauth_error, "invalid_target", "{what}");
        }
        other => panic!("{what}: expected invalid_target, got {other:?}"),
    }
}

fn assert_exchange_targets(
    h: &common::TestHarness,
    realm: &RealmId,
    c: &ClientId,
    via: Target,
    target: &str,
) {
    let token = exchange(h, realm, c, via, target)
        .unwrap_or_else(|e| panic!("{via:?}={target} is a YAML protected resource: {e:?}"));
    let claims = hearth::identity::tokens::decode_claims_unverified(&token).unwrap();
    assert!(
        claims.aud.contains(target),
        "{via:?}: minted aud names {target}"
    );
}

/// The full lifecycle for one request parameter: listed → allowed, unlisted →
/// `invalid_target`, removed from YAML and reconciled → `invalid_target`.
async fn yaml_lifecycle(via: Target) {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = reconcile(&h, &[RS, RS2]);
    let c = client(&h, &realm);

    assert_exchange_targets(&h, &realm, &c, via, RS);
    assert_exchange_targets(&h, &realm, &c, via, RS2);
    assert_invalid_target(
        exchange(&h, &realm, &c, via, UNLISTED),
        "an audience absent from YAML",
    );

    // Drop RS from YAML and reload: it stops being a target, RS2 stays one.
    reconcile(&h, &[RS2]);
    assert_invalid_target(
        exchange(&h, &realm, &c, via, RS),
        "a resource removed from YAML",
    );
    assert_exchange_targets(&h, &realm, &c, via, RS2);

    // Drop the whole `protected_resources` key: nothing is a target.
    reconcile(&h, &[]);
    assert_invalid_target(
        exchange(&h, &realm, &c, via, RS2),
        "the last resource removed from YAML",
    );
}

#[tokio::test]
async fn audience_follows_yaml_protected_resources() {
    yaml_lifecycle(Target::Audience).await;
}

#[tokio::test]
async fn resource_indicator_follows_yaml_protected_resources() {
    yaml_lifecycle(Target::Resource).await;
}

/// YAML is the registry's only source of truth: reconcile leaves exactly the
/// declared `resource_uri`s, removing anything registered another way, and is
/// idempotent.
#[tokio::test]
async fn registry_mirrors_yaml_exactly() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = reconcile(&h, &[RS]);
    h.identity()
        .register_protected_resource(
            &realm,
            &RegisterProtectedResourceRequest {
                resource_uri: UNLISTED.to_string(),
                display_name: "not in YAML".to_string(),
                scopes: Vec::new(),
                required_claims: Vec::new(),
            },
        )
        .unwrap();
    let before = h.identity().list_protected_resources(&realm).unwrap();
    assert_eq!(before.len(), 2, "precondition: a non-YAML registration");

    reconcile(&h, &[RS, RS2]);
    assert_eq!(
        registered_uris(&h, &realm),
        vec![RS2.to_string(), RS.to_string()]
    );
    let rs_id = h
        .identity()
        .list_protected_resources(&realm)
        .unwrap()
        .into_iter()
        .find(|r| r.resource_uri == RS)
        .unwrap()
        .id;

    // A second pass with the same YAML changes nothing: same records, same ids.
    reconcile(&h, &[RS, RS2]);
    assert_eq!(
        registered_uris(&h, &realm),
        vec![RS2.to_string(), RS.to_string()]
    );
    let rs_after = h
        .identity()
        .list_protected_resources(&realm)
        .unwrap()
        .into_iter()
        .find(|r| r.resource_uri == RS)
        .unwrap();
    assert_eq!(rs_after.id, rs_id, "an unchanged entry keeps its record");
    assert_eq!(rs_after.display_name, format!("RS {RS}"));
}

/// A changed `display_name` or scope bundle list updates the record in place.
#[tokio::test]
async fn a_changed_yaml_entry_updates_the_record() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = reconcile(&h, &[RS]);
    let yaml = format!(
        "realms:\n  {REALM}:\n    session_ttl: \"12h\"\n    protected_resources:\n      \
         - resource_uri: \"{RS}\"\n        display_name: \"Renamed\"\n        scopes:\n          \
         - name: \"mcp:tools:invoke\"\n            display_name: \"Invoke tools\"\n"
    );
    let mut cfg = Config::from_yaml_str_unchecked(&yaml).expect("parse yaml");
    cfg.dev_mode = true;
    reconcile_realms(h.identity(), h.authz(), &cfg).expect("reconcile");

    let resources = h.identity().list_protected_resources(&realm).unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].resource_uri, RS);
    assert_eq!(resources[0].display_name, "Renamed");
    assert_eq!(resources[0].scopes, vec!["mcp:tools:invoke".to_string()]);
}

fn declared(uri: &str) -> RegisterProtectedResourceRequest {
    RegisterProtectedResourceRequest {
        resource_uri: uri.to_string(),
        display_name: "RS".to_string(),
        scopes: Vec::new(),
        required_claims: Vec::new(),
    }
}

/// The engine validates the whole declared set before writing: a duplicate or
/// malformed entry is refused and the registry is left exactly as it was
/// (neither the valid new entry is added nor the undeclared one removed).
#[tokio::test]
async fn an_invalid_declared_set_changes_nothing() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = reconcile(&h, &[RS]);
    for bad in [
        vec![declared(RS2), declared(RS2)],
        vec![declared(RS2), declared("https://rs.example.com/api#frag")],
        vec![declared(RS2), declared(" https://padded.example.com")],
        vec![declared(RS2), declared("relative/path")],
    ] {
        let err = h
            .identity()
            .reconcile_protected_resources(&realm, &bad)
            .unwrap_err();
        assert!(
            matches!(err, IdentityError::InvalidInput { .. }),
            "{bad:?}: {err:?}"
        );
        assert_eq!(registered_uris(&h, &realm), vec![RS.to_string()], "{bad:?}");
    }
}

/// The single-register call applies the same URI rule, so a value the YAML
/// path refuses cannot enter the registry another way.
#[tokio::test]
async fn register_refuses_a_fragment_or_padded_resource_uri() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = reconcile(&h, &[]);
    for bad in [
        "https://rs.example.com/api#frag",
        " https://rs.example.com/api",
    ] {
        let err = h
            .identity()
            .register_protected_resource(&realm, &declared(bad))
            .unwrap_err();
        assert!(
            matches!(err, IdentityError::InvalidInput { .. }),
            "{bad:?}: {err:?}"
        );
    }
    assert_eq!(registered_uris(&h, &realm), Vec::<String>::new());
}

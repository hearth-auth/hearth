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
const RS2: &str = "https://mcp.example.com";
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
    let yaml = format!(
        "auth:\n  mfa_required: false\nrealms:\n  {REALM}:\n    session_ttl: \"12h\"\n{resources}"
    );
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
    let h = common::TestHarness::in_process().await.unwrap();
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
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = reconcile(&h, &[RS]);
    h.identity()
        .register_protected_resource(
            &realm,
            &RegisterProtectedResourceRequest {
                resource_uri: UNLISTED.to_string(),
                display_name: "not in YAML".to_string(),
                scopes: Vec::new(),
                required_claims: Vec::new(),
                introspection_client_id: None,
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
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = reconcile(&h, &[RS]);
    let yaml = format!(
        "auth:\n  mfa_required: false\nrealms:\n  {REALM}:\n    session_ttl: \"12h\"\n    \
         protected_resources:\n      \
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
        introspection_client_id: None,
    }
}

/// The engine validates the whole declared set before writing: a duplicate or
/// malformed entry is refused and the registry is left exactly as it was
/// (neither the valid new entry is added nor the undeclared one removed).
#[tokio::test]
async fn an_invalid_declared_set_changes_nothing() {
    let h = common::TestHarness::in_process().await.unwrap();
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
    let h = common::TestHarness::in_process().await.unwrap();
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

// ── One URI rule for the exchange allowlist and RBAC ─────────────────────────

const PERM: &str = "tools.invoke";
const BUNDLE: &str = "mcp:tools:invoke";
/// The canonical form of every spelling in `SPELLINGS`.
const CANON: &str = "https://mcp.example.com/api";
const SPELLINGS: [&str; 4] = [
    "https://mcp.example.com/api",
    "https://mcp.example.com/api/",
    "HTTPS://MCP.Example.COM:443/api",
    "https://mcp.EXAMPLE.com:443/api/",
];
/// URIs that differ from `CANON` in something canonicalization keeps.
const DIFFERENT: [&str; 4] = [
    "https://mcp.example.com/other",
    "https://mcp.example.com/API",
    "http://mcp.example.com/api",
    "https://mcp.example.com:8443/api",
];

/// Realm YAML declaring `tools.invoke` and, per `uri`, a protected resource
/// whose `mcp:tools:invoke` bundle grants it (none → no `protected_resources`).
fn bundle_config(uris: &[&str]) -> Config {
    let mut yaml = format!(
        "auth:\n  mfa_required: false\nrealms:\n  {REALM}:\n    session_ttl: \"12h\"\n    \
         permissions:\n      \
         - name: {PERM}\n        display_name: Invoke\n"
    );
    if !uris.is_empty() {
        yaml.push_str("    protected_resources:\n");
        for uri in uris {
            yaml.push_str(&format!(
                "      - resource_uri: \"{uri}\"\n        display_name: MCP\n        \
                 scopes:\n          - name: \"{BUNDLE}\"\n            display_name: Invoke\n            \
                 permissions: [{PERM}]\n"
            ));
        }
    }
    let mut config = Config::from_yaml_str_unchecked(&yaml).expect("parse yaml");
    config.dev_mode = true;
    config
}

fn reconcile_config(h: &common::TestHarness, config: &Config) -> RealmId {
    reconcile_realms(h.identity(), h.authz(), config).expect("reconcile");
    h.identity()
        .get_realm_by_name(REALM)
        .unwrap()
        .expect("realm exists")
        .id()
        .clone()
}

fn user_with_bundle_permission(h: &common::TestHarness, realm: &RealmId) -> hearth::core::UserId {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("rb-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RB".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    h.rbac()
        .grant_user_permission(
            realm,
            &hearth::rbac::UserPermissionGrant {
                realm_id: realm.clone(),
                user_id: user.id().clone(),
                permission: hearth::rbac::Permission::new(PERM).unwrap(),
                scope: hearth::rbac::Scope::Realm,
                granted_at: hearth::core::Timestamp::from_micros(0),
                granted_by: None,
            },
        )
        .unwrap();
    user.id().clone()
}

/// Whether RBAC grants `mcp:tools:invoke` to a third-party client for a token
/// bound to `resource` — i.e. whether its resource scope lookup finds the
/// YAML bundle under that spelling.
fn rbac_grants_bundle(
    h: &common::TestHarness,
    realm: &RealmId,
    user: &hearth::core::UserId,
    resource: &str,
) -> bool {
    let uri = hearth::core::Uri::try_from(resource.to_string()).unwrap();
    match h.rbac().resolve_with_scopes(
        user,
        realm,
        None,
        &[BUNDLE.to_string()],
        ClientTrustLevel::ThirdParty,
        &[BUNDLE.to_string()],
        Some(&uri),
    ) {
        Ok(resolved) => {
            assert_eq!(resolved.granted_scopes, vec![BUNDLE.to_string()]);
            true
        }
        Err(hearth::rbac::RbacError::InvalidScope { .. }) => false,
        Err(other) => panic!("unexpected RBAC error {other:?}"),
    }
}

/// Every spelling of one URI is the same resource to BOTH layers — the
/// token-exchange allowlist and RBAC's resource scope lookup — and a URI that
/// differs in scheme, port, path or path case is a different resource to both.
#[tokio::test]
async fn spelling_variants_match_in_both_layers() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = reconcile_config(&h, &bundle_config(&["HTTPS://MCP.Example.com:443/api/"]));
    assert_eq!(
        registered_uris(&h, &realm),
        vec![CANON.to_string()],
        "the registry stores the canonical form"
    );
    let c = client(&h, &realm);
    let user = user_with_bundle_permission(&h, &realm);

    for spelling in SPELLINGS {
        for via in [Target::Audience, Target::Resource] {
            let token = exchange(&h, &realm, &c, via, spelling)
                .unwrap_or_else(|e| panic!("{via:?}={spelling}: {e:?}"));
            let claims = hearth::identity::tokens::decode_claims_unverified(&token).unwrap();
            assert!(
                claims.aud.contains(CANON),
                "{via:?}={spelling}: the minted aud carries the canonical form"
            );
        }
        assert!(
            rbac_grants_bundle(&h, &realm, &user, spelling),
            "RBAC finds the bundle under {spelling}"
        );
    }
    for different in DIFFERENT {
        for via in [Target::Audience, Target::Resource] {
            assert_invalid_target(exchange(&h, &realm, &c, via, different), different);
        }
        assert!(
            !rbac_grants_bundle(&h, &realm, &user, different),
            "RBAC must not find the bundle under {different}"
        );
    }
}

/// RBAC's resource scope bundles mirror YAML exactly, like the registry: a
/// bundle dropped from a listed resource, a resource dropped from the list,
/// and an emptied list all remove the bundles.
#[tokio::test]
async fn rbac_resource_bundles_follow_yaml() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = reconcile_config(&h, &bundle_config(&[RS, RS2]));
    let user = user_with_bundle_permission(&h, &realm);
    assert!(rbac_grants_bundle(&h, &realm, &user, RS));
    assert!(rbac_grants_bundle(&h, &realm, &user, RS2));

    // RS dropped from YAML: its bundles go, RS2's stay.
    reconcile_config(&h, &bundle_config(&[RS2]));
    assert!(!rbac_grants_bundle(&h, &realm, &user, RS), "RS removed");
    assert!(rbac_grants_bundle(&h, &realm, &user, RS2), "RS2 kept");

    // RS2 still listed but without its bundle.
    reconcile_config(&h, &config(&[RS2]));
    assert!(
        !rbac_grants_bundle(&h, &realm, &user, RS2),
        "bundle removed"
    );

    // Back, then the whole key removed.
    reconcile_config(&h, &bundle_config(&[RS2]));
    assert!(rbac_grants_bundle(&h, &realm, &user, RS2), "re-added");
    reconcile_config(&h, &bundle_config(&[]));
    assert!(!rbac_grants_bundle(&h, &realm, &user, RS2), "list emptied");
}

// ── Removing a resource stops its tokens (AGENT_AUTH.md §2.5) ────────────────

fn resource_bound_pair(
    h: &common::TestHarness,
    realm: &RealmId,
    resource: Option<&str>,
) -> hearth::identity::TokenPair {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("rt-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RT".into(),
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
                resource: resource.map(|r| hearth::core::Uri::try_from(r.to_string()).unwrap()),
                ..TokenIssuanceContext::default()
            },
        )
        .unwrap()
}

fn introspect_active(h: &common::TestHarness, realm: &RealmId, token: &str) -> bool {
    h.identity()
        .introspect_token(
            realm,
            &hearth::identity::oidc::TokenIntrospectionRequest {
                token: token.to_string(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .unwrap()
        .active
}

/// Every token whose `aud` names a resource removed from YAML stops
/// validating and introspects inactive at once, and its refresh token stops
/// rotating; tokens for other resources and for Hearth alone are untouched.
#[tokio::test]
async fn removing_a_resource_stops_its_tokens() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = reconcile(&h, &[RS, RS2]);
    let c = client(&h, &realm);

    let for_rs = resource_bound_pair(&h, &realm, Some(RS));
    let for_rs2 = resource_bound_pair(&h, &realm, Some(RS2));
    let plain = resource_bound_pair(&h, &realm, None);
    let exchanged = exchange(&h, &realm, &c, Target::Resource, RS).unwrap();
    for token in [
        for_rs.access_token(),
        for_rs2.access_token(),
        plain.access_token(),
        exchanged.as_str(),
    ] {
        h.identity()
            .validate_token(&realm, token)
            .unwrap_or_else(|e| panic!("precondition: valid before removal: {e:?}"));
        assert!(introspect_active(&h, &realm, token), "precondition");
    }

    reconcile(&h, &[RS2]);

    for (what, token) in [
        ("issued for RS", for_rs.access_token()),
        ("exchanged to RS", exchanged.as_str()),
    ] {
        assert!(
            matches!(
                h.identity().validate_token(&realm, token),
                Err(IdentityError::InvalidToken)
            ),
            "{what}: validate_token must refuse a token for a removed resource"
        );
        assert!(!introspect_active(&h, &realm, token), "{what}: inactive");
    }
    let refreshed = h
        .identity()
        .refresh_tokens(&realm, for_rs.refresh_token(), None, None);
    assert!(
        refreshed.is_err(),
        "a refresh token bound to a removed resource must not rotate: {:?}",
        refreshed.map(|p| p.access_token().to_string())
    );

    for (what, token) in [
        ("issued for RS2", for_rs2.access_token()),
        ("plain", plain.access_token()),
    ] {
        h.identity()
            .validate_token(&realm, token)
            .unwrap_or_else(|e| panic!("{what}: untouched by RS's removal: {e:?}"));
        assert!(introspect_active(&h, &realm, token), "{what}: active");
    }
    h.identity()
        .refresh_tokens(&realm, for_rs2.refresh_token(), None, None)
        .expect("RS2's refresh token still rotates");
}

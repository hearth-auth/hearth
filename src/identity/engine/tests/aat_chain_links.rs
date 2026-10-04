//! AAT validation checks every link of the chain against the record Hearth
//! wrote when it minted the link (`delegation-chain-integrity` design §3).
//!
//! Scenario "Validation checks every chain link" of `delegated-authorization`
//! "An AAT is validated along its whole chain". Every token below is signed
//! with the realm key, so only the chain checks can refuse it.

use super::*;

use crate::identity::types::{AatClaims, AatToolPermission, DeriveAatRequest, IssueAatRequest};
use crate::identity::{AgentOwner, CreateAgentRequest};

const AAT_TYP: &str = "aat+jwt";

fn tool(name: &str, actions: &[&str]) -> AatToolPermission {
    AatToolPermission {
        tool: name.to_string(),
        actions: actions.iter().copied().map(str::to_string).collect(),
        constraints: serde_json::Value::Null,
    }
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: EmbeddedIdentityEngine,
    realm: RealmId,
    root: AatClaims,
    child: AatClaims,
    child_token: String,
}

/// A root AAT (`search`: invoke + list; scope `a b`) and a child derived from
/// it (`search`: invoke; scope `a`).
fn chain() -> Chain {
    let (dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let owner = create_test_user(&engine, &realm);
    let agent = engine
        .create_agent(
            &realm,
            &CreateAgentRequest {
                display_name: "aat-chain-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent");
    let root_token = engine
        .issue_aat(
            &realm,
            &IssueAatRequest {
                agent_id: agent.id().clone(),
                tools: vec![tool("search", &["invoke", "list"])],
                scope: vec!["a".to_string(), "b".to_string()],
                aud: None,
                expires_in_secs: Some(600),
            },
        )
        .expect("issue root")
        .aat;
    let child_token = engine
        .derive_aat(
            &realm,
            &DeriveAatRequest {
                parent_aat: root_token.clone(),
                tools: vec![tool("search", &["invoke"])],
                scope: vec!["a".to_string()],
                aud: None,
                expires_in_secs: None,
            },
        )
        .expect("derive child")
        .aat;
    let root = engine
        .validate_aat(&realm, &root_token, None)
        .expect("root validates");
    let child = engine
        .validate_aat(&realm, &child_token, None)
        .expect("child validates");
    Chain {
        _dir: dir,
        engine,
        realm,
        root,
        child,
        child_token,
    }
}

/// Signs `claims` with the realm key, as an AAT.
fn sign(c: &Chain, claims: &AatClaims) -> String {
    c.engine
        .get_or_load_realm_signing_key(&c.realm)
        .expect("signing key")
        .sign_jwt(claims, AAT_TYP)
        .expect("sign AAT")
}

fn assert_refused(c: &Chain, token: &str, what: &str) {
    let result = c.engine.validate_aat(&c.realm, token, None);
    assert!(
        matches!(
            result,
            Err(IdentityError::AatChainBroken { .. } | IdentityError::AatScopeEscalation)
        ),
        "{what}: expected AatChainBroken or AatScopeEscalation, got {:?}",
        result.map(|claims| claims.jti)
    );
}

#[test]
fn a_minted_chain_validates() {
    let c = chain();
    assert_eq!(c.child.aat_parent.as_deref(), Some(c.root.jti.as_str()));
    c.engine
        .validate_aat(&c.realm, &c.child_token, None)
        .expect("a chain Hearth minted validates");
}

#[test]
fn a_chain_without_its_parent_is_refused() {
    let c = chain();
    let mut forged = c.child.clone();
    forged.aat_chain = vec![uuid::Uuid::new_v4().to_string(), forged.jti.clone()];
    assert_refused(
        &c,
        &sign(&c, &forged),
        "aat_chain does not contain aat_parent",
    );
}

#[test]
fn a_chain_that_does_not_end_with_the_token_is_refused() {
    let c = chain();
    let mut forged = c.child.clone();
    forged.aat_chain = vec![c.root.jti.clone()];
    assert_refused(&c, &sign(&c, &forged), "aat_chain does not end with jti");
}

#[test]
fn a_child_whose_tools_exceed_its_parent_is_refused() {
    let c = chain();
    let mut forged = c.child.clone();
    forged.tools = vec![tool("search", &["invoke", "list", "delete"])];
    assert_refused(&c, &sign(&c, &forged), "child tools exceed the parent's");
}

#[test]
fn a_child_whose_scope_exceeds_its_parent_is_refused() {
    let c = chain();
    let mut forged = c.child.clone();
    forged.scope = vec!["a".to_string(), "c".to_string()];
    assert_refused(&c, &sign(&c, &forged), "child scope exceeds the parent's");
}

#[test]
fn a_link_hearth_never_minted_is_refused() {
    let c = chain();
    let mut forged = c.child.clone();
    let jti = uuid::Uuid::new_v4().to_string();
    forged.jti.clone_from(&jti);
    forged.aat_chain = vec![c.root.jti.clone(), jti];
    assert_refused(&c, &sign(&c, &forged), "the token's own jti has no record");
}

#[test]
fn a_root_that_claims_a_parent_is_refused() {
    let c = chain();
    let mut forged = c.root.clone();
    forged.aat_parent = Some(c.child.jti.clone());
    assert_refused(&c, &sign(&c, &forged), "a one-link chain names a parent");
}

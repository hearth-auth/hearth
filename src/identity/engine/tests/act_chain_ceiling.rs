//! `security.max_act_chain_depth`: one configured act-chain ceiling, read by
//! token validation, token exchange and the agent depth limits.
//!
//! Scenarios of `abuse-prevention` "A-38 Delegation-chain depth cap" and
//! `agent-identity` "The agent record".

use super::*;

use crate::identity::tokens::{decode_claims_unverified, ActClaim};
use crate::identity::{AgentOwner, CreateAgentRequest, UpdateAgentRequest};

/// Builds an engine over `storage` whose act-chain ceiling is `ceiling`.
fn engine_on(storage: &Arc<dyn StorageEngine>, ceiling: u8) -> EmbeddedIdentityEngine {
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    EmbeddedIdentityEngine::new(
        Arc::clone(storage),
        clock as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            max_act_chain_depth: ceiling,
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation")
    .with_hibp_transport(Arc::new(NeverPwnedStub))
}

fn open_storage() -> (tempfile::TempDir, Arc<dyn StorageEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    (dir, storage)
}

/// An `act` chain of `depth` links.
fn chain(depth: usize) -> ActClaim {
    let mut act = ActClaim {
        sub: "actor-0".to_string(),
        act: None,
    };
    for i in 1..depth {
        act = ActClaim {
            sub: format!("actor-{i}"),
            act: Some(Box::new(act)),
        };
    }
    act
}

/// A realm-signed access token for a new user, carrying `act`.
fn token_with_act(engine: &EmbeddedIdentityEngine, realm: &RealmId, act: ActClaim) -> String {
    let user = create_test_user(engine, realm);
    let session = engine
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = engine
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens");
    let mut claims = decode_claims_unverified(pair.access_token()).expect("decode claims");
    claims.act = Some(act);
    engine
        .get_signing_key_or_default(realm)
        .issue_token(&claims)
        .expect("re-sign with an act chain")
}

fn agent_request(owner: &User, depth: u8) -> CreateAgentRequest {
    CreateAgentRequest {
        display_name: "depth-agent".to_string(),
        description: None,
        owner: AgentOwner::User(owner.id().clone()),
        capabilities: vec![],
        max_delegation_depth: depth,
    }
}

#[test]
fn the_default_ceiling_is_3() {
    assert_eq!(IdentityConfig::default().max_act_chain_depth, 3);

    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);

    let three = token_with_act(&engine, &realm, chain(3));
    engine
        .validate_token(&realm, &three)
        .expect("a three-level chain is within the default ceiling");

    let four = token_with_act(&engine, &realm, chain(4));
    let err = engine
        .validate_token(&realm, &four)
        .expect_err("a four-level chain passes the default ceiling");
    assert!(matches!(err, IdentityError::InvalidToken), "got {err:?}");
}

#[test]
fn an_operator_raises_the_ceiling() {
    let (_dir, storage) = open_storage();
    let engine = engine_on(&storage, 6);
    let realm = create_test_realm(&engine);

    let five = token_with_act(&engine, &realm, chain(5));
    engine
        .validate_token(&realm, &five)
        .expect("a five-level chain is within a ceiling of 6");

    let seven = token_with_act(&engine, &realm, chain(7));
    let err = engine
        .validate_token(&realm, &seven)
        .expect_err("a seven-level chain passes a ceiling of 6");
    assert!(matches!(err, IdentityError::InvalidToken), "got {err:?}");
}

#[test]
fn a_very_deep_chain_stops_early() {
    let deep = chain(100);
    assert_eq!(
        deep.depth_up_to(3),
        4,
        "the count stops one link past the limit"
    );
    assert_eq!(chain(3).depth_up_to(3), 3);
    assert_eq!(chain(1).depth_up_to(3), 1);

    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let token = token_with_act(&engine, &realm, deep);
    let err = engine
        .validate_token(&realm, &token)
        .expect_err("a 100-level chain passes the default ceiling");
    assert!(matches!(err, IdentityError::InvalidToken), "got {err:?}");
}

#[test]
fn a_delegation_depth_out_of_range_is_refused() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let owner = create_test_user(&engine, &realm);

    for depth in [0_u8, 4] {
        let err = engine
            .create_agent(&realm, &agent_request(&owner, depth), None)
            .expect_err("a depth outside 1..=3 is refused on create");
        assert!(
            matches!(err, IdentityError::InvalidInput { .. }),
            "depth {depth}: got {err:?}"
        );
    }

    let agent = engine
        .create_agent(&realm, &agent_request(&owner, 3), None)
        .expect("the ceiling itself is accepted");
    let err = engine
        .update_agent(
            &realm,
            agent.id(),
            &UpdateAgentRequest {
                max_delegation_depth: Some(4),
                ..UpdateAgentRequest::default()
            },
            None,
        )
        .expect_err("a depth above the ceiling is refused on update");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_raised_ceiling_admits_a_deeper_agent() {
    let (_dir, storage) = open_storage();
    let engine = engine_on(&storage, 6);
    let realm = create_test_realm(&engine);
    let owner = create_test_user(&engine, &realm);

    engine
        .create_agent(&realm, &agent_request(&owner, 6), None)
        .expect("a depth equal to a raised ceiling is accepted");
    let err = engine
        .create_agent(&realm, &agent_request(&owner, 7), None)
        .expect_err("a depth above a raised ceiling is refused");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_lowered_ceiling_caps_a_stored_depth() {
    let (_dir, storage) = open_storage();
    let before = engine_on(&storage, 6);
    let realm = create_test_realm(&before);
    let owner = create_test_user(&before, &realm);
    let agent = before
        .create_agent(&realm, &agent_request(&owner, 5), None)
        .expect("create agent under a ceiling of 6");
    let agent_sub = format!("{}", agent.id());
    assert_eq!(
        before
            .actor_depth_ceiling(&realm, &agent_sub)
            .expect("ceiling"),
        5
    );
    drop(before);

    // The operator lowers the ceiling to 3 and restarts.
    let after = engine_on(&storage, 3);
    assert_eq!(
        after
            .actor_depth_ceiling(&realm, &agent_sub)
            .expect("ceiling"),
        3,
        "a stored depth above the ceiling is capped"
    );
    assert_eq!(
        after
            .actor_depth_ceiling(&realm, "not-an-agent")
            .expect("ceiling"),
        3,
        "a non-agent actor gets the ceiling"
    );
}

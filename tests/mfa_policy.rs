//! scope-trim-trusted-core, group 6: MFA is a plain policy, required by
//! default (spec `mfa-policy`).
//!
//! The default lives where a server builds a realm: a realm declared in
//! `hearth.yaml` with no `auth.mfa_required` (and no global value) records
//! `mfa_required: true`. An explicit `false` is honoured, and every realm whose
//! MFA is off is listed for the startup warning.

mod common;

use hearth::config::{AuthConfig, RealmAuthYaml, RealmYamlConfig};
use hearth::identity::{CreateRealmRequest, RealmConfig};

fn realm_yaml(mfa_required: Option<bool>) -> RealmYamlConfig {
    RealmYamlConfig {
        auth: Some(RealmAuthYaml {
            mfa_required,
            ..RealmAuthYaml::default()
        }),
        ..RealmYamlConfig::default()
    }
}

fn global(mfa_required: Option<bool>) -> AuthConfig {
    AuthConfig {
        mfa_required,
        ..AuthConfig::default()
    }
}

#[test]
fn a_realm_with_no_mfa_setting_requires_mfa() {
    let cfg = realm_yaml(None)
        .to_realm_config("test", &global(None), None)
        .expect("realm config");
    assert_eq!(cfg.mfa_required, Some(true));

    let bare = RealmYamlConfig::default()
        .to_realm_config("test", &global(None), None)
        .expect("realm config");
    assert_eq!(bare.mfa_required, Some(true), "no auth block at all");
}

#[test]
fn an_explicit_opt_out_is_honoured() {
    let realm_off = realm_yaml(Some(false))
        .to_realm_config("test", &global(None), None)
        .expect("realm config");
    assert_eq!(realm_off.mfa_required, Some(false));

    let global_off = realm_yaml(None)
        .to_realm_config("test", &global(Some(false)), None)
        .expect("realm config");
    assert_eq!(global_off.mfa_required, Some(false), "global opt-out");

    let realm_wins = realm_yaml(Some(true))
        .to_realm_config("test", &global(Some(false)), None)
        .expect("realm config");
    assert_eq!(realm_wins.mfa_required, Some(true), "realm beats global");
}

/// The startup `WARN` names every realm whose effective MFA requirement is
/// off; a realm that requires MFA is not named.
#[tokio::test]
async fn realms_with_mfa_off_are_listed_for_the_startup_warning() {
    let h = common::TestHarness::in_process().await.expect("harness");
    for (name, mfa) in [("mfa-on", Some(true)), ("mfa-off", Some(false))] {
        h.identity()
            .create_realm(&CreateRealmRequest {
                name: name.to_string(),
                config: Some(RealmConfig {
                    mfa_required: mfa,
                    ..RealmConfig::default()
                }),
            })
            .expect("realm");
    }
    let off = hearth::identity::realms_with_mfa_off(h.identity()).expect("list");
    assert!(off.iter().any(|n| n == "mfa-off"), "{off:?}");
    assert!(!off.iter().any(|n| n == "mfa-on"), "{off:?}");
}

fn mfa_events(
    h: &common::TestHarness,
    realm: &hearth::core::RealmId,
) -> Vec<hearth::audit::AuditEvent> {
    h.audit()
        .query(&hearth::audit::AuditQuery {
            action: Some(hearth::audit::AuditAction::MfaRequirementChanged),
            ..hearth::audit::AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query")
}

/// Turning a realm's MFA off (reconcile writes through `update_realm`) is
/// audited with the old and new values; an update that leaves it alone is not.
#[tokio::test]
async fn a_realm_mfa_change_is_audited() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "mfa-audit".to_string(),
            config: Some(RealmConfig {
                mfa_required: Some(true),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let update = |mfa: Option<bool>, theme: &str| {
        let mut config = h
            .identity()
            .get_realm(realm.id())
            .expect("get")
            .expect("realm")
            .config()
            .clone();
        config.mfa_required = mfa;
        config.web_theme_name = Some(theme.to_string());
        h.identity()
            .update_realm(
                realm.id(),
                &hearth::identity::UpdateRealmRequest {
                    config: Some(config),
                    ..Default::default()
                },
            )
            .expect("update realm");
    };

    update(Some(true), "unrelated");
    assert!(mfa_events(&h, realm.id()).is_empty(), "no change, no event");

    update(Some(false), "unrelated-2");
    let events = mfa_events(&h, realm.id());
    assert_eq!(events.len(), 1, "{events:?}");
    let meta = events[0].metadata.as_ref().expect("metadata");
    assert_eq!(meta["old"], true, "{meta}");
    assert_eq!(meta["new"], false, "{meta}");
    assert_eq!(events[0].resource_type, "realm");
}

/// Startup applies the configured policy to the system realm, which no
/// other write path may touch; a change is audited, a no-op is not.
#[tokio::test]
async fn startup_applies_the_system_realm_policy() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let system = hearth::core::RealmId::new(uuid::Uuid::nil());

    assert!(h
        .identity()
        .apply_system_realm_mfa_required(true)
        .expect("apply"));
    let realm = h
        .identity()
        .get_realm(&system)
        .expect("get")
        .expect("system");
    assert_eq!(realm.config().mfa_required, Some(true));
    assert_eq!(mfa_events(&h, &system).len(), 1);

    assert!(
        !h.identity()
            .apply_system_realm_mfa_required(true)
            .expect("apply again"),
        "unchanged"
    );
    assert_eq!(mfa_events(&h, &system).len(), 1, "a no-op writes no event");
}

/// `POST /admin/bootstrap` under the production MFA default: the dev realm
/// requires MFA, both dev admins hold a TOTP factor, each secret is returned
/// once, and the minted tokens work (task 6.7).
#[cfg(feature = "dev-endpoints")]
#[tokio::test]
async fn bootstrap_enrols_totp_for_both_dev_admins() {
    let h = common::TestHarness::server().await.expect("server harness");
    h.identity()
        .apply_system_realm_mfa_required(true)
        .expect("startup policy");
    let base = h.base_url().expect("base_url");
    let client = reqwest::Client::new();

    let first: serde_json::Value = client
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap")
        .json()
        .await
        .expect("json");
    let secret = first["totp_secret"].as_str().unwrap_or_default();
    let admin_secret = first["admin_totp_secret"].as_str().unwrap_or_default();
    assert_eq!(secret.len(), 32, "dev-realm admin TOTP secret: {first}");
    assert_eq!(admin_secret.len(), 32, "system admin TOTP secret: {first}");
    let system_token = first["system_access_token"].as_str().unwrap_or_default();
    assert!(!system_token.is_empty(), "system token minted: {first}");

    let realm_id = first["realm_id"].as_str().expect("realm_id");
    let realm = h
        .identity()
        .get_realm(&hearth::core::RealmId::new(
            uuid::Uuid::parse_str(realm_id).expect("uuid"),
        ))
        .expect("get")
        .expect("dev-realm");
    assert_eq!(realm.config().mfa_required, Some(true));

    let token = first["access_token"].as_str().expect("access_token");
    let users = client
        .get(format!("{base}/admin/users"))
        .bearer_auth(token)
        .header("X-Realm-ID", realm_id)
        .send()
        .await
        .expect("users");
    assert_eq!(users.status(), 200, "the dev-realm token works");

    // Re-bootstrap keeps the factor and returns no secret.
    let again: serde_json::Value = client
        .post(format!("{base}/admin/bootstrap"))
        .bearer_auth(token)
        .send()
        .await
        .expect("re-bootstrap")
        .json()
        .await
        .expect("json");
    assert!(
        again["access_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "{again}"
    );
    assert!(
        again["system_access_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "{again}"
    );
    assert_eq!(again["totp_secret"].as_str().unwrap_or_default(), "");
    assert_eq!(again["admin_totp_secret"].as_str().unwrap_or_default(), "");
}

fn run_mfa_lint(root: &std::path::Path) -> (bool, String) {
    let out = std::process::Command::new("bash")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/check-mfa-resolver.sh"
        ))
        .arg(root)
        .output()
        .expect("run lint");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Task 6.3 self-test: a direct read of `mfa_required` fails the lint and
/// names the file and line; the same read with a reasoned marker passes.
#[test]
fn the_mfa_resolver_lint_rejects_a_direct_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src/protocol/web");
    std::fs::create_dir_all(&src).expect("mkdir");
    let file = src.join("gate.rs");
    std::fs::write(
        &file,
        "fn gate(realm: &Realm) -> bool {\n    realm.config().mfa_required.unwrap_or(false)\n}\n",
    )
    .expect("write");
    let (ok, out) = run_mfa_lint(dir.path());
    assert!(!ok, "a direct read must fail: {out}");
    assert!(out.contains("src/protocol/web/gate.rs:2:"), "{out}");

    std::fs::write(
        &file,
        "fn show(c: &Client) -> Option<bool> {\n    c.mfa_required() // mfa-resolver-ok: a form\n}\n\
         fn set(c: &mut Config) {\n    c.mfa_required = Some(true);\n}\n\
         fn above(c: &Client) -> bool {\n    // mfa-resolver-ok: a form\n    \
         c.mfa_required() == Some(true)\n}\n",
    )
    .expect("write");
    let (ok, out) = run_mfa_lint(dir.path());
    assert!(ok, "a marked read and a write pass: {out}");
}

/// The repository itself passes the lint.
#[test]
fn the_repository_passes_the_mfa_resolver_lint() {
    let (ok, out) = run_mfa_lint(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(ok, "{out}");
}

fn active_user(
    h: &common::TestHarness,
    realm: &hearth::core::RealmId,
    email: &str,
) -> hearth::core::UserId {
    let user = h
        .identity()
        .create_user(
            realm,
            &hearth::identity::CreateUserRequest {
                email: email.to_string(),
                display_name: "MFA".to_string(),
                ..Default::default()
            },
        )
        .expect("user");
    h.identity()
        .update_user(
            realm,
            user.id(),
            &hearth::identity::UpdateUserRequest {
                status: Some(hearth::identity::UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    user.id().clone()
}

fn session_with(
    h: &common::TestHarness,
    realm: &hearth::core::RealmId,
    user: &hearth::core::UserId,
    proof: hearth::identity::MfaProof,
) -> Result<hearth::identity::Session, hearth::identity::IdentityError> {
    h.identity().create_session(
        realm,
        user,
        &hearth::identity::SessionContext {
            mfa_proof: proof,
            ..Default::default()
        },
    )
}

/// Only a passkey, a TOTP code or a recovery code satisfies MFA. An email
/// OTP does not; a user-verified passkey alone does (spec `mfa-policy`).
#[tokio::test]
async fn only_strong_factors_satisfy_mfa() {
    use hearth::identity::{IdentityError, MfaProof};
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "strong-factors".to_string(),
            config: Some(RealmConfig {
                mfa_required: Some(true),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let user = active_user(&h, realm.id(), "strong@example.com");

    for proof in [
        MfaProof::None,
        MfaProof::EmailOtp,
        MfaProof::PasskeyPossession,
    ] {
        let err = session_with(&h, realm.id(), &user, proof).expect_err("refused");
        assert!(
            matches!(err, IdentityError::MfaRequired),
            "{proof:?}: {err:?}"
        );
    }
    for proof in [MfaProof::Proved, MfaProof::ProvedWebAuthn] {
        session_with(&h, realm.id(), &user, proof)
            .unwrap_or_else(|e| panic!("{proof:?} satisfies MFA: {e:?}"));
    }
    assert!(!MfaProof::EmailOtp.satisfies_mfa_required());
    assert!(!MfaProof::EmailOtp.satisfies_webauthn_required());
}

/// On a realm that does not require MFA, an email OTP still opens a session
/// for a user whose only factor is email OTP.
#[tokio::test]
async fn an_email_otp_completes_a_sign_in_where_mfa_is_optional() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "optional-mfa".to_string(),
            config: Some(RealmConfig {
                mfa_required: Some(false),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let user = active_user(&h, realm.id(), "opt@example.com");
    session_with(&h, realm.id(), &user, hearth::identity::MfaProof::EmailOtp)
        .expect("an email OTP opens a session where MFA is optional");
}

fn org(
    h: &common::TestHarness,
    realm: &hearth::core::RealmId,
    slug: &str,
    mfa_required: bool,
) -> hearth::identity::Organization {
    h.identity()
        .create_organization(
            realm,
            &hearth::identity::CreateOrganizationRequest {
                name: slug.to_string(),
                slug: slug.to_string(),
                description: None,
                config: Some(hearth::identity::OrganizationConfig {
                    mfa_required,
                    ..Default::default()
                }),
                attributes: Default::default(),
            },
        )
        .expect("org")
}

fn realm_with_mfa(h: &common::TestHarness, name: &str, mfa: bool) -> hearth::identity::Realm {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: Some(RealmConfig {
                mfa_required: Some(mfa),
                ..RealmConfig::default()
            }),
        })
        .expect("realm")
}

/// An organization that requires MFA tightens an optional realm for its
/// members only (spec `mfa-policy`).
#[tokio::test]
async fn an_org_requires_mfa_for_its_members_in_an_optional_realm() {
    use hearth::identity::{IdentityError, MfaProof, OrganizationRole};
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_mfa(&h, "org-tightens", false);
    let strict = org(&h, realm.id(), "strict", true);
    let member = active_user(&h, realm.id(), "member@example.com");
    let outsider = active_user(&h, realm.id(), "outsider@example.com");
    h.identity()
        .add_member(realm.id(), strict.id(), &member, OrganizationRole::Member)
        .expect("join");

    let err = session_with(&h, realm.id(), &member, MfaProof::None).expect_err("member");
    assert!(matches!(err, IdentityError::MfaRequired), "{err:?}");
    session_with(&h, realm.id(), &member, MfaProof::Proved).expect("member with TOTP");
    session_with(&h, realm.id(), &outsider, MfaProof::None).expect("a non-member is not bound");
}

/// An organization cannot loosen a realm that requires MFA.
#[tokio::test]
async fn an_org_cannot_loosen_a_realm_that_requires_mfa() {
    use hearth::identity::{IdentityError, MfaProof, OrganizationRole};
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_mfa(&h, "org-loosen", true);
    let lax = org(&h, realm.id(), "lax", false);
    let member = active_user(&h, realm.id(), "lax-member@example.com");
    h.identity()
        .add_member(realm.id(), lax.id(), &member, OrganizationRole::Member)
        .expect("join");
    let err = session_with(&h, realm.id(), &member, MfaProof::None).expect_err("still required");
    assert!(matches!(err, IdentityError::MfaRequired), "{err:?}");
}

/// A change of an organization's MFA requirement is audited with the old
/// and new values; an update that keeps it is not. An update that names
/// only another setting keeps the requirement.
#[tokio::test]
async fn an_org_mfa_change_is_audited() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_mfa(&h, "org-audit", false);
    let o = org(&h, realm.id(), "audited", false);
    let update = |config: hearth::identity::OrganizationConfig| {
        h.identity()
            .update_organization(
                realm.id(),
                o.id(),
                &hearth::identity::UpdateOrganizationRequest {
                    config: Some(config),
                    ..Default::default()
                },
            )
            .expect("update org")
    };
    update(hearth::identity::OrganizationConfig {
        mfa_required: true,
        ..Default::default()
    });
    let events = mfa_events(&h, realm.id());
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].resource_type, "organization");
    assert_eq!(events[0].resource_id, o.id().as_uuid().to_string());
    let meta = events[0].metadata.as_ref().expect("metadata");
    assert_eq!(meta["old"], false, "{meta}");
    assert_eq!(meta["new"], true, "{meta}");

    update(hearth::identity::OrganizationConfig {
        mfa_required: true,
        max_members: Some(10),
    });
    assert_eq!(mfa_events(&h, realm.id()).len(), 1, "unchanged, no event");
}

/// A SCIM-created organization does not require MFA.
#[tokio::test]
async fn a_scim_created_org_does_not_require_mfa() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_mfa(&h, "org-scim", false);
    let o = h
        .identity()
        .create_scim_organization(
            realm.id(),
            &hearth::identity::CreateOrganizationRequest {
                name: "scim".to_string(),
                slug: "scim".to_string(),
                description: None,
                config: None,
                attributes: Default::default(),
            },
        )
        .expect("scim org");
    assert!(!o.config().mfa_required);
}

fn mfa_method_issues(yaml: &str) -> Vec<String> {
    let config = hearth::config::Config::from_yaml_str_unchecked(yaml).expect("parse");
    config
        .validate_all()
        .into_iter()
        .filter(|i| i.field.ends_with("auth.mfa_methods"))
        .map(|i| format!("{}: {}", i.field, i.reason))
        .collect()
}

/// A realm that requires MFA must offer a method that satisfies it — a
/// passkey (`webauthn`) or TOTP. Email OTP alone cannot (spec `mfa-policy`),
/// so such a realm could never complete a sign-in.
#[test]
fn a_realm_requiring_mfa_must_offer_a_qualifying_method() {
    let only_email = "realms:\n  shop:\n    auth:\n      mfa_methods: [email_otp]\n";
    let issues = mfa_method_issues(only_email);
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(
        issues[0].starts_with("realms.shop.auth.mfa_methods"),
        "{issues:?}"
    );

    let global_only_email = "auth:\n  mfa_methods: [email_otp]\nrealms:\n  shop: {}\n";
    assert_eq!(
        mfa_method_issues(global_only_email).len(),
        1,
        "inherited methods"
    );

    for ok in [
        "realms:\n  shop:\n    auth:\n      mfa_methods: [totp, email_otp]\n",
        "realms:\n  shop:\n    auth:\n      mfa_methods: [webauthn]\n",
        "realms:\n  shop:\n    auth:\n      mfa_required: false\n      mfa_methods: [email_otp]\n",
    ] {
        assert!(
            mfa_method_issues(ok).is_empty(),
            "{ok}: {:?}",
            mfa_method_issues(ok)
        );
    }
}

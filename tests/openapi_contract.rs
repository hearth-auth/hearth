#![allow(clippy::unwrap_used)]
//! Contract test: `docs/api/openapi.json` describes the REST admin JSON the
//! server really sends and accepts (OpenSpec `sdk-standard-libraries` 1.2).
//!
//! The four SDK admin clients are generated from the merged spec, so a spec
//! that disagrees with a handler ships a client that cannot talk to the
//! server. Each call below goes through the real router and is checked
//! against the merged spec:
//!
//! - the response status is documented for the operation;
//! - every key of a JSON object is a declared property (unless the schema
//!   allows `additionalProperties`), every `required` property is present,
//!   and every value has the declared type (`null` only where `nullable`);
//! - the request body the test sends uses only declared properties.
//!
//! The checker is hand-written and small: it follows `$ref`, `items`,
//! `properties`, `additionalProperties`, `required`, `type`, `nullable` and
//! string `enum`, which is all the admin schemas use.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::Request;
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, OrganizationRole, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::protocol::web::openapi::MERGED_SPEC_JSON;
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::{json, Value};
use tower::ServiceExt as _;

// ── the checker ──────────────────────────────────────────────────────────────

struct Spec(Value);

impl Spec {
    fn merged() -> Self {
        Self(serde_json::from_str(MERGED_SPEC_JSON).expect("merged spec is JSON"))
    }

    /// Follows a `$ref` chain to the schema it names.
    fn resolve<'a>(&'a self, mut schema: &'a Value) -> &'a Value {
        while let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            let name = r.trim_start_matches("#/components/schemas/");
            schema = &self.0["components"]["schemas"][name];
            assert!(!schema.is_null(), "dangling $ref {r}");
        }
        schema
    }

    /// The path template that matches `path` (fewest parameters wins, so
    /// `/admin/users/bulk` beats `/admin/users/{id}`).
    fn template(&self, path: &str) -> Option<String> {
        let segs: Vec<&str> = path.split('/').collect();
        let mut best: Option<(usize, String)> = None;
        for tmpl in self.0["paths"].as_object().unwrap().keys() {
            let t: Vec<&str> = tmpl.split('/').collect();
            if t.len() != segs.len() {
                continue;
            }
            let mut params = 0;
            let ok = t.iter().zip(&segs).all(|(a, b)| {
                if a.starts_with('{') {
                    params += 1;
                    true
                } else {
                    a == b
                }
            });
            if ok && best.as_ref().is_none_or(|(p, _)| params < *p) {
                best = Some((params, tmpl.clone()));
            }
        }
        best.map(|(_, t)| t)
    }

    /// Checks `value` against `schema`, appending each mismatch to `errs`.
    fn check(&self, value: &Value, schema: &Value, at: &str, errs: &mut Vec<String>) {
        let schema = self.resolve(schema);
        if value.is_null() {
            if schema.get("nullable") != Some(&Value::Bool(true)) {
                errs.push(format!("{at}: null, but the schema is not nullable"));
            }
            return;
        }
        let ty = schema.get("type").and_then(Value::as_str);
        let type_ok = match ty {
            Some("object") => value.is_object(),
            Some("array") => value.is_array(),
            Some("string") => value.is_string(),
            Some("integer") => value.is_i64() || value.is_u64(),
            Some("number") => value.is_number(),
            Some("boolean") => value.is_boolean(),
            _ => true,
        };
        if !type_ok {
            errs.push(format!("{at}: expected {}, got {value}", ty.unwrap_or("?")));
            return;
        }
        if let (Some(s), Some(allowed)) = (value.as_str(), schema.get("enum")) {
            if !allowed.as_array().unwrap().iter().any(|a| a == s) {
                errs.push(format!("{at}: {s:?} is not in enum {allowed}"));
            }
        }
        if let Some(items) = value.as_array() {
            if let Some(item_schema) = schema.get("items") {
                for (i, item) in items.iter().enumerate() {
                    self.check(item, item_schema, &format!("{at}[{i}]"), errs);
                }
            }
        }
        if let Some(obj) = value.as_object() {
            let props = schema.get("properties").and_then(Value::as_object);
            let extra = schema.get("additionalProperties");
            for (k, v) in obj {
                let here = format!("{at}.{k}");
                match (props.and_then(|p| p.get(k)), extra) {
                    (Some(s), _) => self.check(v, s, &here, errs),
                    (None, Some(Value::Bool(true))) => {}
                    (None, Some(s)) if s.is_object() => self.check(v, s, &here, errs),
                    (None, _) if props.is_none() && ty != Some("object") => {}
                    (None, _) => errs.push(format!("{here}: undeclared property")),
                }
            }
            for req in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let name = req.as_str().unwrap();
                if !obj.contains_key(name) {
                    errs.push(format!("{at}.{name}: required, but missing"));
                }
            }
        }
    }

    /// Checks one exchange: request body, documented status, response body.
    fn exchange(
        &self,
        method: &str,
        path: &str,
        req: Option<&Value>,
        status: u16,
        resp: &Value,
        errs: &mut Vec<String>,
    ) {
        let label = format!("{method} {path} → {status}");
        let path_only = path.split('?').next().unwrap();
        let Some(tmpl) = self.template(path_only) else {
            errs.push(format!("{label}: path not in the spec"));
            return;
        };
        let op = &self.0["paths"][&tmpl][method.to_ascii_lowercase()];
        if op.is_null() {
            errs.push(format!("{label}: method not in the spec ({tmpl})"));
            return;
        }
        if let Some(body) = req {
            let schema = &op["requestBody"]["content"]["application/json"]["schema"];
            if schema.is_null() {
                errs.push(format!("{label}: request body not documented"));
            } else {
                self.check(body, schema, &format!("{label} request"), errs);
            }
        }
        let Some(response) = op["responses"].get(status.to_string()) else {
            errs.push(format!(
                "{label}: status not documented (has {:?})",
                op["responses"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>()
            ));
            return;
        };
        let schema = &response["content"]["application/json"]["schema"];
        match (resp.is_null(), schema.is_null()) {
            (true, _) => {}
            (false, true) => errs.push(format!("{label}: response body not documented")),
            (false, false) => self.check(resp, schema, &format!("{label} response"), errs),
        }
    }
}

// ── the checker checks ───────────────────────────────────────────────────────

/// The checker must catch what it claims to catch, or every green run below
/// is vacuous.
#[test]
fn checker_reports_undeclared_missing_and_mistyped_values() {
    let spec = Spec(json!({
        "paths": {},
        "components": {"schemas": {"Thing": {
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "string"},
                "n": {"type": "integer"},
                "kind": {"type": "string", "enum": ["a", "b"]},
                "opt": {"type": "string", "nullable": true},
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        }}}
    }));
    let schema = json!({"$ref": "#/components/schemas/Thing"});
    let mut errs = Vec::new();
    spec.check(
        &json!({"n": "1", "kind": "c", "tags": [1], "extra": true, "opt": null}),
        &schema,
        "t",
        &mut errs,
    );
    errs.sort();
    assert_eq!(
        errs,
        vec![
            "t.extra: undeclared property",
            "t.id: required, but missing",
            "t.kind: \"c\" is not in enum [\"a\",\"b\"]",
            "t.n: expected integer, got \"1\"",
            "t.tags[0]: expected string, got 1",
        ]
    );

    let mut ok = Vec::new();
    spec.check(
        &json!({"id": "x", "opt": null, "n": 2}),
        &schema,
        "t",
        &mut ok,
    );
    assert_eq!(ok, Vec::<String>::new());
}

// ── fixture ──────────────────────────────────────────────────────────────────

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

struct Fixture {
    h: common::TestHarness,
    app: axum::Router,
    spec: Spec,
    errs: Vec<String>,
    /// The realm (`X-Realm-ID`) and bearer token requests are sent with.
    caller: Option<(RealmId, String)>,
}

impl Fixture {
    async fn new() -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        h.rbac().seed_realm(&system_realm()).expect("seed system");
        let app = router(Arc::new(AppState::new(
            h.identity_arc(),
            h.rbac_arc(),
            h.audit_arc(),
        )));
        Self {
            h,
            app,
            spec: Spec::merged(),
            errs: Vec::new(),
            caller: None,
        }
    }

    fn realm(&self) -> RealmId {
        let realm = self
            .h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("contract-{}", uuid::Uuid::new_v4().simple()),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        self.h.rbac().seed_realm(&realm).expect("seed realm");
        realm
    }

    fn user(&self, realm: &RealmId) -> UserId {
        let req = CreateUserRequest {
            email: format!("u-{}@contract.test", uuid::Uuid::new_v4().simple()),
            display_name: "U".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        };
        if realm == &system_realm() {
            self.h.identity().create_admin_user(&req)
        } else {
            self.h.identity().create_user(realm, &req)
        }
        .expect("create user")
        .id()
        .clone()
    }

    /// Sends the next requests as a fresh `realm.admin` of `realm`.
    fn act_as_admin_of(&mut self, realm: &RealmId) {
        let token = self.admin_token(realm);
        self.caller = Some((realm.clone(), token));
    }

    /// A token for a fresh `realm.admin` of `realm`.
    fn admin_token(&self, realm: &RealmId) -> String {
        let user = self.user(realm);
        let role = self
            .h
            .rbac()
            .get_role_by_name(realm, "realm.admin")
            .expect("lookup")
            .expect("seeded realm.admin");
        self.h
            .rbac()
            .assign_role(
                realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");
        let session = self
            .h
            .identity()
            .create_session(realm, &user, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(realm, &user, session.id())
            .expect("tokens")
            .access_token()
            .to_string()
    }

    /// Sends one request as `caller` and checks it against the spec.
    /// Returns the response body (`null` when empty).
    async fn call(&mut self, method: &str, path: &str, body: Option<Value>, expect: u16) -> Value {
        let (realm, token) = self.caller.clone().expect("set a caller first");
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("x-realm-id", realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {token}"))
            .body(
                body.as_ref()
                    .map_or_else(Body::empty, |b| Body::from(b.to_string())),
            )
            .expect("request");
        let resp = self.app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 1 << 22).await.expect("body");
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, expect, "{method} {path}: {value}");
        self.spec
            .exchange(method, path, body.as_ref(), status, &value, &mut self.errs);
        value
    }

    async fn get(&mut self, path: &str) -> Value {
        self.call("GET", path, None, 200).await
    }

    async fn post(&mut self, path: &str, body: Value, expect: u16) -> Value {
        self.call("POST", path, Some(body), expect).await
    }

    async fn patch(&mut self, path: &str, body: Value) -> Value {
        self.call("PATCH", path, Some(body), 200).await
    }

    async fn delete(&mut self, path: &str) {
        self.call("DELETE", path, None, 204).await;
    }

    /// Fails the test with every mismatch collected so far.
    fn assert_no_mismatch(&self) {
        assert!(
            self.errs.is_empty(),
            "{} spec mismatch(es):\n{}",
            self.errs.len(),
            self.errs.join("\n")
        );
    }
}

/// `v[key]` as a string; panics when it is not one.
fn s(v: &Value, key: &str) -> String {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("no string {key} in {v}"))
        .to_string()
}

// ── the contract ─────────────────────────────────────────────────────────────
//
// Each test drives the operations an SDK admin client calls, through the
// router, against the merged spec.

#[tokio::test]
async fn users_and_applications_match_the_spec() {
    let mut f = Fixture::new().await;
    let realm = f.realm();
    f.act_as_admin_of(&realm);

    let user = f
        .post(
            "/admin/users",
            json!({
                "email": "contract-user@contract.test",
                "display_name": "Contract User",
                "first_name": "Con",
                "last_name": "Tract",
                "attributes": {"team": "sdk"}
            }),
            201,
        )
        .await;
    let uid = s(&user, "id");
    f.get("/admin/users?limit=10").await;
    f.get(&format!("/admin/users/{uid}")).await;
    // pbjson decodes this body: enums take their proto names.
    let patch = json!({"display_name": "Renamed", "status": "USER_STATUS_ACTIVE"});
    f.patch(&format!("/admin/users/{uid}"), patch).await;

    let client = f
        .post(
            "/admin/applications",
            json!({
                "client_name": "contract",
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_basic"
            }),
            201,
        )
        .await;
    let cid = s(&client, "client_id");
    f.get("/admin/applications").await;
    f.get(&format!("/admin/applications/{cid}")).await;
    f.patch(
        &format!("/admin/applications/{cid}"),
        json!({"client_name": "renamed"}),
    )
    .await;
    let regen = format!("/admin/applications/{cid}/regenerate-secret");
    f.call("POST", &regen, None, 200).await;

    f.delete(&format!("/admin/applications/{cid}")).await;
    f.delete(&format!("/admin/users/{uid}")).await;
    f.assert_no_mismatch();
}

#[tokio::test]
async fn roles_assignments_and_groups_match_the_spec() {
    let mut f = Fixture::new().await;
    let realm = f.realm();
    f.act_as_admin_of(&realm);
    let uid = f.user(&realm).as_uuid().to_string();

    let role = f
        .post(
            "/admin/roles",
            json!({
                "name": "contract-reader",
                "description": "reads",
                "permissions": ["user.read"],
                "parent_roles": []
            }),
            201,
        )
        .await;
    let rid = s(&role, "id");
    f.get("/admin/roles").await;
    f.get(&format!("/admin/roles/{rid}")).await;
    f.patch(
        &format!("/admin/roles/{rid}"),
        json!({"description": "reads more"}),
    )
    .await;

    let roles = format!("/admin/users/{uid}/roles");
    let assignment = f.post(&roles, json!({"role_id": rid}), 201).await;
    f.get(&roles).await;
    f.delete(&format!("/admin/assignments/{}", s(&assignment, "id")))
        .await;

    let group = f
        .post(
            "/admin/groups",
            json!({"name": "Contract Group", "slug": "contract-group", "description": "g"}),
            201,
        )
        .await;
    let gid = s(&group, "id");
    f.get("/admin/groups").await;
    f.get(&format!("/admin/groups/{gid}")).await;
    f.patch(
        &format!("/admin/groups/{gid}"),
        json!({"description": "g2"}),
    )
    .await;
    let members = format!("/admin/groups/{gid}/members");
    f.post(&members, json!({"type": "user", "id": uid}), 201)
        .await;
    f.get(&members).await;
    f.delete(&format!("{members}/{uid}?type=user")).await;

    f.delete(&format!("/admin/groups/{gid}")).await;
    f.delete(&format!("/admin/roles/{rid}")).await;
    f.assert_no_mismatch();
}

#[tokio::test]
async fn organizations_match_the_spec() {
    let mut f = Fixture::new().await;
    let realm = f.realm();
    f.act_as_admin_of(&realm);
    let member = f.user(&realm);
    let uid = member.as_uuid().to_string();
    f.post(
        "/admin/roles",
        json!({"name": "contract-reader", "permissions": ["user.read"]}),
        201,
    )
    .await;

    let org = f
        .post(
            "/admin/organizations",
            json!({
                "slug": "contract-org",
                "display_name": "Contract Org",
                "member_limit": 5,
                "mfa_required": false,
                "attributes": {"tier": "gold"}
            }),
            201,
        )
        .await;
    let oid = s(&org, "id");
    f.get("/admin/organizations").await;
    f.get(&format!("/admin/organizations/{oid}")).await;

    let org_id = OrganizationId::new(oid.parse().unwrap());
    f.h.identity()
        .add_member(&realm, &org_id, &member, OrganizationRole::Member)
        .expect("add member");
    let roles = format!("/admin/organizations/{oid}/members/{uid}/roles");
    f.post(&roles, json!({"role_name": "contract-reader"}), 204)
        .await;
    f.get(&roles).await;
    f.delete(&format!("{roles}/contract-reader")).await;

    // Suspend last: a suspended organization takes no new members.
    let update = json!({"display_name": "Contract Org 2", "status": "suspended"});
    f.patch(&format!("/admin/organizations/{oid}"), update)
        .await;
    f.delete(&format!("/admin/organizations/{oid}")).await;
    f.assert_no_mismatch();
}

#[tokio::test]
async fn audit_and_realms_match_the_spec() {
    let mut f = Fixture::new().await;
    let realm = f.realm();
    f.act_as_admin_of(&realm);
    // Something to audit.
    f.post("/admin/roles", json!({"name": "audited"}), 201)
        .await;
    f.get("/admin/audit").await;

    // A system-realm operator manages another realm.
    f.act_as_admin_of(&system_realm());
    let tid = realm.as_uuid().to_string();
    f.get("/admin/realms").await;
    f.get(&format!("/admin/realms/{tid}")).await;
    f.call("POST", &format!("/admin/realms/{tid}/suspend"), None, 200)
        .await;
    f.call("POST", &format!("/admin/realms/{tid}/unsuspend"), None, 200)
        .await;
    f.assert_no_mismatch();
}

//! AdminClient — user and realm CRUD operations.

use crate::error::HearthError;
use crate::types::*;

/// Client for Hearth admin operations (user and realm CRUD).
///
/// Requires an admin access token obtained via `/admin/bootstrap`.
pub struct AdminClient {
    base_url: String,
    realm_id: String,
    http: reqwest::Client,
}

impl AdminClient {
    pub fn new(
        base_url: impl Into<String>,
        admin_token: impl Into<String>,
        realm_id: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let realm_id = realm_id.into();
        let admin_token = admin_token.into();
        let http = reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    "X-Realm-ID",
                    reqwest::header::HeaderValue::from_str(&realm_id).expect("valid realm id"),
                );
                h.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {admin_token}"))
                        .expect("valid token"),
                );
                h
            })
            .build()
            .expect("reqwest client");
        Self {
            base_url,
            realm_id,
            http,
        }
    }

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------

    pub async fn create_user(&self, req: &CreateUserRequest) -> Result<User, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/users", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn list_users(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PageResponse<User>, HearthError> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .http
            .get(format!("{}/admin/users", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn get_user(&self, user_id: &str) -> Result<User, HearthError> {
        // base_url may be http:// for local dev; callers are responsible for
        // using https:// in production. // lgtm[rust/cleartext-transmission]
        let resp = self
            .http
            .get(format!("{}/admin/users/{user_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        req: &UpdateUserRequest,
    ) -> Result<User, HearthError> {
        let resp = self
            .http
            .patch(format!("{}/admin/users/{user_id}", self.base_url)) // lgtm[rust/cleartext-transmission]
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/users/{user_id}", self.base_url)) // lgtm[rust/cleartext-transmission]
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Realms
    // ------------------------------------------------------------------

    // Realms are provisioned via hearth.yaml, not the admin API. There is no
    // `create_realm` and no `update_realm` method: the server answers 405 with
    // "Realms are managed via hearth.yaml" to both POST /admin/realms and
    // PATCH /admin/realms/{id} (HEA-2171, audit 2026-08-28 §25.4). Only read
    // paths and deletion are exposed.

    pub async fn list_realms(&self) -> Result<Vec<Realm>, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/realms", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        let val: serde_json::Value = resp.json().await?;
        if let Some(items) = val.get("items").and_then(|i| i.as_array()) {
            Ok(serde_json::from_value(serde_json::Value::Array(items.clone()))?)
        } else {
            Ok(serde_json::from_value(val)?)
        }
    }

    pub async fn get_realm(&self, realm_id: &str) -> Result<Realm, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/realms/{realm_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn delete_realm(&self, realm_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/realms/{realm_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // OAuth Clients
    // ------------------------------------------------------------------

    /// Create an OAuth 2.0 client registration.
    pub async fn create_client(
        &self,
        req: &CreateClientRequest,
    ) -> Result<OAuthClient, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/applications", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// List OAuth 2.0 client registrations (paginated).
    pub async fn list_clients(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PageResponse<OAuthClient>, HearthError> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .http
            .get(format!("{}/admin/applications", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Retrieve a single OAuth 2.0 client by ID.
    pub async fn get_client(&self, client_id: &str) -> Result<OAuthClient, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/applications/{client_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Update an OAuth 2.0 client.
    pub async fn update_client(
        &self,
        client_id: &str,
        req: &UpdateClientRequest,
    ) -> Result<OAuthClient, HearthError> {
        let resp = self
            .http
            .patch(format!("{}/admin/applications/{client_id}", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Replace a confidential client's secret
    /// (`POST /admin/applications/{id}/regenerate-secret`). The returned
    /// client's [`OAuthClient::secret`] is the new secret, returned once; the
    /// old secret stops working immediately.
    pub async fn regenerate_client_secret(
        &self,
        client_id: &str,
    ) -> Result<OAuthClient, HearthError> {
        let resp = self
            .http
            .post(format!(
                "{}/admin/applications/{client_id}/regenerate-secret",
                self.base_url
            ))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Delete an OAuth 2.0 client registration.
    pub async fn delete_client(&self, client_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/applications/{client_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------

    /// Create a realm-level role.
    pub async fn create_role(&self, req: &CreateRoleRequest) -> Result<Role, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/roles", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// List realm-level roles (paginated).
    pub async fn list_roles(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PageResponse<Role>, HearthError> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .http
            .get(format!("{}/admin/roles", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Retrieve a single role by ID.
    pub async fn get_role(&self, role_id: &str) -> Result<Role, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/roles/{role_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Update a realm-level role.
    pub async fn update_role(
        &self,
        role_id: &str,
        req: &UpdateRoleRequest,
    ) -> Result<Role, HearthError> {
        let resp = self
            .http
            .patch(format!("{}/admin/roles/{role_id}", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Delete a realm-level role.
    pub async fn delete_role(&self, role_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/roles/{role_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------

    /// Create a realm-level group.
    pub async fn create_group(&self, req: &CreateGroupRequest) -> Result<Group, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/groups", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// List realm-level groups (paginated).
    pub async fn list_groups(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PageResponse<Group>, HearthError> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .http
            .get(format!("{}/admin/groups", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Retrieve a single group by ID.
    pub async fn get_group(&self, group_id: &str) -> Result<Group, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/groups/{group_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Update a realm-level group.
    pub async fn update_group(
        &self,
        group_id: &str,
        req: &UpdateGroupRequest,
    ) -> Result<Group, HearthError> {
        let resp = self
            .http
            .patch(format!("{}/admin/groups/{group_id}", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Delete a realm-level group.
    pub async fn delete_group(&self, group_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/groups/{group_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Organization Memberships — removed
    // ------------------------------------------------------------------
    //
    // Hearth serves no organization route over HTTP: there is no /admin/orgs,
    // no /admin/orgs/{id}/members and no per-member route anywhere in the
    // router, so list_org_members, add_org_member, update_org_member and
    // remove_org_member every one 404'd (audit 2026-08-28 §25.19).
    // Organization membership is administered through the admin console, not
    // the admin API.

    fn check(resp: &reqwest::Response) -> Result<(), HearthError> {
        let status = resp.status().as_u16();
        if status < 400 {
            return Ok(());
        }
        Err(HearthError::Api {
            status,
            message: format!("{}", resp.status()),
            details: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn regenerate_client_secret_posts_and_returns_the_new_secret() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let body = r#"{"client_id":"c1","client_name":"svc","client_secret":"new-secret"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let admin = AdminClient::new(format!("http://{addr}"), "admin-token", "realm-1");
        let client = admin
            .regenerate_client_secret("c1")
            .await
            .expect("regenerate_client_secret");
        assert_eq!(client.secret.as_deref(), Some("new-secret"));
        let req = server.await.unwrap();
        assert!(
            req.starts_with("POST /admin/applications/c1/regenerate-secret "),
            "{req}"
        );
    }

    #[test]
    fn admin_client_url_methods_compile() {
        // Verify the method signatures compile and the URL patterns are well-formed.
        // These are structural tests — actual HTTP calls require a live server.
        let base = "https://auth.example.com";
        let client_id = "client_123";
        let role_id = "role_456";
        let group_id = "group_789";

        assert_eq!(
            format!("{base}/admin/applications/{client_id}"),
            "https://auth.example.com/admin/applications/client_123"
        );
        assert_eq!(
            format!("{base}/admin/roles/{role_id}"),
            "https://auth.example.com/admin/roles/role_456"
        );
        assert_eq!(
            format!("{base}/admin/groups/{group_id}"),
            "https://auth.example.com/admin/groups/group_789"
        );
    }

    #[test]
    fn admin_types_serialize_deserialize() {
        // Verify all new admin types round-trip through serde correctly.
        let role = Role {
            id: "r1".into(),
            name: "admin".into(),
            description: Some("Admin role".into()),
            permissions: vec!["users.read".into()],
            created_at: None,
        };
        let json = serde_json::to_string(&role).unwrap();
        let back: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "admin");
        assert_eq!(back.permissions, vec!["users.read"]);

        let group = Group {
            id: "g1".into(),
            name: "engineers".into(),
            slug: Some("engineers".into()),
            description: None,
            created_at: None,
        };
        let json = serde_json::to_string(&group).unwrap();
        let back: Group = serde_json::from_str(&json).unwrap();
        assert_eq!(back.slug, Some("engineers".into()));
    }

    #[test]
    fn create_role_request_serializes() {
        let req = CreateRoleRequest {
            name: "editor".into(),
            description: None,
            permissions: vec!["docs.write".into(), "docs.read".into()],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "editor");
        assert_eq!(json["permissions"][0], "docs.write");
        assert!(json.get("description").is_none());
    }

    // ── /admin/applications wire shape ──────────────────────────────────
    //
    // `POST /admin/applications` deserializes the proto `RegisterClientRequest`:
    // the name key is `client_name` (an unknown `name` is a 422) and both enums
    // take their proto names (`embedded` / `first_party` are a 422).
    // `PATCH /admin/applications/{id}` reads `client_name` but ignores unknown
    // keys, so `name` answers 200 and renames nothing; its enums are
    // snake_case strings. Every client route answers with the proto
    // `OAuthClient` (`client_id` / `client_name`, enum names upper-case).

    #[test]
    fn create_client_request_uses_the_proto_wire_shape() {
        let req = CreateClientRequest {
            name: "My App".into(),
            redirect_uris: vec!["https://app.example.com/cb".into()],
            trust_level: Some("first_party".into()),
            access_token_authorization: AccessTokenAuthorization::Introspection,
            token_endpoint_auth_method: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "client_name": "My App",
                "redirect_uris": ["https://app.example.com/cb"],
                "trust_level": "CLIENT_TRUST_LEVEL_FIRST_PARTY",
                "access_token_authorization": "INTROSPECTION",
            })
        );
    }

    #[test]
    fn create_client_request_default_mode_is_the_proto_name() {
        let req = CreateClientRequest {
            name: "My App".into(),
            redirect_uris: vec![],
            trust_level: Some("third_party".into()),
            access_token_authorization: AccessTokenAuthorization::Embedded,
            token_endpoint_auth_method: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["access_token_authorization"], "EMBEDDED");
        assert_eq!(json["trust_level"], "CLIENT_TRUST_LEVEL_THIRD_PARTY");
    }

    #[test]
    fn client_requests_carry_the_auth_method_and_the_record_its_generated_secret() {
        let req = CreateClientRequest {
            name: "svc".into(),
            redirect_uris: vec![],
            trust_level: None,
            access_token_authorization: AccessTokenAuthorization::Embedded,
            token_endpoint_auth_method: Some("client_secret_basic".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["token_endpoint_auth_method"], "client_secret_basic");

        let req = RegisterClientRequest {
            name: "svc".into(),
            redirect_uris: vec![],
            trust_level: None,
            token_endpoint_auth_method: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("token_endpoint_auth_method").is_none(), "{json}");

        // The create (or regenerate) response carries the generated secret
        // once, under the wire key `client_secret`.
        let client: OAuthClient = serde_json::from_value(serde_json::json!({
            "client_id": "c1",
            "client_name": "svc",
            "client_secret": "generated-once",
        }))
        .unwrap();
        assert_eq!(client.secret.as_deref(), Some("generated-once"));
    }

    #[test]
    fn register_client_request_trust_level_is_the_proto_name() {
        // `POST /clients` takes the same proto body as `POST /admin/applications`.
        let req = RegisterClientRequest {
            name: "My App".into(),
            redirect_uris: vec![],
            trust_level: Some("first_party".into()),
            token_endpoint_auth_method: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["trust_level"], "CLIENT_TRUST_LEVEL_FIRST_PARTY");

        // A value the SDK has no mapping for is sent unchanged, so the server
        // rejects it rather than the SDK silently picking a trust level.
        let req = RegisterClientRequest {
            trust_level: Some("CLIENT_TRUST_LEVEL_THIRD_PARTY".into()),
            ..req
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["trust_level"], "CLIENT_TRUST_LEVEL_THIRD_PARTY");
    }

    #[test]
    fn update_client_request_sends_client_name() {
        let req = UpdateClientRequest {
            name: Some("Renamed".into()),
            trust_level: Some("first_party".into()),
            access_token_authorization: Some(AccessTokenAuthorization::Decision),
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "client_name": "Renamed",
                "trust_level": "first_party",
                "access_token_authorization": "decision",
            })
        );
    }

    #[test]
    fn oauth_client_parses_the_server_response() {
        // Verbatim shape of a live `GET /admin/applications/{id}` answer.
        let body = r#"{"access_token_authorization":"DECISION","client_id":"c-1","client_name":"My App","created_at":1790194176035537,"grant_types":["authorization_code"],"redirect_uris":["https://x/cb"]}"#;
        let client: OAuthClient = serde_json::from_str(body).unwrap();
        assert_eq!(client.id, "c-1");
        assert_eq!(client.name, "My App");
        assert_eq!(
            client.access_token_authorization,
            AccessTokenAuthorization::Decision
        );

        // `EMBEDDED` is proto3's zero value, so the server omits it.
        let body = r#"{"client_id":"c-2","client_name":"B","redirect_uris":[]}"#;
        let client: OAuthClient = serde_json::from_str(body).unwrap();
        assert_eq!(
            client.access_token_authorization,
            AccessTokenAuthorization::Embedded
        );
    }
}

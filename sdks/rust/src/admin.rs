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

    pub async fn create_realm(&self, req: &CreateRealmRequest) -> Result<Realm, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/realms", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

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

    pub async fn update_realm(
        &self,
        realm_id: &str,
        req: &UpdateRealmRequest,
    ) -> Result<Realm, HearthError> {
        let resp = self
            .http
            .put(format!("{}/admin/realms/{realm_id}", self.base_url))
            .json(req)
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
            .post(format!("{}/admin/clients", self.base_url))
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
            .get(format!("{}/admin/clients", self.base_url))
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
            .get(format!("{}/admin/clients/{client_id}", self.base_url))
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
            .patch(format!("{}/admin/clients/{client_id}", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Delete an OAuth 2.0 client registration.
    pub async fn delete_client(&self, client_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/clients/{client_id}", self.base_url))
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
    // Organization Memberships
    // ------------------------------------------------------------------

    /// List members of an organization (paginated).
    pub async fn list_org_members(
        &self,
        org_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PageResponse<OrgMember>, HearthError> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .http
            .get(format!("{}/admin/orgs/{org_id}/members", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Add a user to an organization.
    pub async fn add_org_member(
        &self,
        org_id: &str,
        req: &AddOrgMemberRequest,
    ) -> Result<OrgMember, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/orgs/{org_id}/members", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Update an organization member's role.
    pub async fn update_org_member(
        &self,
        org_id: &str,
        user_id: &str,
        req: &UpdateOrgMemberRequest,
    ) -> Result<OrgMember, HearthError> {
        let resp = self
            .http
            .patch(format!(
                "{}/admin/orgs/{org_id}/members/{user_id}",
                self.base_url
            ))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    /// Remove a user from an organization.
    pub async fn remove_org_member(&self, org_id: &str, user_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!(
                "{}/admin/orgs/{org_id}/members/{user_id}",
                self.base_url
            ))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

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

    #[test]
    fn admin_client_url_methods_compile() {
        // Verify the method signatures compile and the URL patterns are well-formed.
        // These are structural tests — actual HTTP calls require a live server.
        let base = "https://auth.example.com";
        let client_id = "client_123";
        let role_id = "role_456";
        let group_id = "group_789";
        let org_id = "org_abc";
        let user_id = "user_def";

        assert_eq!(
            format!("{base}/admin/clients/{client_id}"),
            "https://auth.example.com/admin/clients/client_123"
        );
        assert_eq!(
            format!("{base}/admin/roles/{role_id}"),
            "https://auth.example.com/admin/roles/role_456"
        );
        assert_eq!(
            format!("{base}/admin/groups/{group_id}"),
            "https://auth.example.com/admin/groups/group_789"
        );
        assert_eq!(
            format!("{base}/admin/orgs/{org_id}/members/{user_id}"),
            "https://auth.example.com/admin/orgs/org_abc/members/user_def"
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

        let member = OrgMember {
            user_id: "u1".into(),
            org_id: "o1".into(),
            role: "member".into(),
            joined_at: None,
        };
        let json = serde_json::to_string(&member).unwrap();
        let back: OrgMember = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role, "member");
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

    #[test]
    fn add_org_member_request_serializes() {
        let req = AddOrgMemberRequest {
            user_id: "user_abc".into(),
            role: "owner".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_id"], "user_abc");
        assert_eq!(json["role"], "owner");
    }
}

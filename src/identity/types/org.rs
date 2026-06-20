//! Organization types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::{InvitationId, OrganizationId, Timestamp, UserId};

/// The lifecycle status of an organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OrganizationStatus {
    /// Organization is active; members can operate normally.
    Active,
    /// Organization is suspended by an administrator.
    Suspended,
    /// Organization was removed from YAML config and soft-deleted.
    ///
    /// Behaves like `Suspended` (new membership operations denied) but
    /// additionally signals that the org can be permanently deleted from
    /// the admin UI. Restored to `Active` if the org slug reappears in YAML.
    Archived,
}

/// Per-organization configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationConfig {
    /// Maximum number of members allowed. `None` means unlimited.
    pub max_members: Option<u32>,
}

/// An organization within a realm.
///
/// Organizations represent B2B customer groups. Users can be members of
/// multiple organizations within the same realm. Fields are private;
/// access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    id: OrganizationId,
    name: String,
    slug: String,
    description: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attributes: BTreeMap<String, String>,
    status: OrganizationStatus,
    config: OrganizationConfig,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Organization {
    /// Creates a new organization. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: OrganizationId,
        name: String,
        slug: String,
        description: String,
        status: OrganizationStatus,
        config: OrganizationConfig,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            name,
            slug,
            description,
            attributes: BTreeMap::new(),
            status,
            config,
            created_at,
            updated_at,
        }
    }

    /// Returns the organization's unique identifier.
    pub fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// Returns the organization's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the organization's URL-safe slug.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Returns the organization's description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the organization's custom attribute map.
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Returns the organization's lifecycle status.
    pub fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// Returns the organization's configuration.
    pub fn config(&self) -> &OrganizationConfig {
        &self.config
    }

    /// Returns when the organization was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the organization was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the name. Used internally during organization updates.
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Updates the description. Used internally during organization updates.
    pub(crate) fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Replaces the attributes map. Used internally during organization updates.
    pub(crate) fn set_attributes(&mut self, attributes: BTreeMap<String, String>) {
        self.attributes = attributes;
    }

    /// Updates the status. Used internally during organization updates.
    pub(crate) fn set_status(&mut self, status: OrganizationStatus) {
        self.status = status;
    }

    /// Updates the configuration. Used internally during organization updates.
    pub(crate) fn set_config(&mut self, config: OrganizationConfig) {
        self.config = config;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// A role within an organization.
///
/// Roles form a hierarchy: Owner > Admin > Member. Higher roles
/// inherit the capabilities of lower roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRole {
    /// Full control including delete, role management, and billing.
    Owner,
    /// Can manage members and settings but not delete the org.
    Admin,
    /// Basic membership with access to org resources.
    Member,
}

/// A membership record linking a user to an organization.
///
/// Stored as bidirectional indexes (org→user and user→org) for
/// efficient lookups in both directions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMembership {
    org_id: OrganizationId,
    user_id: UserId,
    role: OrganizationRole,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional_roles: Vec<String>,
    joined_at: Timestamp,
    invited_by: Option<UserId>,
}

impl OrganizationMembership {
    /// Creates a new membership. Used internally by the identity engine.
    pub(crate) fn new(
        org_id: OrganizationId,
        user_id: UserId,
        role: OrganizationRole,
        joined_at: Timestamp,
        invited_by: Option<UserId>,
    ) -> Self {
        Self {
            org_id,
            user_id,
            role,
            additional_roles: Vec::new(),
            joined_at,
            invited_by,
        }
    }

    /// Returns the organization this membership belongs to.
    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    /// Returns the user who is a member.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the member's role within the organization.
    pub fn role(&self) -> OrganizationRole {
        self.role
    }

    /// Additional organization-scoped RBAC roles layered on top of the
    /// canonical membership tier.
    pub fn additional_roles(&self) -> &[String] {
        &self.additional_roles
    }

    /// Returns when the user joined the organization (UTC microseconds).
    pub fn joined_at(&self) -> Timestamp {
        self.joined_at
    }

    /// Returns who invited this member, if applicable.
    pub fn invited_by(&self) -> Option<&UserId> {
        self.invited_by.as_ref()
    }

    /// Updates the role. Used internally during role changes.
    pub(crate) fn set_role(&mut self, role: OrganizationRole) {
        self.role = role;
    }

    /// Replaces the additional role set.
    #[allow(dead_code)]
    pub(crate) fn set_additional_roles(&mut self, roles: Vec<String>) {
        self.additional_roles = roles;
    }
}

/// The status of an organization invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    /// Invitation has been sent but not yet acted upon.
    Pending,
    /// Invitation was accepted; the user is now a member.
    Accepted,
    /// Invitation was revoked by an admin before acceptance.
    Revoked,
    /// Invitation expired before the recipient acted.
    Expired,
}

/// An invitation to join an organization.
///
/// The token is stored as a SHA-256 hash. The plaintext token is returned
/// only once at creation time and never persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    id: InvitationId,
    org_id: OrganizationId,
    email: String,
    role: OrganizationRole,
    token_hash: String,
    status: InvitationStatus,
    expires_at: Timestamp,
    invited_by: UserId,
    created_at: Timestamp,
}

impl OrganizationInvitation {
    /// Creates a new invitation. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: InvitationId,
        org_id: OrganizationId,
        email: String,
        role: OrganizationRole,
        token_hash: String,
        status: InvitationStatus,
        expires_at: Timestamp,
        invited_by: UserId,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            org_id,
            email,
            role,
            token_hash,
            status,
            expires_at,
            invited_by,
            created_at,
        }
    }

    /// Returns the invitation's unique identifier.
    pub fn id(&self) -> &InvitationId {
        &self.id
    }

    /// Returns which organization this invitation is for.
    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    /// Returns the email address the invitation was sent to.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the role the invitee will receive upon acceptance.
    pub fn role(&self) -> OrganizationRole {
        self.role
    }

    /// Returns the SHA-256 hash of the invitation token.
    pub(crate) fn token_hash(&self) -> &str {
        &self.token_hash
    }

    /// Returns the invitation's current status.
    pub fn status(&self) -> InvitationStatus {
        self.status
    }

    /// Returns when the invitation expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns who created this invitation.
    pub fn invited_by(&self) -> &UserId {
        &self.invited_by
    }

    /// Returns when the invitation was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Marks the invitation as accepted.
    pub(crate) fn set_accepted(&mut self) {
        self.status = InvitationStatus::Accepted;
    }

    /// Marks the invitation as revoked.
    pub(crate) fn set_revoked(&mut self) {
        self.status = InvitationStatus::Revoked;
    }
}

/// Request to create a new organization.
#[derive(Clone, Debug, Default)]
pub struct CreateOrganizationRequest {
    /// Display name for the organization.
    pub name: String,
    /// URL-safe slug (lowercase alphanumeric + hyphens, 3-63 chars).
    pub slug: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional configuration overrides.
    pub config: Option<OrganizationConfig>,
    /// Custom attribute key-value pairs.
    pub attributes: BTreeMap<String, String>,
}

/// Request to update an existing organization.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateOrganizationRequest {
    /// New display name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// New lifecycle status.
    pub status: Option<OrganizationStatus>,
    /// New configuration overrides.
    pub config: Option<OrganizationConfig>,
    /// Replace the custom attribute map. `None` leaves existing attributes unchanged.
    pub attributes: Option<BTreeMap<String, String>>,
}

/// Request to create an invitation to join an organization.
#[derive(Clone, Debug)]
pub struct CreateInvitationRequest {
    /// Organization to invite the user to.
    pub org_id: OrganizationId,
    /// Email address of the invitee.
    pub email: String,
    /// Role to assign upon acceptance.
    pub role: OrganizationRole,
    /// User who is creating the invitation.
    pub invited_by: UserId,
}

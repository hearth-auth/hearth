//! The records of one backup member, restored together (#896).

use super::{
    AgentExport, ConsentExport, FederationLinkExport, MfaFactorExport, Organization,
    OrganizationInvitation, OrganizationMembership, RevocationExport, ScimMappingExport,
};

/// The records of one backup member that a restore imports together with
/// [`IdentityEngine::import_records`](crate::identity::IdentityEngine::import_records).
///
/// Each variant holds records of the member a realm can hold millions of.
/// The engine validates and writes each record as the one-record import of
/// its member does (`import_organization`, `import_mfa_factor`, ...), and
/// many records share each durable write.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum ImportRecords<'a> {
    /// Records of `organizations.ndjson`.
    Organizations(&'a [Organization]),
    /// Records of `mfa_factors.ndjson`.
    MfaFactors(&'a [MfaFactorExport]),
    /// Records of `organization_memberships.ndjson`.
    OrganizationMemberships(&'a [OrganizationMembership]),
    /// Records of `consents.ndjson`.
    Consents(&'a [ConsentExport]),
    /// Records of `agents.ndjson`.
    Agents(&'a [AgentExport]),
    /// Records of `federation_links.ndjson`.
    FederationLinks(&'a [FederationLinkExport]),
    /// Records of `scim_mappings.ndjson`.
    ScimMappings(&'a [ScimMappingExport]),
    /// Records of `invitations.ndjson`.
    Invitations(&'a [OrganizationInvitation]),
    /// Records of `revocations.ndjson`.
    Revocations(&'a [RevocationExport]),
}

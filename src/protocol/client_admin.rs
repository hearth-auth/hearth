//! Administrative OAuth-client operations shared by the REST and gRPC admin
//! surfaces, so the two cannot drift (a per-surface copy is how the gRPC
//! create path came to accept caller-chosen secrets that REST refused).

use crate::audit::{AuditAction, AuditEngine, CreateAuditEvent};
use crate::core::{ClientId, RealmId, UserId};
use crate::identity::{IdentityEngine, IdentityError, OAuthClient, RegisterClientRequest};
use crate::protocol::proto::identity::v1 as pb;

/// The admin create response for `client`: the client record plus — for a
/// confidential client whose secret Hearth generated from `request` — that
/// secret, the one time it is returned. Only its hash is stored.
pub(crate) fn created_client_record(
    client: &OAuthClient,
    request: &RegisterClientRequest,
) -> pb::OAuthClient {
    let mut record = pb::OAuthClient::from(client);
    record.client_secret = request
        .generated_client_secret
        .as_ref()
        .map(|g| g.expose().to_string());
    record
}

/// Regenerates a confidential client's secret for an authenticated admin and
/// audits it (`client_updated`, `change: client_secret_regenerated`, with the
/// acting admin). The record returned carries the new secret, once; the old
/// secret stops authenticating as soon as the new hash is stored.
///
/// # Errors
/// [`IdentityError::ClientNotFound`] for an unknown client;
/// [`IdentityError::InvalidInput`] for a public client;
/// [`IdentityError::FapiViolation`] for a FAPI 2.0 client or in a FAPI 2.0
/// Advanced realm.
pub(crate) fn regenerate_client_secret(
    identity: &dyn IdentityEngine,
    audit: &dyn AuditEngine,
    realm_id: &RealmId,
    actor: &UserId,
    client_id: &ClientId,
    via: &str,
) -> Result<pb::OAuthClient, IdentityError> {
    let secret = identity.regenerate_client_secret(realm_id, client_id)?;
    let client = identity
        .get_client(realm_id, client_id)?
        .ok_or(IdentityError::ClientNotFound)?;
    crate::protocol::audit_log::record(
        audit,
        &CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: actor.as_uuid().to_string(),
            action: AuditAction::ClientUpdated,
            resource_type: "client".to_string(),
            resource_id: client_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "via": via,
                "change": "client_secret_regenerated",
            })),
        },
    );
    let mut record = pb::OAuthClient::from(&client);
    record.client_secret = Some(secret);
    Ok(record)
}

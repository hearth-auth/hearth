//! `OAuthService` gRPC implementation.
//!
//! The OAuth surface authenticates via per-RPC client credentials (not the
//! admin bearer interceptor). The target realm is supplied via the
//! `x-realm-id` metadata header, same as the admin surface — gRPC clients
//! typically have dedicated per-realm stubs so this is not a usability
//! burden.

use tonic::{Request, Response, Status};

use crate::core::ClientId;
use crate::identity::{self as domain, DeviceAuthorizationRequest};
use crate::protocol::convert::oauth::{
    proto_authorize_to_domain, proto_client_creds_to_domain, proto_token_exchange_to_domain,
};
use crate::protocol::proto::identity::v1 as pb;
use crate::protocol::proto::identity::v1::o_auth_service_server::OAuthService;

use super::convert::{
    extract_grpc_user_auth, extract_realm_id, identity_to_status, verify_grpc_client_auth,
};
use super::server::GrpcState;

pub struct OAuthSvc {
    state: GrpcState,
}

impl OAuthSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl OAuthService for OAuthSvc {
    async fn authorize(
        &self,
        req: Request<pb::AuthorizationRequest>,
    ) -> Result<Response<pb::AuthorizationResponse>, Status> {
        use crate::identity::{AuthorizationRequest, IdentityError};

        let realm_id = extract_realm_id(req.metadata())?;
        // HEA-1721: authenticate the caller; their token's `sub` is the authoritative user identity.
        let authenticated_user_id =
            extract_grpc_user_auth(req.metadata(), &realm_id, self.state.identity.as_ref())?;
        let body = req.into_inner();

        // PAR path: when `request_uri` is present, consume the stored entry to
        // obtain pre-validated parameters with `via_par = true`.
        let domain_req = if let Some(ref request_uri) = body.request_uri {
            let stored = self
                .state
                .identity
                .consume_par(&realm_id, request_uri)
                .map_err(|e| match e {
                    IdentityError::InvalidPushedAuthorizationRequest => {
                        Status::invalid_argument("invalid or expired request_uri")
                    }
                    other => identity_to_status(other),
                })?;
            AuthorizationRequest {
                client_id: stored.client_id,
                redirect_uri: stored.redirect_uri,
                scope: stored.scope,
                state: stored.state,
                resource: stored.resource,
                response_type: stored.response_type,
                user_id: authenticated_user_id,
                code_challenge: stored.code_challenge,
                code_challenge_method: stored.code_challenge_method,
                nonce: stored.nonce,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: true,
            }
        } else {
            let mut r = proto_authorize_to_domain(body).map_err(Status::invalid_argument)?;
            // Override body-supplied user_id with the authenticated identity (HEA-1721).
            r.user_id = authenticated_user_id;
            r
        };

        let resp = self
            .state
            .identity
            .authorize(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::AuthorizationResponse::from(&resp)))
    }

    async fn token_exchange(
        &self,
        req: Request<pb::TokenExchangeRequest>,
    ) -> Result<Response<pb::OidcTokenResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let domain_req = proto_token_exchange_to_domain(&body).map_err(Status::invalid_argument)?;
        let resp = self
            .state
            .identity
            .exchange_authorization_code(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OidcTokenResponse::from(&resp)))
    }

    async fn revoke(
        &self,
        req: Request<pb::TokenRevocationRequest>,
    ) -> Result<Response<pb::OAuthEmpty>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        verify_grpc_client_auth(req.metadata(), &realm_id, self.state.identity.as_ref())?;
        let body: domain::TokenRevocationRequest = req.into_inner().into();
        self.state
            .identity
            .revoke_token(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthEmpty {}))
    }

    async fn introspect(
        &self,
        req: Request<pb::TokenIntrospectionRequest>,
    ) -> Result<Response<pb::IntrospectionResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        verify_grpc_client_auth(req.metadata(), &realm_id, self.state.identity.as_ref())?;
        let body: domain::TokenIntrospectionRequest = req.into_inner().into();
        let resp = self
            .state
            .identity
            .introspect_token(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::IntrospectionResponse::from(&resp)))
    }

    async fn device_authorize(
        &self,
        req: Request<pb::DeviceAuthorizationRequest>,
    ) -> Result<Response<pb::DeviceAuthorizationResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let client_id = body
            .client_id
            .parse::<uuid::Uuid>()
            .map(ClientId::new)
            .map_err(|_| Status::invalid_argument("invalid client_id UUID"))?;
        let domain_req = DeviceAuthorizationRequest {
            client_id,
            scope: body.scope,
        };
        let resp = self
            .state
            .identity
            .device_authorize(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::DeviceAuthorizationResponse::from(&resp)))
    }

    async fn client_credentials(
        &self,
        req: Request<pb::ClientCredentialsRequest>,
    ) -> Result<Response<pb::ClientCredentialsResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let domain_req = proto_client_creds_to_domain(&body).map_err(Status::invalid_argument)?;
        let resp = self
            .state
            .identity
            .client_credentials_token(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::ClientCredentialsResponse::from(&resp)))
    }

    async fn register_client(
        &self,
        req: Request<pb::RegisterClientRequest>,
    ) -> Result<Response<pb::OAuthClient>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body: domain::RegisterClientRequest = req.into_inner().into();
        let client = self
            .state
            .identity
            .register_client(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthClient::from(&client)))
    }

    async fn decide(
        &self,
        req: Request<pb::TokenDecisionRequest>,
    ) -> Result<Response<pb::TokenDecisionResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        // Bearer token expected in `authorization` metadata.
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("bearer token required"))?
            .to_string();
        let body = req.into_inner();
        let domain_req = domain::oidc::DecidePermissionRequest {
            token,
            permission: body.permission,
            organization_id: body.organization_id,
            resource: body.resource,
        };
        let resp = self
            .state
            .identity
            .decide_token_permission(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::TokenDecisionResponse {
            allowed: resp.allowed,
        }))
    }
}

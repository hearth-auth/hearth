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

use super::auth::{authenticate_admin, grpc_require_permission};
use super::convert::{
    extract_grpc_user_auth, extract_realm_id, identity_to_status, verify_grpc_client_auth,
    verify_grpc_confidential_client_auth, CLIENT_ID_META_KEY,
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
        let (authenticated_user_id, bearer_session) =
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
            // No consent screen over gRPC (GA audit B2).
            .authorize_non_interactive(&realm_id, &domain_req, &bearer_session)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::AuthorizationResponse::from(&resp)))
    }

    async fn token_exchange(
        &self,
        req: Request<pb::TokenExchangeRequest>,
    ) -> Result<Response<pb::OidcTokenResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let md = req.metadata().clone();
        let body = req.into_inner();
        let domain_req = proto_token_exchange_to_domain(&body).map_err(Status::invalid_argument)?;

        // O2 (HEA-1755): confidential clients MUST authenticate on the
        // code-exchange path. Public (PKCE) and unknown clients pass through —
        // the exchange enforces PKCE and surfaces invalid_grant for bad codes —
        // except that a FAPI 2.0 Advanced realm accepts no public client.
        // A client with keys instead of a secret is not public; this RPC
        // carries no assertion, so it is refused (it exchanges over HTTP).
        //
        // A lookup ERROR fails closed (GA audit L12): matching only `Ok(Some)`
        // skipped client authentication on a storage error and ran the
        // exchange unauthenticated.
        if let Some(client) = self
            .state
            .identity
            .get_client(&realm_id, &domain_req.client_id)
            .map_err(identity_to_status)?
        {
            if client.is_public() {
                crate::identity::client_auth::authenticate_client(
                    &self.state.identity,
                    &realm_id,
                    &domain_req.client_id,
                    None,
                )
                .await
                .map_err(|e| super::convert::client_auth_status(&e))?;
            } else {
                let authenticated =
                    verify_grpc_client_auth(&md, &realm_id, &self.state.identity).await?;
                if authenticated != domain_req.client_id {
                    return Err(Status::unauthenticated(
                        "client authentication does not match request client_id",
                    ));
                }
            }
        }

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
        let client_id =
            verify_grpc_client_auth(req.metadata(), &realm_id, &self.state.identity).await?;
        // `verify_grpc_client_auth` accepts any secretless client on its
        // `client_id` alone. A `private_key_jwt` client is secretless but
        // confidential, and this RPC carries no assertion, so it cannot
        // authenticate here — refuse it rather than let anyone who knows its
        // public identifier revoke as it (RFC 7009 §2.1). It revokes over
        // HTTP with its assertion.
        let client = self
            .state
            .identity
            .get_client(&realm_id, &client_id)
            .map_err(identity_to_status)?;
        if client.is_some_and(|c| c.requires_client_assertion()) {
            return Err(Status::unauthenticated("invalid client credentials"));
        }
        // RFC 7009 §2.1: revoke only a token issued to the authenticated
        // client; any other token is a silent OK no-op, as on the HTTP routes.
        let mut body: domain::TokenRevocationRequest = req.into_inner().into();
        body.revoking_client_id = Some(client_id);
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
        // Task 26.43: confidential clients only (RFC 7662 §2.1). The
        // authenticated client is passed on so the RFC 7662 audience
        // restriction applies here exactly as on the HTTP routes — this path
        // used to pass `None`, which skipped it.
        let client_id =
            verify_grpc_confidential_client_auth(req.metadata(), &realm_id, &self.state.identity)
                .await?;
        let mut body: domain::TokenIntrospectionRequest = req.into_inner().into();
        body.introspecting_client_id = Some(client_id);
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
        let md = req.metadata().clone();
        let body = req.into_inner();
        let client_id = body
            .client_id
            .parse::<uuid::Uuid>()
            .map(ClientId::new)
            .map_err(|_| Status::invalid_argument("invalid client_id UUID"))?;

        // RFC 8628 §3.1: a confidential client authenticates at the device
        // authorization endpoint exactly as it does at the token endpoint.
        // The REST sibling `POST /device_authorization` has enforced this
        // since audit §4.19#4 / §4.22#6 was closed; this RPC never did, so a
        // party holding only the client *identifier* could still start the
        // whole RFC 8628 flow under a confidential client's identity by
        // switching protocol. `DeviceAuthorizationRequest.client_secret` was
        // already on the wire — and its own proto comment already promised
        // this check — but the handler decoded the field and dropped it
        // (task 23.9). Public clients pass through unchanged.
        //
        // `private_key_jwt` (RFC 7523 §2.2): a request carrying either
        // assertion field is authenticated by the assertion alone — never
        // read as absent and sent on to the secret or public-client paths.
        let presented = crate::identity::client_auth::presented_client_assertion(
            body.client_assertion_type.as_deref(),
            body.client_assertion.as_deref(),
        );
        if !matches!(presented, Ok(None)) {
            // RFC 6749 §2.3: one authentication method per request.
            if md.get(CLIENT_ID_META_KEY).is_some()
                || body
                    .client_secret
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
            {
                return Err(Status::invalid_argument(
                    "more than one client authentication method was used",
                ));
            }
            let Some(assertion) = presented.map_err(|e| super::convert::client_auth_status(&e))?
            else {
                return Err(Status::unauthenticated("invalid client credentials"));
            };
            self.state
                .identity
                .verify_client_assertion(&realm_id, &client_id, assertion)
                .map_err(|e| super::convert::client_auth_status(&e))?;
            let resp = self
                .state
                .identity
                .device_authorize(
                    &realm_id,
                    &DeviceAuthorizationRequest {
                        client_id,
                        scope: body.scope,
                    },
                )
                .map_err(identity_to_status)?;
            return Ok(Response::new(pb::DeviceAuthorizationResponse::from(&resp)));
        }

        // The lookup fails closed: a storage error becomes an error to the
        // caller rather than a skipped gate.
        let client = self
            .state
            .identity
            .get_client(&realm_id, &client_id)
            .map_err(identity_to_status)?;
        // A FAPI 2.0 Advanced realm refuses a public client too (the engine's
        // check answers for the realm); a client with keys instead of a secret
        // is not public and, with no assertion on this RPC, is refused.
        if client.as_ref().is_some_and(|c| c.is_public()) {
            crate::identity::client_auth::authenticate_client(
                &self.state.identity,
                &realm_id,
                &client_id,
                None,
            )
            .await
            .map_err(|e| super::convert::client_auth_status(&e))?;
        } else if client.is_some() {
            if md.get(CLIENT_ID_META_KEY).is_some() {
                // Metadata credentials are the gRPC analogue of HTTP Basic and
                // take precedence, as the proto comment states.
                let authenticated =
                    verify_grpc_client_auth(&md, &realm_id, &self.state.identity).await?;
                if authenticated != client_id {
                    return Err(Status::unauthenticated(
                        "client authentication does not match request client_id",
                    ));
                }
            } else {
                // `client_secret_post` fallback: the request body's own field.
                crate::identity::client_auth::authenticate_client(
                    &self.state.identity,
                    &realm_id,
                    &client_id,
                    body.client_secret.as_deref(),
                )
                .await
                .map_err(|e| super::convert::client_auth_status(&e))?;
            }
        }

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
        let resp = crate::identity::client_auth::client_credentials_token(
            &self.state.identity,
            &realm_id,
            domain_req,
        )
        .await
        .map_err(identity_to_status)?;
        Ok(Response::new(pb::ClientCredentialsResponse::from(&resp)))
    }

    async fn register_client(
        &self,
        req: Request<pb::RegisterClientRequest>,
    ) -> Result<Response<pb::OAuthClient>, Status> {
        // HEA-1750 (A1): client registration is a privileged operation. This RPC
        // previously only read the realm header, letting any caller mint OAuth
        // clients. Require an admin token carrying `hearth.clients.admin`, matching
        // the `ApplicationAdminService::create_application` gate.
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        grpc_require_permission(&auth, "hearth.clients.admin")?;
        let body: domain::RegisterClientRequest = req.into_inner().into();
        let client = self
            .state
            .identity
            .register_client(&auth.realm_id, &body)
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
        // RFC 9449 §7.2: a `cnf`-bound token cannot prove possession over gRPC
        // (no DPoP proof channel), so it gets no decision — fail-closed, as
        // `POST /oauth/authorize` answers a DPoP failure (GA audit B2).
        if self
            .state
            .identity
            .validate_token(&realm_id, &token)
            .is_ok_and(|claims| claims.cnf.is_some())
        {
            return Ok(Response::new(pb::TokenDecisionResponse { allowed: false }));
        }
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

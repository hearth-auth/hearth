//! SAML 2.0 web handlers.
//!
//! Covers both sides Hearth participates in:
//!
//! - **SP side** (Hearth consuming upstream IdP assertions): metadata +
//!   Assertion Consumer Service at `…/federation/saml/…`.
//! - **IdP side** (Hearth issuing assertions to registered SPs): metadata
//!   + SingleSignOnService + IdP-initiated launcher at `…/saml/…`.

use axum::extract::{Form, Path as AxumPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use std::sync::Arc;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{RealmId, Timestamp};
use crate::identity::federation::saml::authn_request::BuildAuthnRequestParams;
use crate::identity::federation::saml::response::ResponseBuilder;
use crate::identity::federation::saml::types::{
    SamlNameIdFormat, SamlStateBag, SAML_ASSERTION_SENTINEL_SKEW_SECS,
};
use crate::identity::federation::saml::{
    build_authn_request_xml, build_idp_metadata, build_logout_response_xml, build_post_form_html,
    build_redirect_url, build_response_xml, build_sp_metadata, parse_authn_request,
    parse_logout_request, parse_post_form_saml, sign_element, verify_signed_element,
    BuildLogoutResponseParams, IdpMetadataParams, SamlSpOutcome, SamlSpService, SpMetadataParams,
};
use crate::identity::federation::IdpKind;

use super::auth::UiSession;
use super::WebState;
use crate::abuse::redirect::validate_return_to;

// ============================================================================
// SP side — consume external IdP assertions.
// ============================================================================

/// `GET /ui/realms/{realm}/federation/saml/metadata?idp=<name>`
///
/// Returns the SP metadata XML for a specific configured SAML IdP. The
/// operator hands this to their IdP's admin console.
#[derive(Deserialize)]
pub struct SpMetadataQuery {
    pub idp: String,
}

pub async fn sp_metadata(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SpMetadataQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    // Check that an IdP with this name exists and is SAML-kind.
    let Ok(Some(idp)) = state.identity.get_idp_by_name(&realm, &q.idp) else {
        return (StatusCode::NOT_FOUND, "IdP not configured").into_response();
    };
    if idp.kind != IdpKind::Saml {
        return (StatusCode::BAD_REQUEST, "IdP is not SAML").into_response();
    }

    // Build SP metadata. For Phase 1 we advertise unsigned AuthnRequests by
    // default but include our signing cert so the operator's IdP admin can
    // enable signature validation on their side.
    let Some(realm_url) = realm_base_url_from_headers(&state, &headers, &realm_name) else {
        return saml_origin_unconfigured();
    };
    let acs_url = format!("{realm_url}/federation/saml/acs");
    let sp_entity_id = realm_url.clone();

    let signing_key = state
        .identity
        .get_or_create_saml_signing_key(&realm, &sp_entity_id)
        .ok();
    let cert_der = signing_key.as_ref().map(|k| k.cert_der().to_vec());

    let xml = build_sp_metadata(&SpMetadataParams {
        entity_id: &sp_entity_id,
        acs_url: &acs_url,
        slo_url: None,
        sign_authn_requests: false,
        want_assertions_signed: true,
        signing_cert_der: cert_der.as_deref(),
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        )
        .body(xml.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `POST /ui/realms/{realm}/federation/saml/acs`
///
/// Assertion Consumer Service. Receives a POSTed `SAMLResponse` and
/// `RelayState` from the external IdP.
#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(default, rename = "RelayState")]
    pub relay_state: Option<String>,
}

#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn sp_acs(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(form): Form<AcsForm>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let _span = tracing::info_span!(
        "hearth.saml.sp_acs",
        "hearth.realm_id" = %realm,
        "hearth.saml.role" = "sp",
    )
    .entered();

    // Decode the base64 payload.
    let xml = match parse_post_form_saml(&form.saml_response) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid SAMLResponse").into_response(),
    };

    // Resolve the state bag from RelayState (it carries the IdP we're
    // expecting + the request ID).
    let Some(relay) = form.relay_state.as_deref() else {
        return (StatusCode::BAD_REQUEST, "missing RelayState").into_response();
    };
    let Ok(bag) = state.identity.take_saml_state(&realm, relay) else {
        return (StatusCode::BAD_REQUEST, "invalid RelayState").into_response();
    };

    // Load the corresponding IdP config.
    let Ok(Some(idp_cfg)) = state.identity.get_idp(&realm, &bag.idp_id) else {
        return (StatusCode::BAD_REQUEST, "IdP not found").into_response();
    };
    if idp_cfg.kind != IdpKind::Saml {
        return (StatusCode::BAD_REQUEST, "IdP is not SAML").into_response();
    }

    // Adapt generic IdpConfig → SamlIdpConfig (SAML-specific fields are
    // shoehorned into the generic shape during reconcile).
    // `want_assertions_signed` is driven per-IdP from the connector config
    // (HEA-1759 / S4 Part A): when `true` the SP-service requires an
    // individually-signed `<Assertion>`; when `false` it falls back to
    // accepting a Response-level signature (common for SPs that sign the
    // outer Response only).
    let saml_idp = crate::identity::federation::saml::SamlIdpConfig {
        idp_id: idp_cfg.id.clone(),
        name: idp_cfg.name.clone(),
        entity_id: idp_cfg.issuer.clone(),
        sso_url: idp_cfg.authorization_endpoint.clone(),
        slo_url: idp_cfg.userinfo_endpoint.clone(),
        idp_certificates_pem: vec![idp_cfg.client_secret.expose_secret().to_string()],
        sign_authn_requests: false,
        want_assertions_signed: idp_cfg.want_assertions_signed,
        attribute_map: idp_cfg.claim_mappings.clone(),
    };

    let Some(realm_url) = realm_base_url_from_headers(&state, &headers, &realm_name) else {
        return saml_origin_unconfigured();
    };
    let sp_entity_id = realm_url.clone();
    let acs_url = format!("{realm_url}/federation/saml/acs");
    let now = Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0),
    );

    let outcome = SamlSpService::complete(
        &saml_idp,
        &sp_entity_id,
        &acs_url,
        Some(&bag.request_id),
        now,
        &xml,
    );

    match outcome {
        SamlSpOutcome::Accepted {
            identity,
            assertion,
            ..
        } => {
            // Replay guard. The sentinel carries the instant past which this
            // assertion can no longer validate, so the key space it lives in
            // can be reclaimed (22.11 / audit §4.10#9).
            let sentinel_expiry_secs = assertion
                .not_on_or_after
                .map_or_else(
                    || now.as_micros() / 1_000_000,
                    |noa| noa.as_micros() / 1_000_000,
                )
                .saturating_add(SAML_ASSERTION_SENTINEL_SKEW_SECS);
            if let Err(_e) = state.identity.mark_saml_assertion_consumed(
                &realm,
                &bag.idp_id,
                &assertion.id,
                sentinel_expiry_secs,
            ) {
                let _ = state.audit.append(&CreateAuditEvent {
                    realm_id: realm.clone(),
                    actor: "system".to_string(),
                    action: AuditAction::SamlLoginFailed,
                    resource_type: "saml".to_string(),
                    resource_id: assertion.id.clone(),
                    metadata: Some(serde_json::json!({ "reason": "replay" })),
                });
                return (StatusCode::BAD_REQUEST, "replay detected").into_response();
            }

            // 19.5 (audit §4.10#6, §4.22#4): this used to stop here — audit a
            // completed login and 302 to `return_to` with no cookie and no
            // user. The assertion proved who the caller is and nothing acted
            // on it. Run the identity through the same federation pipeline the
            // OIDC callback uses (link → auto-link → confirm → JIT), then
            // issue a real Hearth session.
            //
            // A-52: sanitize the stored return_to before using it as Location.
            let return_to = bag
                .return_to
                .as_deref()
                .and_then(|u| validate_return_to(u, &[]))
                .unwrap_or_else(|| "/ui/account".to_string());

            let Some(service) = super::federation::build_service(&state) else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "federation unavailable")
                    .into_response();
            };
            let link_mode = match state.identity.get_realm(&realm) {
                Ok(Some(r)) => r
                    .config()
                    .federation_link_mode
                    .unwrap_or(crate::identity::federation::LinkMode::Confirm),
                _ => crate::identity::federation::LinkMode::Confirm,
            };
            let external_sub = identity.external_sub.clone();
            let fed_outcome = match service.resolve_identity(&realm, identity, link_mode, now) {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(error = %e, "SAML identity resolution failed");
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: realm.clone(),
                        actor: "system".to_string(),
                        action: AuditAction::SamlLoginFailed,
                        resource_type: "saml".to_string(),
                        resource_id: assertion.id.clone(),
                        metadata: Some(serde_json::json!({ "reason": "link" })),
                    });
                    return (StatusCode::INTERNAL_SERVER_ERROR, "SAML login failed")
                        .into_response();
                }
            };

            let secure = state.is_secure_request(&headers);
            let response = super::federation::complete_federation_outcome(
                &state,
                &headers,
                &realm,
                &bag.idp_id,
                fed_outcome,
                &return_to,
                secure,
            );

            // Audit the login as completed only when a session cookie was
            // actually issued. A confirm-to-link hop or an MFA challenge is a
            // redirect without one — real progress, but not a completed
            // login, and the audit log must not say otherwise.
            if issued_session_cookie(&response) {
                let _ = state.audit.append(&CreateAuditEvent {
                    realm_id: realm.clone(),
                    actor: external_sub,
                    action: AuditAction::SamlLoginCompleted,
                    resource_type: "saml".to_string(),
                    resource_id: assertion.id.clone(),
                    metadata: Some(serde_json::json!({ "idp": idp_cfg.name })),
                });
            } else if response.status().is_redirection() {
                tracing::info!(
                    assertion_id = %assertion.id,
                    "SAML assertion accepted; login pending a further step"
                );
            } else {
                let _ = state.audit.append(&CreateAuditEvent {
                    realm_id: realm.clone(),
                    actor: "system".to_string(),
                    action: AuditAction::SamlLoginFailed,
                    resource_type: "saml".to_string(),
                    resource_id: assertion.id.clone(),
                    metadata: Some(serde_json::json!({ "reason": "session" })),
                });
            }
            response
        }
        SamlSpOutcome::Rejected { error } => {
            let reason = match &error {
                crate::identity::IdentityError::Saml(ref e) => e.category(),
                _ => "parse",
            };
            tracing::warn!(%reason, error = %error, "SAML response rejected");
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::SamlLoginFailed,
                resource_type: "saml".to_string(),
                resource_id: String::new(),
                metadata: Some(serde_json::json!({ "reason": reason })),
            });
            (StatusCode::BAD_REQUEST, "SAML response rejected").into_response()
        }
    }
}

/// `GET /ui/realms/{realm}/federation/saml/begin?idp=<name>` — initiates
/// an SP-initiated SSO by redirecting the browser to the IdP's SSO URL.
#[derive(Deserialize)]
pub struct SpBeginQuery {
    pub idp: String,
    #[serde(default)]
    pub return_to: Option<String>,
}

pub async fn sp_begin(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SpBeginQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(Some(idp_cfg)) = state.identity.get_idp_by_name(&realm, &q.idp) else {
        return (StatusCode::NOT_FOUND, "IdP not configured").into_response();
    };
    if idp_cfg.kind != IdpKind::Saml {
        return (StatusCode::BAD_REQUEST, "IdP is not SAML").into_response();
    }

    let Some(realm_url) = realm_base_url_from_headers(&state, &headers, &realm_name) else {
        return saml_origin_unconfigured();
    };
    let sp_entity_id = realm_url.clone();
    let acs_url = format!("{realm_url}/federation/saml/acs");

    let req_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    // 22.27 (audit 2026-08-28 §4.25#5): RelayState is the only thing binding the
    // ACS callback to this login attempt, so it gets a full 128 bits rather than
    // the 122 a UUID v4 carries. Same 32-hex shape as before.
    let state_token = crate::core::random_secret_hex();
    let now = now();

    let authn_xml = build_authn_request_xml(&BuildAuthnRequestParams {
        id: &req_id,
        destination: &idp_cfg.authorization_endpoint,
        issuer: &sp_entity_id,
        acs_url: &acs_url,
        issue_instant: now,
        nameid_format: Some(SamlNameIdFormat::EmailAddress.as_uri()),
        force_authn: false,
    });

    // A-52: validate return_to before persisting in state bag.
    let validated_return_to = q
        .return_to
        .as_deref()
        .and_then(|u| validate_return_to(u, &[]));
    let bag = SamlStateBag {
        token: state_token.clone(),
        request_id: req_id.clone(),
        realm_id: realm.clone(),
        idp_id: idp_cfg.id.clone(),
        return_to: validated_return_to,
        created_at: now,
    };
    if state.identity.put_saml_state(&bag).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "state persist failed").into_response();
    }

    let url = match build_redirect_url(
        &idp_cfg.authorization_endpoint,
        "SAMLRequest",
        authn_xml.as_bytes(),
        Some(&state_token),
    ) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "redirect build failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "anonymous".to_string(),
        action: AuditAction::SamlLoginInitiated,
        resource_type: "saml".to_string(),
        resource_id: req_id,
        metadata: Some(serde_json::json!({ "idp": idp_cfg.name })),
    });

    Redirect::to(&url).into_response()
}

// ============================================================================
// IdP side — issue assertions to registered SPs.
// ============================================================================

/// `GET /ui/realms/{realm}/saml/metadata` — IdP metadata.
pub async fn idp_metadata(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let Some(realm_url) = realm_base_url_from_headers(&state, &headers, &realm_name) else {
        return saml_origin_unconfigured();
    };
    let sso_url = format!("{realm_url}/saml/sso");
    let slo_service_url = format!("{realm_url}/saml/slo-idp");
    let entity_id = realm_url.clone();

    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no key").into_response(),
    };

    // Advertise what the SSO endpoint enforces (§4.10#4). SAML metadata
    // carries one `WantAuthnRequestsSigned` per IdP, but the requirement is
    // per SP. Advertise `true` as soon as any registered SP requires signing:
    // an SP that signs when it need not is served normally, while an SP that
    // does not sign when it must is refused — so erring towards `true` is the
    // safe direction.
    let want_signed = state
        .identity
        .list_saml_sps(&realm)
        .map(|sps| sps.iter().any(|sp| sp.want_authn_requests_signed))
        .unwrap_or(false);

    let xml = build_idp_metadata(&IdpMetadataParams {
        entity_id: &entity_id,
        sso_url: &sso_url,
        slo_url: Some(&slo_service_url),
        signing_cert_der: key.cert_der(),
        want_authn_requests_signed: want_signed,
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        )
        .body(xml.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET /ui/realms/{realm}/saml/sso` — SSO endpoint, HTTP-Redirect binding
/// inbound. Accepts `SAMLRequest` + `RelayState`.
#[derive(Deserialize)]
pub struct IdpSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(default, rename = "RelayState")]
    pub relay_state: Option<String>,
}

pub async fn idp_sso_get(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    session: UiSession,
    Query(q): Query<IdpSsoQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    if let Some(resp) = reject_session_realm_mismatch(&session, &realm) {
        return resp;
    }
    let Ok(xml) = crate::identity::federation::saml::decode_redirect_request(&q.saml_request)
    else {
        return (StatusCode::BAD_REQUEST, "bad SAMLRequest").into_response();
    };
    idp_complete_sso(state, headers, realm, &session, xml, q.relay_state).await
}

pub async fn idp_sso_post(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    session: UiSession,
    Form(q): Form<IdpSsoQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    if let Some(resp) = reject_session_realm_mismatch(&session, &realm) {
        return resp;
    }
    let Ok(xml) = parse_post_form_saml(&q.saml_request) else {
        return (StatusCode::BAD_REQUEST, "bad SAMLRequest").into_response();
    };
    idp_complete_sso(state, headers, realm, &session, xml, q.relay_state).await
}

async fn idp_complete_sso(
    state: Arc<WebState>,
    headers: axum::http::HeaderMap,
    realm: RealmId,
    session: &UiSession,
    xml: Vec<u8>,
    relay_state: Option<String>,
) -> Response {
    let _span = tracing::info_span!(
        "hearth.saml.idp_sso",
        "hearth.realm_id" = %realm,
        "hearth.saml.role" = "idp",
    )
    .entered();

    // Parse the AuthnRequest.
    let req = match parse_authn_request(&xml) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad AuthnRequest").into_response(),
    };

    // Resolve the SP by Issuer.
    let Ok(Some(sp)) = state.identity.get_saml_sp_by_entity_id(&realm, &req.issuer) else {
        return (StatusCode::NOT_FOUND, "unknown SP").into_response();
    };

    // `want_authn_requests_signed` used to parse, reach this record, and
    // change nothing — a documented security flag that was a silent no-op
    // (audit 2026-08-28 §4.10#4). This endpoint is a signing oracle, so an SP
    // that asked for the check gets the check. Fail closed when the SP has no
    // certificate registered: there is nothing to verify against.
    //
    // The HTTP-Redirect binding carries its signature as query parameters,
    // not inside the XML, so an SP that requires signing must use the
    // HTTP-POST binding — same constraint as the IdP-side SLO endpoint.
    if sp.want_authn_requests_signed {
        let Some(sp_cert) = sp.sp_certificate_pem.as_deref() else {
            return (
                StatusCode::FORBIDDEN,
                "SP requires signed AuthnRequests but has no certificate registered",
            )
                .into_response();
        };
        if verify_signed_element(&xml, "AuthnRequest", sp_cert).is_err() {
            return (
                StatusCode::FORBIDDEN,
                "AuthnRequest signature did not verify",
            )
                .into_response();
        }
    }

    // Audit receipt.
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlIdpAuthnRequestReceived,
        resource_type: "saml".to_string(),
        resource_id: req.id.clone(),
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    // S1 (HEA-1751): this endpoint is a SAML *signing oracle* — it mints a
    // signed assertion for a registered SP. It MUST be gated on a live,
    // authenticated Hearth session (enforced by the `UiSession` extractor on
    // the public handlers) and the asserted subject MUST be derived from that
    // authenticated user — never a fixed placeholder, and never a value the
    // requester controls. The NameID is the session user's email (the
    // EmailAddress NameID format that registered SPs default to).
    let subject_name_id = session.user_email.clone();

    let Some(realm_url) = realm_base_url_for_realm(&headers, &state, &realm) else {
        return saml_origin_unconfigured();
    };
    let idp_entity_id = realm_url.clone();

    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &idp_entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no key").into_response(),
    };

    let session_index = uuid::Uuid::new_v4().simple().to_string();
    let response_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let assertion_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let now = now();
    let response_xml = build_response_xml(&ResponseBuilder {
        response_id: &response_id,
        in_response_to: Some(&req.id),
        issue_instant: now,
        destination: &sp.acs_url,
        issuer: &idp_entity_id,
        audience: &sp.entity_id,
        assertion_id: &assertion_id,
        subject_name_id: &subject_name_id,
        subject_name_id_format: sp.nameid_format.as_uri(),
        session_index: &session_index,
        not_before: now,
        not_on_or_after: Timestamp::from_micros(now.as_micros() + 600 * 1_000_000),
        attributes: &Default::default(),
    });
    let signed_xml = match sign_element(response_xml.as_bytes(), &response_id, &key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlIdpResponseIssued,
        resource_type: "saml".to_string(),
        resource_id: response_id,
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    let html = build_post_form_html(
        &sp.acs_url,
        "SAMLResponse",
        &signed_xml,
        relay_state.as_deref(),
    );
    Html(html).into_response()
}

/// IdP-initiated SSO — admin launches a login at a registered SP.
#[derive(Deserialize)]
pub struct IdpInitQuery {
    pub sp: String,
}

pub async fn idp_sso_init(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    session: UiSession,
    Query(q): Query<IdpInitQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    // S1 (HEA-1751): IdP-initiated SSO also mints a signed assertion, so it
    // is gated on a live session (via the `UiSession` extractor) and the
    // subject is the authenticated user — never a fixed placeholder.
    if let Some(resp) = reject_session_realm_mismatch(&session, &realm) {
        return resp;
    }
    let Ok(Some(sp)) = state.identity.get_saml_sp_by_key(&realm, &q.sp) else {
        return (StatusCode::NOT_FOUND, "SP not registered").into_response();
    };
    let subject_name_id = session.user_email.clone();

    let Some(realm_url) = realm_base_url_from_headers(&state, &headers, &realm_name) else {
        return saml_origin_unconfigured();
    };
    let idp_entity_id = realm_url.clone();
    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &idp_entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no key").into_response(),
    };

    let session_index = uuid::Uuid::new_v4().simple().to_string();
    let response_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let assertion_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let now = now();

    let response_xml = build_response_xml(&ResponseBuilder {
        response_id: &response_id,
        in_response_to: None, // IdP-initiated: unsolicited Response
        issue_instant: now,
        destination: &sp.acs_url,
        issuer: &idp_entity_id,
        audience: &sp.entity_id,
        assertion_id: &assertion_id,
        subject_name_id: &subject_name_id,
        subject_name_id_format: sp.nameid_format.as_uri(),
        session_index: &session_index,
        not_before: now,
        not_on_or_after: Timestamp::from_micros(now.as_micros() + 600 * 1_000_000),
        attributes: &Default::default(),
    });

    let signed_xml = match sign_element(response_xml.as_bytes(), &response_id, &key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action: AuditAction::SamlIdpInitiatedSso,
        resource_type: "saml".to_string(),
        resource_id: response_id,
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    let html = build_post_form_html(&sp.acs_url, "SAMLResponse", &signed_xml, None);
    Html(html).into_response()
}

// ============================================================================
// IdP-side SLO — receive LogoutRequest from SP, return LogoutResponse.
// ============================================================================

/// `GET /ui/realms/{realm}/saml/slo-idp` — HTTP-Redirect binding.
pub async fn idp_slo_get(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<IdpSsoQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(xml) = crate::identity::federation::saml::decode_redirect_request(&q.saml_request)
    else {
        return (StatusCode::BAD_REQUEST, "bad SAMLRequest").into_response();
    };
    idp_complete_slo(state, headers, realm, xml, q.relay_state).await
}

/// `POST /ui/realms/{realm}/saml/slo-idp` — HTTP-POST binding.
pub async fn idp_slo_post(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(q): Form<IdpSsoQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(xml) = parse_post_form_saml(&q.saml_request) else {
        return (StatusCode::BAD_REQUEST, "bad SAMLRequest").into_response();
    };
    idp_complete_slo(state, headers, realm, xml, q.relay_state).await
}

async fn idp_complete_slo(
    state: Arc<WebState>,
    headers: axum::http::HeaderMap,
    realm: RealmId,
    xml: Vec<u8>,
    relay_state: Option<String>,
) -> Response {
    let req = match parse_logout_request(&xml) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad LogoutRequest").into_response(),
    };

    // Resolve SP by issuer entity ID.
    let Ok(Some(sp)) = state.identity.get_saml_sp_by_entity_id(&realm, &req.issuer) else {
        return (StatusCode::NOT_FOUND, "unknown SP").into_response();
    };

    // This endpoint mints a realm-key-signed LogoutResponse below, so it is a
    // signing oracle. Refuse to sign unless the inbound LogoutRequest is
    // authenticated by the SP's registered certificate — an unauthenticated
    // caller must never drive the realm key (audit 2026-08-28 §4.10#2). Fail
    // closed when the SP has no certificate registered (nothing to verify
    // against) or the embedded signature does not verify. The HTTP-Redirect
    // binding carries its signature as query parameters, not in the XML, so
    // an SP using SLO must present a signed HTTP-POST LogoutRequest.
    let Some(sp_cert) = sp.sp_certificate_pem.as_deref() else {
        return (
            StatusCode::FORBIDDEN,
            "SP has no certificate registered; a signed LogoutRequest is required",
        )
            .into_response();
    };
    if verify_signed_element(&xml, "LogoutRequest", sp_cert).is_err() {
        return (
            StatusCode::FORBIDDEN,
            "LogoutRequest signature did not verify",
        )
            .into_response();
    }

    let Some(slo_url) = sp.slo_url.clone() else {
        return (StatusCode::BAD_REQUEST, "SP has no SLO URL registered").into_response();
    };

    let Some(realm_url) = realm_base_url_for_realm(&headers, &state, &realm) else {
        return saml_origin_unconfigured();
    };
    let idp_entity_id = realm_url.clone();
    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &idp_entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no signing key").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlSloRequested,
        resource_type: "saml".to_string(),
        resource_id: req.id.clone(),
        metadata: Some(serde_json::json!({ "sp": sp.sp_key, "name_id": req.name_id })),
    });

    let response_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let response_xml = build_logout_response_xml(&BuildLogoutResponseParams {
        id: &response_id,
        in_response_to: &req.id,
        destination: &slo_url,
        issue_instant: now(),
        issuer: &idp_entity_id,
        success: true,
    });
    let signed = match sign_element(response_xml.as_bytes(), &response_id, &key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlSloCompleted,
        resource_type: "saml".to_string(),
        resource_id: response_id,
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    let html = build_post_form_html(&slo_url, "SAMLResponse", &signed, relay_state.as_deref());
    Html(html).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Rejects a request whose authenticated session belongs to a different
/// realm than the one named in the path.
///
/// S1 (HEA-1751): the `UiSession` extractor proves the caller is logged in,
/// but the session's realm is bound to the cookie, not the URL. Without this
/// check a user authenticated in realm A could drive realm B's IdP endpoints
/// to mint an assertion — a cross-realm privilege escalation. Returns
/// `Some(FORBIDDEN)` on mismatch, `None` when the realms agree.
fn reject_session_realm_mismatch(session: &UiSession, realm: &RealmId) -> Option<Response> {
    if &session.realm_id == realm {
        None
    } else {
        Some((StatusCode::FORBIDDEN, "session realm mismatch").into_response())
    }
}

fn resolve_realm(state: &WebState, realm_name: &str) -> Option<RealmId> {
    state
        .identity
        .get_realm_by_name(realm_name)
        .ok()
        .flatten()
        .map(|r| r.id().clone())
}

/// Whether `response` carries a `Set-Cookie` for the Hearth session cookie.
///
/// The SAML ACS audits `saml_login_completed` only when this is true. A
/// confirm-to-link hop or an MFA challenge is also a redirect, and neither is
/// a completed login — auditing one would repeat exactly the defect 19.5
/// closes (audit 2026-08-28 §4.22#4).
fn issued_session_cookie(response: &Response) -> bool {
    let prefix = format!("{}=", super::auth::SESSION_COOKIE);
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.starts_with(&prefix) && !c.contains("Max-Age=0"))
}

/// The response returned when no attacker-independent SAML origin exists.
///
/// SAML entity IDs, `Destination` and `AudienceRestriction` are all absolute
/// URLs that must be stable and operator-chosen. Serving a SAML endpoint
/// without one is a misconfiguration, not a request error.
fn saml_origin_unconfigured() -> Response {
    tracing::warn!(
        "SAML endpoint refused: neither `onboarding.base_url` nor `oidc.issuer` is \
         configured, and the request Host is not loopback. SAML audience and \
         destination validation must be anchored to a configured absolute URL."
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "SAML is not configured: set `onboarding.base_url` (or `oidc.issuer`) to this \
         server's public URL",
    )
        .into_response()
}

/// Resolves the public origin for this server (scheme + host).
///
/// SAML audience and destination validation must be anchored to a value an
/// attacker cannot set (audit 2026-08-28 §4.10#7). Resolution order:
///
/// 1. `onboarding.base_url` — the canonical public URL, also used for emailed
///    links.
/// 2. `oidc.issuer` — the other absolute public URL a production deployment
///    already configures.
/// 3. A loopback `Host` header (`localhost`, `127.0.0.1`, `[::1]`) for dev and
///    tests, where there is no multi-tenant origin to spoof.
///
/// Returns `None` in every other case — notably a deployment started from the
/// shipped `hearth.example.yaml`, where both keys are commented out. Forwarded
/// headers (`X-Forwarded-Host`, `X-Forwarded-Proto`) are **never** consulted on
/// this path: they are settable by anyone who can reach the port, and a SAML
/// origin derived from one is an origin the attacker chose.
fn trusted_base_url(state: &WebState, headers: &axum::http::HeaderMap) -> Option<String> {
    let cfg = state.config.as_ref();
    let onboarding = cfg.and_then(|c| c.onboarding.base_url.as_deref());
    let issuer = cfg.and_then(|c| c.oidc.issuer.as_deref());
    trusted_origin(configured_public_origin(onboarding, issuer), headers)
}

/// Picks the configured absolute public URL, preferring `onboarding.base_url`
/// over `oidc.issuer`. Empty strings are not configuration.
fn configured_public_origin<'a>(
    onboarding_base_url: Option<&'a str>,
    oidc_issuer: Option<&'a str>,
) -> Option<&'a str> {
    onboarding_base_url
        .filter(|u| !u.trim().is_empty())
        .or_else(|| oidc_issuer.filter(|u| !u.trim().is_empty()))
}

/// Pure core of [`trusted_base_url`]: use the configured public origin when
/// there is one, otherwise fall back to a **loopback** `Host` and nothing else.
fn trusted_origin(
    configured_base_url: Option<&str>,
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    if let Some(u) = configured_base_url {
        return Some(u.trim_end_matches('/').to_string());
    }
    loopback_base_url_from_host(headers)
}

/// Dev/test fallback: the request `Host`, accepted only when it names a
/// loopback address.
///
/// `X-Forwarded-Host` and `X-Forwarded-Proto` are deliberately not read. A
/// non-loopback `Host` yields `None` so the caller fails closed rather than
/// anchoring a security decision to a request header.
fn loopback_base_url_from_host(headers: &axum::http::HeaderMap) -> Option<String> {
    // No `Host` at all (in-process router tests, HTTP/1.0) is not an
    // attacker-chosen origin — it is no origin. Use the loopback default.
    let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) else {
        return Some("http://localhost:8420".to_string());
    };
    // RFC 7230: an IPv6 literal is bracketed; everything else splits on the
    // first colon (the optional port).
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    if matches!(hostname, "localhost" | "127.0.0.1" | "::1") {
        Some(format!("http://{host}"))
    } else {
        None
    }
}

fn realm_base_url_from_headers(
    state: &WebState,
    headers: &axum::http::HeaderMap,
    realm_name: &str,
) -> Option<String> {
    trusted_base_url(state, headers).map(|base| format!("{base}/ui/realms/{realm_name}"))
}

fn realm_base_url_for_realm(
    headers: &axum::http::HeaderMap,
    state: &WebState,
    realm: &RealmId,
) -> Option<String> {
    let base = trusted_base_url(state, headers)?;
    state
        .identity
        .get_realm(realm)
        .ok()
        .flatten()
        .map(|r| format!("{base}/ui/realms/{}", r.name()))
}

fn now() -> Timestamp {
    Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers_with_host(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("host", host.parse().expect("host header"));
        h
    }

    #[test]
    fn trusted_origin_ignores_spoofed_host_when_configured() {
        // S3 (HEA-1751): with a configured public origin, an attacker who
        // controls the `Host` header must NOT be able to shift the origin
        // used for SAML audience/destination validation.
        let headers = headers_with_host("evil.attacker.example");
        let origin = trusted_origin(Some("https://auth.company.example/"), &headers)
            .expect("a configured origin always resolves");
        assert_eq!(origin, "https://auth.company.example");
        assert!(
            !origin.contains("attacker"),
            "spoofed Host must not leak into the trusted origin"
        );
    }

    #[test]
    fn trusted_origin_trims_trailing_slash_on_config() {
        let headers = headers_with_host("ignored.example");
        assert_eq!(
            trusted_origin(Some("https://auth.company.example/"), &headers).as_deref(),
            Some("https://auth.company.example")
        );
    }

    /// 19.4/19.6 (audit §4.10#7): `X-Forwarded-Host` is settable by anyone who
    /// can reach the port. It must never reach the SAML origin — not even in
    /// the unconfigured dev fallback, where the loopback `Host` is used
    /// instead.
    #[test]
    fn trusted_origin_never_reads_x_forwarded_host() {
        let mut headers = headers_with_host("localhost:8420");
        headers.insert(
            "x-forwarded-host",
            "evil.attacker.example".parse().expect("xfh header"),
        );
        headers.insert("x-forwarded-proto", "https".parse().expect("xfp header"));
        let origin = trusted_origin(None, &headers);
        assert_eq!(
            origin.as_deref(),
            Some("http://localhost:8420"),
            "X-Forwarded-Host / -Proto must not steer the SAML origin"
        );
    }

    /// 19.6: with no configured absolute URL and a non-loopback `Host`, there
    /// is no attacker-independent origin to validate against. Refuse rather
    /// than trust the header — this is the shipped-example-config case the
    /// audit reported.
    #[test]
    fn trusted_origin_refuses_unconfigured_non_loopback_host() {
        let headers = headers_with_host("auth.company.example");
        assert_eq!(
            trusted_origin(None, &headers),
            None,
            "an unconfigured deployment must refuse to anchor SAML to the Host header"
        );
    }

    /// A request with no `Host` at all carries no origin to spoof; the
    /// loopback default keeps in-process router tests and HTTP/1.0 clients
    /// working without trusting anything.
    #[test]
    fn trusted_origin_defaults_to_loopback_when_host_absent() {
        assert_eq!(
            trusted_origin(None, &HeaderMap::new()).as_deref(),
            Some("http://localhost:8420")
        );
    }

    #[test]
    fn trusted_origin_falls_back_to_loopback_host_when_unconfigured() {
        // Dev / test mode: no configured origin, loopback Host is accepted.
        for host in ["localhost:8420", "127.0.0.1:8420", "[::1]:8420"] {
            let headers = headers_with_host(host);
            assert_eq!(
                trusted_origin(None, &headers).as_deref(),
                Some(format!("http://{host}").as_str()),
                "loopback host {host} must be usable in the dev fallback"
            );
        }
    }

    /// 19.6: `oidc.issuer` is the other absolute public URL an operator
    /// configures; it is accepted when `onboarding.base_url` is absent so a
    /// production deployment is not forced to set two keys.
    #[test]
    fn configured_public_origin_prefers_onboarding_then_issuer() {
        assert_eq!(
            configured_public_origin(Some("https://a.example"), Some("https://b.example")),
            Some("https://a.example")
        );
        assert_eq!(
            configured_public_origin(None, Some("https://b.example")),
            Some("https://b.example")
        );
        assert_eq!(configured_public_origin(None, None), None);
        // An empty string is not a configured origin.
        assert_eq!(configured_public_origin(Some(""), None), None);
    }
}

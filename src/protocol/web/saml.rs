//! SAML 2.0 web handlers — the service-provider side only.
//!
//! Hearth consumes assertions from an upstream IdP: SP metadata, the
//! Assertion Consumer Service and the login `begin` hop, all under
//! `…/federation/saml/…`. Hearth does not act as a SAML IdP (removed in 3.0.0,
//! scope-trim-trusted-core).

use axum::extract::{Form, Path as AxumPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use std::sync::Arc;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{RealmId, Timestamp};
use crate::identity::federation::saml::authn_request::BuildAuthnRequestParams;
use crate::identity::federation::saml::types::{
    SamlNameIdFormat, SamlStateBag, SAML_ASSERTION_SENTINEL_SKEW_SECS,
};
use crate::identity::federation::saml::{
    build_authn_request_xml, build_redirect_url, build_sp_metadata, parse_post_form_saml,
    SamlSpOutcome, SamlSpService, SpMetadataParams,
};
use crate::identity::federation::IdpKind;

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
    crate::protocol::client_info::PeerAddr(peer_addr): crate::protocol::client_info::PeerAddr,
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
        // `idp_certificate_pem` may be a bundle (outgoing + incoming
        // certificate during an IdP key rollover); each block is trusted.
        idp_certificates_pem: crate::identity::federation::saml::split_pem_certificates(
            idp_cfg.client_secret.expose_secret(),
        ),
        sign_authn_requests: false,
        want_assertions_signed: idp_cfg.want_assertions_signed,
        trust_asserted_email: idp_cfg.trust_asserted_email,
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
                crate::protocol::audit_log::record(
                    state.audit.as_ref(),
                    &CreateAuditEvent {
                        realm_id: realm.clone(),
                        actor: "system".to_string(),
                        action: AuditAction::SamlLoginFailed,
                        resource_type: "saml".to_string(),
                        resource_id: assertion.id.clone(),
                        metadata: Some(serde_json::json!({ "reason": "replay" })),
                    },
                );
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
                .and_then(|u| validate_return_to(u, state.allowed_return_to_origins()))
                .unwrap_or_else(|| "/ui/account".to_string());

            let Some(service) = super::federation::build_service(&state, &realm_name) else {
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
                    crate::protocol::audit_log::record(
                        state.audit.as_ref(),
                        &CreateAuditEvent {
                            realm_id: realm.clone(),
                            actor: "system".to_string(),
                            action: AuditAction::SamlLoginFailed,
                            resource_type: "saml".to_string(),
                            resource_id: assertion.id.clone(),
                            metadata: Some(serde_json::json!({ "reason": "link" })),
                        },
                    );
                    return (StatusCode::INTERNAL_SERVER_ERROR, "SAML login failed")
                        .into_response();
                }
            };

            let secure = state.is_secure_request(&headers);
            let response = super::federation::complete_federation_outcome(
                &state,
                &headers,
                peer_addr,
                &realm,
                &realm_name,
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
                crate::protocol::audit_log::record(
                    state.audit.as_ref(),
                    &CreateAuditEvent {
                        realm_id: realm.clone(),
                        actor: external_sub,
                        action: AuditAction::SamlLoginCompleted,
                        resource_type: "saml".to_string(),
                        resource_id: assertion.id.clone(),
                        metadata: Some(serde_json::json!({ "idp": idp_cfg.name })),
                    },
                );
            } else if response.status().is_redirection() {
                tracing::info!(
                    assertion_id = %assertion.id,
                    "SAML assertion accepted; login pending a further step"
                );
            } else {
                crate::protocol::audit_log::record(
                    state.audit.as_ref(),
                    &CreateAuditEvent {
                        realm_id: realm.clone(),
                        actor: "system".to_string(),
                        action: AuditAction::SamlLoginFailed,
                        resource_type: "saml".to_string(),
                        resource_id: assertion.id.clone(),
                        metadata: Some(serde_json::json!({ "reason": "session" })),
                    },
                );
            }
            response
        }
        SamlSpOutcome::Rejected { error } => {
            let reason = match &error {
                crate::identity::IdentityError::Saml(ref e) => e.category(),
                _ => "parse",
            };
            tracing::warn!(%reason, error = %error, "SAML response rejected");
            crate::protocol::audit_log::record(
                state.audit.as_ref(),
                &CreateAuditEvent {
                    realm_id: realm.clone(),
                    actor: "system".to_string(),
                    action: AuditAction::SamlLoginFailed,
                    resource_type: "saml".to_string(),
                    resource_id: String::new(),
                    metadata: Some(serde_json::json!({ "reason": reason })),
                },
            );
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
        .and_then(|u| validate_return_to(u, state.allowed_return_to_origins()));
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

    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm.clone(),
            actor: "anonymous".to_string(),
            action: AuditAction::SamlLoginInitiated,
            resource_type: "saml".to_string(),
            resource_id: req_id,
            metadata: Some(serde_json::json!({ "idp": idp_cfg.name })),
        },
    );

    Redirect::to(&url).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

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

    /// 21.12 (audit §4.23#11): the unauthenticated SP metadata document must
    /// not publish an attacker-chosen origin. `entityID` and the ACS URL are
    /// built from `realm_base_url_from_headers` → [`trusted_base_url`] →
    /// [`trusted_origin`], so with `onboarding.base_url` and `oidc.issuer` both
    /// unset and a non-loopback `Host`, a spoofed `X-Forwarded-Host` must
    /// produce no origin at all — `sp_metadata` then answers
    /// `saml_origin_unconfigured()` rather than publishing an attacker-chosen
    /// entityID to every anonymous caller.
    #[test]
    fn metadata_origin_refuses_a_spoofed_forwarded_host() {
        let mut headers = headers_with_host("auth.company.example");
        headers.insert(
            "x-forwarded-host",
            "evil.attacker.example".parse().expect("xfh header"),
        );
        headers.insert("x-forwarded-proto", "https".parse().expect("xfp header"));
        assert_eq!(
            trusted_origin(None, &headers),
            None,
            "SAML metadata must not derive entityID or the SSO/SLO URLs from X-Forwarded-Host"
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

    // ======================================================================
    // 19.5 (audit 2026-08-28 §4.10#6, §4.22#4) — the ACS must not audit a
    // login it did not complete.
    //
    // `issued_session_cookie` is the whole gate: `sp_acs` writes
    // `saml_login_completed` if and only if it returns true. The original
    // defect was an unconditional "completed" event on a cookie-less
    // redirect, so every branch that redirects WITHOUT a session cookie must
    // read false here.
    // ======================================================================

    /// Builds a `Response` carrying the given `Set-Cookie` headers.
    fn response_with_cookies(cookies: &[&str]) -> Response {
        let mut resp = StatusCode::SEE_OTHER.into_response();
        for c in cookies {
            resp.headers_mut().append(
                header::SET_COOKIE,
                axum::http::HeaderValue::from_str(c).expect("cookie header"),
            );
        }
        resp
    }

    /// Control: a real login cookie reads true, so the refusals below cannot
    /// pass vacuously.
    #[test]
    fn issued_session_cookie_sees_a_real_login_cookie() {
        let resp =
            response_with_cookies(&["hearth_ui_session=abc.def; HttpOnly; Path=/ui; SameSite=Lax"]);
        assert!(
            issued_session_cookie(&resp),
            "a Set-Cookie for the session cookie must count as a completed login"
        );
    }

    /// The confirm-to-link hop redirects with its own ticket cookie and no
    /// session. It is real progress, but nobody is logged in — auditing it as
    /// `saml_login_completed` is the exact defect 19.5 closes.
    #[test]
    fn issued_session_cookie_refuses_the_confirm_link_hop() {
        let resp = response_with_cookies(&[
            "hearth_ui_fed_confirm=tkt.mac; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=600",
        ]);
        assert!(
            !issued_session_cookie(&resp),
            "a confirm-to-link ticket cookie is not a session"
        );
    }

    /// A logout-shaped cookie clears the session rather than establishing one.
    /// Matching on the name alone would read it as a completed login.
    #[test]
    fn issued_session_cookie_refuses_a_cleared_session_cookie() {
        let resp = response_with_cookies(&[
            "hearth_ui_session=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0",
        ]);
        assert!(
            !issued_session_cookie(&resp),
            "an expiring session cookie must not count as a completed login"
        );
    }

    /// A redirect with no `Set-Cookie` at all — the original 19.5 defect,
    /// where the ACS 302'd to `return_to` and audited a completed login.
    #[test]
    fn issued_session_cookie_refuses_a_bare_redirect() {
        assert!(
            !issued_session_cookie(&response_with_cookies(&[])),
            "a redirect carrying no cookie authenticates nobody"
        );
    }

    /// A cookie whose *name* merely starts with the session cookie's name
    /// must not satisfy the gate — the prefix ends at the `=`.
    #[test]
    fn issued_session_cookie_refuses_a_name_prefixed_cookie() {
        let resp =
            response_with_cookies(&["hearth_ui_session_hint=1; HttpOnly; Path=/ui; SameSite=Lax"]);
        assert!(
            !issued_session_cookie(&resp),
            "only the session cookie itself proves a session was issued"
        );
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

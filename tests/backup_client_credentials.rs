#![allow(clippy::unwrap_used)]
//! A backup restore must never turn an authenticated OAuth client into a
//! public one.
//!
//! The export writes the whole `OAuthClient` record — the stored secret hash,
//! the inline JWKS, the assertion key, the security profile. The restore read
//! none of those fields and re-created every client as a secretless Standard
//! client, so after a restore `is_public()` was true for all of them: anyone
//! who knew a `client_id` could push to `/as/par`, start a device flow, and
//! take a `client_credentials` token for a client that used to require a
//! secret or a signed assertion.
//!
//! Each test registers clients on a source instance, exports the realm,
//! restores it into a fresh server, and then checks through HTTP that every
//! restored client still authenticates with its credential AND is still
//! refused without it.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hearth::backup::{
    BackupArchive, BackupExporter, BackupImporter, BackupManifest, ExportOptions, ImportOptions,
};
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientProfile, ClientTrustLevel, CreateRealmRequest, GeneratedClientSecret,
    RegisterClientRequest, UpdateClientRequest,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use secrecy::SecretString;
use tempfile::NamedTempFile;

const REDIRECT_URI: &str = "https://app.example.com/cb";
/// S256 of the RFC 7636 Appendix B verifier.
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const CALLER_SECRET: &str = "restore-argon2id-client-secret-0123456789";

// ── keys ─────────────────────────────────────────────────────────────────────

struct ClientKey(Ed25519KeyPair);

impl ClientKey {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn jwks(&self) -> String {
        serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref()),
        }]})
        .to_string()
    }

    fn raw_public_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref())
    }

    fn assertion(&self, client: &ClientId, aud: &str) -> String {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::json!({"alg": "EdDSA", "kid": "k1", "typ": "JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "iss": client.to_string(), "sub": client.to_string(), "aud": aud,
                    "exp": now + 60, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
                })
                .to_string()
            ),
        );
        let sig = self.0.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

// ── backup plumbing ──────────────────────────────────────────────────────────

fn passphrase() -> SecretString {
    SecretString::new("backup-client-credentials-passphrase".into())
}

/// Exports `realm` from `src` and restores it into `dst`, returning the
/// restored realm's id and name.
fn export_and_restore(
    src: &common::TestHarness,
    realm: &RealmId,
    dst: &common::TestHarness,
) -> (RealmId, String, hearth::backup::ImportReport) {
    let tmp = NamedTempFile::new().expect("tempfile");
    let mut writer = BackupArchive::create(tmp.path()).expect("create archive");
    let exporter = BackupExporter::new(src.identity_arc(), src.audit_arc(), src.rbac_arc());
    let dek = BackupExporter::generate_dek().expect("dek");
    let realm_manifest = exporter
        .export_realm(realm, &mut writer, &ExportOptions::default(), &dek)
        .expect("export realm");
    let (wrapped, params) = BackupExporter::wrap_dek(&dek, &passphrase()).expect("wrap dek");
    let mut manifest = BackupManifest::new(vec![realm_manifest]);
    manifest.sections_encrypted = true;
    manifest.wrapped_dek_b64 = Some(wrapped);
    manifest.dek_wrapping_params = Some(params);
    writer.finish(manifest).expect("finish archive");

    let reader = BackupArchive::open(tmp.path()).expect("open archive");
    let slug = reader.realms()[0].slug.clone();
    let report = BackupImporter::new(dst.identity_arc(), dst.rbac_arc(), dst.audit_arc())
        .import_realm(
            &slug,
            &reader,
            &ImportOptions {
                dek_passphrase: Some(passphrase()),
                ..ImportOptions::default()
            },
        )
        .expect("import realm");
    let restored: RealmId = reader.realms()[0].realm_id.parse().expect("realm id");
    let name = dst
        .identity()
        .get_realm(&restored)
        .expect("get realm")
        .expect("restored realm exists")
        .name()
        .to_string();
    (restored, name, report)
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

struct Dst {
    h: common::TestHarness,
    base: String,
    realm_id: RealmId,
    realm_name: String,
    issuer: String,
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Header,
    Realm,
}

const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

impl Dst {
    async fn post(
        &self,
        route: Route,
        endpoint: &str,
        form: &[(&str, String)],
        basic: Option<(&ClientId, &str)>,
    ) -> (u16, serde_json::Value) {
        let url = match route {
            Route::Header => format!("{}/{endpoint}", self.base),
            Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
        };
        let mut req = reqwest::Client::new().post(&url).form(form);
        if matches!(route, Route::Header) {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        if let Some((id, secret)) = basic {
            req = req.header(
                "Authorization",
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{secret}", id.as_uuid()))
                ),
            );
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }
}

fn id(client: &ClientId) -> String {
    client.as_uuid().to_string()
}

fn par_form(client: &ClientId) -> Vec<(&'static str, String)> {
    vec![
        ("client_id", id(client)),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("scope", "openid".to_string()),
        ("state", "restore-state".to_string()),
        ("response_type", "code".to_string()),
        ("code_challenge", PKCE_CHALLENGE.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ]
}

fn client_credentials_form(client: &ClientId) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", id(client)),
    ]
}

fn device_form(client: &ClientId) -> Vec<(&'static str, String)> {
    vec![("client_id", id(client)), ("scope", "openid".to_string())]
}

fn with_assertion(
    mut form: Vec<(&'static str, String)>,
    key: &ClientKey,
    client: &ClientId,
    aud: &str,
) -> Vec<(&'static str, String)> {
    form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()));
    form.push(("client_assertion", key.assertion(client, aud)));
    form
}

fn assert_refused(status: u16, body: &serde_json::Value, what: &str) {
    assert_eq!(
        status, 401,
        "{what}: a restored client presenting only its client_id must be refused, got {status} {body}"
    );
}

async fn source_realm(src: &common::TestHarness) -> RealmId {
    src.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("restore-creds-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

async fn restore(src: &common::TestHarness, realm: &RealmId) -> Dst {
    let h = common::TestHarness::server().await.expect("dst server");
    let (realm_id, realm_name, report) = export_and_restore(src, realm, &h);
    assert_eq!(report.clients.errored, 0, "no client may fail to restore");
    let base = h.base_url().expect("base_url").to_string();
    let issuer = format!(
        "{}/realms/{realm_name}",
        h.identity().oidc_discovery().issuer
    );
    Dst {
        h,
        base,
        realm_id,
        realm_name,
        issuer,
    }
}

fn all_grants() -> Vec<String> {
    vec![
        "authorization_code".to_string(),
        "client_credentials".to_string(),
        DEVICE_GRANT.to_string(),
    ]
}

// ── tests ────────────────────────────────────────────────────────────────────

/// A client with a caller-chosen secret (Argon2id) and one with a
/// Hearth-generated secret (the fast `$hearth-sha256$` format) both come back
/// holding the SAME stored hash, still authenticate with their secret, and
/// are still refused without it at `/token`, `/as/par` and
/// `/device_authorization`.
#[tokio::test]
async fn restored_secret_clients_still_require_their_secret() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let realm = source_realm(&src).await;

    let argon = src
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Argon2id secret client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some(CALLER_SECRET.to_string()),
                grant_types: all_grants(),
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register argon2id client");
    assert!(argon
        .client_secret_hash()
        .unwrap()
        .starts_with("$argon2id$"));

    let generated = GeneratedClientSecret::generate();
    let fast = src
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Generated secret client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                generated_client_secret: Some(generated.clone()),
                grant_types: all_grants(),
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register fast-hash client");
    assert!(fast
        .client_secret_hash()
        .unwrap()
        .starts_with("$hearth-sha256$v=1$"));

    let dst = restore(&src, &realm).await;

    for (source, secret) in [(&argon, CALLER_SECRET), (&fast, generated.expose())] {
        let cid = source.client_id();
        let restored = dst
            .h
            .identity()
            .get_client(&dst.realm_id, cid)
            .expect("get client")
            .expect("the client must be restored");
        assert_eq!(
            restored.client_secret_hash(),
            source.client_secret_hash(),
            "the stored secret hash must be restored verbatim, never re-hashed or dropped"
        );
        assert!(
            !restored.is_public(),
            "a secret client must not restore public"
        );

        for route in ROUTES {
            let what = format!("{route:?} {}", source.client_name());

            let (s, b) = dst
                .post(route, "token", &client_credentials_form(cid), None)
                .await;
            assert_refused(s, &b, &format!("{what} /token client_credentials"));
            let (s, b) = dst
                .post(
                    route,
                    "token",
                    &[("grant_type", "client_credentials".to_string())],
                    Some((cid, secret)),
                )
                .await;
            assert_eq!(s, 200, "{what} /token with its secret: {b}");

            let (s, b) = dst.post(route, "as/par", &par_form(cid), None).await;
            assert_refused(s, &b, &format!("{what} /as/par"));
            let (s, b) = dst
                .post(route, "as/par", &par_form(cid), Some((cid, secret)))
                .await;
            assert_eq!(s, 201, "{what} /as/par with its secret: {b}");

            let (s, b) = dst
                .post(route, "device_authorization", &device_form(cid), None)
                .await;
            assert_refused(s, &b, &format!("{what} /device_authorization"));
            let (s, b) = dst
                .post(
                    route,
                    "device_authorization",
                    &device_form(cid),
                    Some((cid, secret)),
                )
                .await;
            assert_eq!(s, 200, "{what} /device_authorization with its secret: {b}");
        }
    }
}

/// A `private_key_jwt` client (inline JWKS, no secret) and its assertion key
/// come back intact: it authenticates with a signed assertion and is refused
/// on its `client_id` alone.
#[tokio::test]
async fn restored_private_key_jwt_client_still_requires_its_assertion() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let realm = source_realm(&src).await;
    let key = ClientKey::new();
    let assertion_key = ClientKey::new();

    let registered = src
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "JWKS client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                grant_types: all_grants(),
                trust_level: ClientTrustLevel::FirstParty,
                jwks: Some(key.jwks()),
                ..Default::default()
            },
        )
        .expect("register jwks client");
    let cid = registered.client_id().clone();
    let source = src
        .identity()
        .update_client(
            &realm,
            &cid,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(assertion_key.raw_public_b64())),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    let dst = restore(&src, &realm).await;
    let restored = dst
        .h
        .identity()
        .get_client(&dst.realm_id, &cid)
        .expect("get client")
        .expect("restored");
    assert_eq!(restored.jwks(), source.jwks(), "the JWKS must be restored");
    assert_eq!(
        restored.assertion_public_key(),
        source.assertion_public_key(),
        "the assertion key must be restored"
    );
    assert!(
        !restored.is_public(),
        "a keyed client must not restore public"
    );

    for route in ROUTES {
        let what = format!("{route:?} private_key_jwt");

        let (s, b) = dst
            .post(route, "token", &client_credentials_form(&cid), None)
            .await;
        assert_refused(s, &b, &format!("{what} /token client_credentials"));
        let form = with_assertion(client_credentials_form(&cid), &key, &cid, &dst.issuer);
        let (s, b) = dst.post(route, "token", &form, None).await;
        assert_eq!(s, 200, "{what} /token with an assertion: {b}");

        let (s, b) = dst.post(route, "as/par", &par_form(&cid), None).await;
        assert_refused(s, &b, &format!("{what} /as/par"));
        let form = with_assertion(par_form(&cid), &key, &cid, &dst.issuer);
        let (s, b) = dst.post(route, "as/par", &form, None).await;
        assert_eq!(s, 201, "{what} /as/par with an assertion: {b}");

        let (s, b) = dst
            .post(route, "device_authorization", &device_form(&cid), None)
            .await;
        assert_refused(s, &b, &format!("{what} /device_authorization"));
        let form = with_assertion(device_form(&cid), &key, &cid, &dst.issuer);
        let (s, b) = dst.post(route, "device_authorization", &form, None).await;
        assert_eq!(
            s, 200,
            "{what} /device_authorization with an assertion: {b}"
        );
    }
}

/// A FAPI 2.0 client is never public (bf9fbfbd). It comes back as FAPI 2.0
/// with its JWKS, and PAR still demands its assertion.
#[tokio::test]
async fn restored_fapi2_client_stays_fapi2_and_is_never_public() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let realm = source_realm(&src).await;
    let key = ClientKey::new();
    let cid = src
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "FAPI 2.0 client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                jwks: Some(key.jwks()),
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect("register fapi2 client")
        .client_id()
        .clone();

    let dst = restore(&src, &realm).await;
    let restored = dst
        .h
        .identity()
        .get_client(&dst.realm_id, &cid)
        .expect("get client")
        .expect("restored");
    assert!(
        restored.profile().is_fapi2(),
        "the FAPI 2.0 profile must be restored"
    );
    assert!(!restored.is_public(), "a FAPI 2.0 client is never public");

    for route in ROUTES {
        let (s, b) = dst.post(route, "as/par", &par_form(&cid), None).await;
        assert_refused(s, &b, &format!("{route:?} FAPI 2.0 /as/par"));
        let form = with_assertion(par_form(&cid), &key, &cid, &dst.issuer);
        let (s, b) = dst.post(route, "as/par", &form, None).await;
        assert_eq!(s, 201, "{route:?} FAPI 2.0 /as/par with an assertion: {b}");
    }
}

/// A genuinely public client (no credential in the source) still restores
/// public — the fix must not break SPAs and native apps.
#[tokio::test]
async fn restored_public_client_stays_public() {
    let src = common::TestHarness::embedded().await.expect("src harness");
    let realm = source_realm(&src).await;
    let cid = src
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "SPA".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register public client")
        .client_id()
        .clone();

    let dst = restore(&src, &realm).await;
    let (s, b) = dst
        .post(Route::Header, "as/par", &par_form(&cid), None)
        .await;
    assert_eq!(s, 201, "a public client pushes on its client_id alone: {b}");
}

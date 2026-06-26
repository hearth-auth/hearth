import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import CodeBlock from '@theme/CodeBlock';
import clsx from 'clsx';

import styles from './index.module.css';

// ── TypeScript (browser SDK) ──────────────────────────────────────────────────

const TS_SNIPPET = `\
import { HearthApiClient, createHearthAuth } from '@hearth-auth/sdk';

const client = new HearthApiClient({
  baseUrl: 'http://localhost:8420/realms/dev-realm',
  realmId: '<realm-id>',
});

// One helper runs the full OAuth 2.0 + PKCE handshake for you.
const auth = createHearthAuth(client, {
  clientId:    '<client-id>',
  redirectUri: 'http://localhost:3000/callback',
  hearthUrl:   'http://localhost:8420',
  realmSlug:   'dev-realm',
});

await auth.startLogin();                  // "Log in" button → redirect to Hearth
// …on your /callback route:
const p = new URLSearchParams(window.location.search);
await auth.handleCallback(p.get('code'), p.get('state')); // tokens stored + auto-refreshed
`;

const TS_REACT_SNIPPET = `\
import { HearthProvider, useHasPermission } from '@hearth-auth/sdk';

// Wrap your app once at the root — shares the auth context with all children
function App() {
  return (
    <HearthProvider client={client}>
      <AdminPage />
    </HearthProvider>
  );
}

// In any component — reads permissions from the JWT in context, no network call
function AdminPage() {
  const canAdmin = useHasPermission('hearth.admin');
  if (!canAdmin) return <p>Access denied.</p>;
  return <div>Welcome, admin.</div>;
}
`;

// ── Node.js ───────────────────────────────────────────────────────────────────

const NODE_SNIPPET = `\
import { HearthClient } from '@hearth-auth/node';

const client = new HearthClient({
  issuer_url: 'http://localhost:8420',
  client_id:  '<client-id>',
});

// Login route — generate PKCE and build the redirect URL
app.get('/login', async (req, res) => {
  const { authorizationUrl, state, codeVerifier } = await client.beginLogin(
    'http://localhost:3000/callback', 'openid');
  req.session.oauthState   = state;
  req.session.codeVerifier = codeVerifier;
  res.redirect(authorizationUrl);
});

// Callback route — exchange the code for tokens
app.get('/callback', async (req, res) => {
  const tokens = await client.completeLogin(
    req.query.code, req.session.codeVerifier, 'http://localhost:3000/callback');
  // store tokens.accessToken in your session, then redirect
  res.redirect('/');
});
`;

const NODE_EXPRESS_SNIPPET = `\
import express from 'express';
import { hearthMiddleware } from '@hearth-auth/node';

const app = express();

// Mount once to attach a verified token to every request
app.use(hearthMiddleware({
  issuer_url:   'http://localhost:8420',
  expectedMode: 'embedded',
}));

// Require a permission on a single route — 401 on missing token, 403 on denied
app.get('/admin', hearthMiddleware({
  issuer_url:         'http://localhost:8420',
  expectedMode:       'embedded',
  requiredPermission: 'hearth.admin',
}), (req, res) => {
  res.json({ sub: req.hearthToken?.subject() });
});
`;

const NODE_NEXTJS_SNIPPET = `\
// middleware.ts — runs in the Edge Runtime (V8 isolate, no Node.js APIs)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { hearthEdgeMiddleware } from '@hearth-auth/node/nextjs/edge';

const guard = hearthEdgeMiddleware({
  issuerUrl: process.env.HEARTH_ISSUER_URL!,
  jwksUri:   \`\${process.env.HEARTH_ISSUER_URL}/.well-known/jwks.json\`,
});

export async function middleware(request: NextRequest) {
  const result = await guard(request);
  if (result) return result;   // 401 or 403 — return to client
  return NextResponse.next();
}

export const config = { matcher: ['/api/:path*'] };
`;

// ── Go ────────────────────────────────────────────────────────────────────────

const GO_SNIPPET = `\
import "github.com/hearth-auth/hearth/sdks/go/hearth"

client := hearth.NewClient("http://localhost:8420", "<realm-id>")
pkce, _ := hearth.GeneratePKCE()

// 1. Redirect the user to log in (store pkce.Verifier + state in the session):
authURL := "http://localhost:8420/realms/dev-realm/authorize?response_type=code" +
    "&client_id=<client-id>&redirect_uri=http://localhost:3000/callback&scope=openid" +
    "&state=" + state + "&code_challenge=" + pkce.Challenge + "&code_challenge_method=S256"
http.Redirect(w, r, authURL, http.StatusFound)

// 2. On your /callback, exchange the code for tokens:
tokens, _ := client.ExchangeCode(ctx, hearth.TokenRequest{
    ClientID: "<client-id>", Code: code,
    RedirectURI: "http://localhost:3000/callback", CodeVerifier: verifier,
})
`;

const GO_GIN_SNIPPET = `\
import (
    hearth    "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthgin "github.com/hearth-auth/hearth/sdks/go/hearth/gin"
    "github.com/gin-gonic/gin"
)

client := hearth.NewClient("https://hearth.example.com", "<realm-id>")

r := gin.Default()
r.Use(hearthgin.HearthMiddleware(client))

// Gate a route group on a permission — claims decoded locally, no network call
admin := r.Group("/admin", hearthgin.RequirePermission("hearth.admin"))
admin.GET("/data", func(c *gin.Context) {
    c.JSON(200, gin.H{"token": hearthgin.GetToken(c)})
})
`;

const GO_ECHO_SNIPPET = `\
import (
    hearth      "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthecho  "github.com/hearth-auth/hearth/sdks/go/hearth/echo"
    "github.com/labstack/echo/v4"
)

client := hearth.NewClient("https://hearth.example.com", "<realm-id>")

e := echo.New()
e.Use(hearthecho.HearthMiddleware(client))

// Gate a group on a permission — claims decoded locally, no network call
admin := e.Group("/admin", hearthecho.RequirePermission("hearth.admin"))
admin.GET("/data", func(c echo.Context) error {
    return c.JSON(200, map[string]any{"token": hearthecho.GetToken(c)})
})
`;

// ── Python ────────────────────────────────────────────────────────────────────

const PYTHON_SNIPPET = `\
import secrets, hashlib, base64
from hearth import HearthClient

client = HearthClient("http://localhost:8420", "<realm-id>")

# 1. Redirect the user to log in (store verifier + state in the session):
verifier  = secrets.token_urlsafe(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
auth_url = ("http://localhost:8420/realms/dev-realm/authorize?response_type=code"
            "&client_id=<client-id>&redirect_uri=http://localhost:3000/callback&scope=openid"
            "&state=" + state + "&code_challenge=" + challenge + "&code_challenge_method=S256")
return redirect(auth_url)

# 2. On your /callback, exchange the code ("" = public client, no secret):
tokens = client.exchange_code(code, "<client-id>", "", "http://localhost:3000/callback", code_verifier=verifier)
`;

const PYTHON_FASTAPI_SNIPPET = `\
from hearth import HearthClient
from hearth.fastapi import HearthFastAPIDep, require_permission
from fastapi import FastAPI

client    = HearthClient(base_url='http://localhost:8420', realm_id='<realm-id>')
auth      = HearthFastAPIDep(client=client, mode='embedded')
AdminOnly = require_permission('hearth.admin', dep=auth)

app = FastAPI()

@app.get('/admin')
def admin_data(claims: AdminOnly):   # 401/403 raised automatically before handler runs
    return {'sub': claims.sub, 'permissions': claims.permissions}
`;

const PYTHON_DJANGO_SNIPPET = `\
# settings.py — register the middleware and point it at your Hearth instance
import os
from hearth import HearthClient

HEARTH_CLIENT = HearthClient(
    base_url=os.environ['HEARTH_BASE_URL'],
    realm_id=os.environ['HEARTH_REALM_ID'],
)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ...
    'hearth.django.HearthDjangoMiddleware',
]

# views.py — per-view permission gate (no manual token extraction needed)
from hearth.django import require_permission
from django.http import JsonResponse

@require_permission('hearth.admin')
def admin_data(request):
    return JsonResponse({'ok': True})
`;

// ── PHP ───────────────────────────────────────────────────────────────────────

const PHP_SNIPPET = `\
use Hearth\\HearthClient;

$hearth = new HearthClient(issuerUrl: 'http://localhost:8420/realms/dev-realm');

// 1. Redirect the user to log in (store verifier + state in the session):
$verifier  = bin2hex(random_bytes(32));
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
$q = http_build_query([
  'response_type' => 'code', 'client_id' => '<client-id>',
  'redirect_uri' => 'http://localhost:3000/callback', 'scope' => 'openid',
  'state' => $state, 'code_challenge' => $challenge, 'code_challenge_method' => 'S256',
]);
header("Location: http://localhost:8420/realms/dev-realm/authorize?" . $q); exit;

// 2. On your /callback, exchange the code for tokens:
$tokens = $hearth->exchangeCode($_GET['code'], 'http://localhost:3000/callback', $verifier);
`;

const PHP_LARAVEL_SNIPPET = `\
// .env — configure once
// HEARTH_ISSUER_URL=https://hearth.example.com
// HEARTH_CLIENT_ID=<client_id>

// routes/api.php — apply hearth.auth middleware to a route group
Route::middleware('hearth.auth')->group(function () {
    Route::get('/profile',    [ProfileController::class, 'show']);
    Route::post('/documents', [DocumentController::class, 'create']);
});

// app/Http/Controllers/ProfileController.php — read verified claims
public function show(Request $request): JsonResponse {
    $claims = $request->attributes->get('hearth_claims');
    return response()->json(['sub' => $claims->sub]);
}
`;

// ── Rust ──────────────────────────────────────────────────────────────────────

const RUST_SNIPPET = `\
use hearth_sdk::HearthClient;

let client = HearthClient::new("http://localhost:8420", "<realm-id>");

// 1. Redirect the user to log in (store verifier + state in the session).
// challenge = BASE64URL(SHA256(verifier))
let auth_url = format!("http://localhost:8420/realms/dev-realm/authorize?response_type=code\
&client_id=<client-id>&redirect_uri=http://localhost:3000/callback&scope=openid\
&state={state}&code_challenge={challenge}&code_challenge_method=S256");

// 2. On your /callback, exchange the code ("" = public client, no secret):
let tokens = client.exchange_code(
    &code, "<client-id>", "", "http://localhost:3000/callback", Some(&verifier)).await?;
`;

const RUST_ACTIX_SNIPPET = `\
use hearth_sdk::{AccessTokenAuthorization, HearthClient};
use hearth_sdk::actix::{HearthActixMiddleware, RequirePermission};
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = HearthClient::new("https://hearth.example.com", "<realm-id>");

    HttpServer::new(move || {
        App::new().service(
            web::scope("/admin")
                .wrap(HearthActixMiddleware::new(
                    client.clone(), AccessTokenAuthorization::Embedded))
                .wrap(RequirePermission::new("hearth.admin"))
                .route("/data", web::get().to(handler)),
        )
    })
    .bind("0.0.0.0:8080")?.run().await
}
`;

// ── Kotlin ────────────────────────────────────────────────────────────────────

const KOTLIN_SNIPPET = `\
import io.hearth.sdk.HearthClient

val client = HearthClient(
    issuerUrl    = "https://hearth.example.com",
    realmId      = "<realm-id>",
    clientId     = "<client-id>",
)

// Login handler — generate PKCE and return the redirect URL
suspend fun handleLogin(session: YourSessionStore): String {
    val result = client.beginLogin(
        redirectUri = "https://myapp.com/callback",
        scopes      = "openid profile email",
    )
    session["state"]        = result.state
    session["codeVerifier"] = result.codeVerifier
    return result.authorizationUrl   // redirect the browser here
}

// Callback handler — exchange the code for tokens
suspend fun handleCallback(code: String, session: YourSessionStore) =
    client.completeLogin(code, session["codeVerifier"]!!, "https://myapp.com/callback")
`;

const KOTLIN_KTOR_SNIPPET = `\
// build.gradle.kts
// implementation("io.hearth:hearth-ktor:1.0.0")

import io.hearth.sdk.ktor.hearth
import io.hearth.sdk.ktor.HearthPrincipal
import io.ktor.server.application.*
import io.ktor.server.auth.*

fun Application.configureAuth() {
    install(Authentication) {
        hearth("hearth") {
            issuerUrl = System.getenv("HEARTH_ISSUER_URL")
            realmId   = System.getenv("HEARTH_REALM_ID")
        }
    }

    routing {
        authenticate("hearth") {
            get("/admin") {
                val principal = call.principal<HearthPrincipal>()!!
                call.respond(mapOf(
                    "sub"         to principal.claims.subject(),
                    "permissions" to principal.claims.permissions(),
                ))
            }
        }
    }
}
`;

const KOTLIN_SPRING_SNIPPET = `\
// build.gradle.kts
// implementation("io.hearth:hearth-spring:1.0.0")

// application.yml — HearthJwtAuthenticationFilter is auto-configured by Spring Boot
// hearth:
//   issuer-url: https://hearth.example.com
//   realm-id: <realm-id>

// Wire the filter into your SecurityFilterChain:
http.addFilterBefore(hearthFilter, UsernamePasswordAuthenticationFilter::class.java)
    .authorizeHttpRequests { it.anyRequest().authenticated() }

// Use @AuthenticationPrincipal to access the verified HearthAuthentication:
@GetMapping("/admin")
fun admin(@AuthenticationPrincipal auth: HearthAuthentication) = mapOf(
    "sub"         to auth.claims.subject(),
    "permissions" to auth.claims.permissions(),
)
`;

// ── curl ──────────────────────────────────────────────────────────────────────

const CURL_SNIPPET = `\
# 1. Generate an S256 PKCE pair, then open the login URL in a browser:
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "http://localhost:8420/realms/dev-realm/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=openid&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 2. Exchange the ?code= you're redirected with for an access token:
curl -fsS -X POST http://localhost:8420/token -H "X-Realm-ID: $REALM_ID" \\
  -d grant_type=authorization_code -d code=$CODE -d client_id=$CLIENT_ID \\
  -d redirect_uri=http://localhost:3000/callback -d code_verifier=$VERIFIER | jq -r .access_token
`;

const FEATURES = [
  {
    tag: 'Performance',
    title: 'Sub-millisecond hot path',
    desc: 'validate_token, lookup_session, and lookup_user serve from memory-mapped structures with zero heap allocations and no lock contention.',
  },
  {
    tag: 'Standards',
    title: 'OIDC Core & OAuth 2.0',
    desc: 'Full OIDC Core 1.0 conformance. Auth code + PKCE, client credentials, device flow, refresh rotation, introspection, and revocation.',
  },
  {
    tag: 'Auth',
    title: 'MFA & Passkeys',
    desc: 'TOTP, WebAuthn Level 2, magic links, and recovery codes. Brute-force lockout and replay protection included.',
  },
  {
    tag: 'RBAC',
    title: 'Claims-based authorization',
    desc: 'Roles, groups, and permissions embedded in JWTs at issuance. No runtime authorization roundtrips on the hot path.',
  },
  {
    tag: 'Multi-tenant',
    title: 'Realms & Organizations',
    desc: 'Full realm isolation with per-realm signing keys, config, and email branding. B2B org management with invitation flows built in.',
  },
  {
    tag: 'Operations',
    title: 'Single binary, no deps',
    desc: 'Embedded WAL storage engine. No Postgres, no Redis, no sidecar. Raft clustering for HA. Ships as one statically-linked binary.',
  },
];

function QuickstartTeaser() {
  return (
    <section className={styles.quickstart}>
      <div className="container">
        <h2 className={styles.sectionHeading}>First authenticated request in 5 minutes</h2>
        <p className={styles.sectionSub}>
          Drop Hearth into your stack — TypeScript, Node, Go, Python, PHP, Rust, Kotlin, or plain
          HTTP. Select your language then your framework; full guides live on the SDK pages.
        </p>
        <div className={styles.quickstartTabs}>
          <Tabs groupId="lang">

            {/* ── TypeScript ── */}
            <TabItem value="ts" label="TypeScript" default>
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw (browser)" default>
                  <CodeBlock language="ts">{TS_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="react" label="React">
                  <CodeBlock language="tsx">{TS_REACT_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/typescript">Full TypeScript SDK guide →</Link>
              </p>
            </TabItem>

            {/* ── Node.js ── */}
            <TabItem value="node" label="Node">
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw" default>
                  <CodeBlock language="ts">{NODE_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="express" label="Express">
                  <CodeBlock language="ts">{NODE_EXPRESS_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="nextjs" label="Next.js">
                  <CodeBlock language="ts">{NODE_NEXTJS_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/node">Node SDK</Link>
                {' · '}
                <Link to="/docs/sdks/node-nextjs">Next.js adapter →</Link>
              </p>
            </TabItem>

            {/* ── Python ── */}
            <TabItem value="python" label="Python">
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw" default>
                  <CodeBlock language="python">{PYTHON_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="fastapi" label="FastAPI">
                  <CodeBlock language="python">{PYTHON_FASTAPI_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="django" label="Django">
                  <CodeBlock language="python">{PYTHON_DJANGO_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/python">Python SDK</Link>
                {' · '}
                <Link to="/docs/sdks/python-fastapi">FastAPI</Link>
                {' · '}
                <Link to="/docs/sdks/python-django">Django →</Link>
              </p>
            </TabItem>

            {/* ── PHP ── */}
            <TabItem value="php" label="PHP">
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw" default>
                  <CodeBlock language="php">{PHP_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="laravel" label="Laravel">
                  <CodeBlock language="php">{PHP_LARAVEL_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/php">PHP SDK</Link>
                {' · '}
                <Link to="/docs/sdks/php-laravel">Laravel adapter →</Link>
              </p>
            </TabItem>

            {/* ── Go ── */}
            <TabItem value="go" label="Go">
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw" default>
                  <CodeBlock language="go">{GO_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="gin" label="Gin">
                  <CodeBlock language="go">{GO_GIN_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="echo" label="Echo">
                  <CodeBlock language="go">{GO_ECHO_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/go">Go SDK</Link>
                {' · '}
                <Link to="/docs/sdks/go-gin">Gin</Link>
                {' · '}
                <Link to="/docs/sdks/go-echo">Echo →</Link>
              </p>
            </TabItem>

            {/* ── Rust ── */}
            <TabItem value="rust" label="Rust">
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw" default>
                  <CodeBlock language="rust">{RUST_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="actix" label="Actix-web">
                  <CodeBlock language="rust">{RUST_ACTIX_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/rust">Rust SDK</Link>
                {' · '}
                <Link to="/docs/sdks/rust-actix">Actix-web adapter →</Link>
              </p>
            </TabItem>

            {/* ── Kotlin ── */}
            <TabItem value="kotlin" label="Kotlin">
              <Tabs groupId="framework">
                <TabItem value="raw" label="Raw" default>
                  <CodeBlock language="kotlin">{KOTLIN_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="ktor" label="Ktor">
                  <CodeBlock language="kotlin">{KOTLIN_KTOR_SNIPPET}</CodeBlock>
                </TabItem>
                <TabItem value="spring" label="Spring Boot">
                  <CodeBlock language="kotlin">{KOTLIN_SPRING_SNIPPET}</CodeBlock>
                </TabItem>
              </Tabs>
              <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                <Link to="/docs/sdks/kotlin">Kotlin SDK</Link>
                {' · '}
                <Link to="/docs/sdks/kotlin-ktor">Ktor</Link>
                {' · '}
                <Link to="/docs/sdks/kotlin-spring">Spring Boot →</Link>
              </p>
            </TabItem>

            {/* ── curl ── (no inner framework tabs) */}
            <TabItem value="bash" label="curl">
              <CodeBlock language="bash">{CURL_SNIPPET}</CodeBlock>
            </TabItem>

          </Tabs>
        </div>
        <div className={styles.heroCta} style={{ marginTop: '2rem' }}>
          <Link className="button button--primary button--lg" to="/docs/getting-started">
            Full quickstart →
          </Link>
          <Link className="button button--outline button--lg" to="/docs/sdks/overview">
            SDK reference
          </Link>
        </div>
      </div>
    </section>
  );
}

function HeroSection() {
  return (
    <section className={styles.hero}>
      <div className="container">
        <p className={styles.heroEyebrow}>Self-hosted identity provider</p>
        <h1 className={styles.heroTitle}>
          Auth that <span className={styles.heroAccent}>stays lit</span>
        </h1>
        <p className={styles.heroTagline}>
          Hearth is a single-binary OIDC/OAuth2 identity server targeting sub-millisecond
          p99 latency on the validate path — with no external dependencies.
        </p>
        <div className={styles.heroCta}>
          <Link className="button button--primary button--lg" to="/docs/getting-started">
            Get started →
          </Link>
          <Link className="button button--outline button--lg" to="/docs/migrating-from-keycloak">
            Migrate from Keycloak
          </Link>
        </div>
      </div>
    </section>
  );
}

function StatsBar() {
  return (
    <div className="container">
      <div className={styles.stats}>
        <div className={styles.stat}>
          <span className={styles.statValue}>&lt;1 ms</span>
          <span className={styles.statLabel}>p99 validate_token</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.statValue}>0</span>
          <span className={styles.statLabel}>heap allocs on hot path</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.statValue}>1</span>
          <span className={styles.statLabel}>binary, no deps</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.statValue}>OIDC</span>
          <span className={styles.statLabel}>Core 1.0 conformant</span>
        </div>
      </div>
    </div>
  );
}

function FeaturesSection() {
  return (
    <section className={styles.features}>
      <div className="container">
        <h2 className={styles.sectionHeading}>Everything identity needs</h2>
        <p className={styles.sectionSub}>
          No Postgres. No Redis. No plugin system to maintain. Just one binary.
        </p>
        <div className={styles.featuresGrid}>
          {FEATURES.map(({ tag, title, desc }) => (
            <div key={title} className={styles.featureCard}>
              <p className={styles.featureIcon}>{tag}</p>
              <h3 className={styles.featureTitle}>{title}</h3>
              <p className={styles.featureDesc}>{desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function MigrateSection() {
  return (
    <section className={styles.migrate}>
      <div className="container" style={{ textAlign: 'center', padding: '0 1.5rem' }}>
        <h2 className={styles.sectionHeading}>Drop-in from Keycloak or Auth0</h2>
        <p className={styles.sectionSub}>
          Realm export → <code>hearth migrate keycloak --file export.json</code>. Users,
          credentials, and clients migrate in one command. PBKDF2-SHA256 hashes carry
          over; Argon2id upgrade happens transparently on next login.
        </p>
        <div className={styles.heroCta}>
          <Link className="button button--primary button--lg" to="/docs/migrating-from-keycloak">
            Keycloak migration guide →
          </Link>
          <Link className="button button--outline button--lg" to="/docs/migrating-from-auth0">
            Auth0 migration guide
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description={siteConfig.tagline}
    >
      <main>
        <HeroSection />
        <QuickstartTeaser />
        <StatsBar />
        <FeaturesSection />
        <MigrateSection />
      </main>
    </Layout>
  );
}

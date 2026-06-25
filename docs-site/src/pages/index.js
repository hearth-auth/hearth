import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import CodeBlock from '@theme/CodeBlock';
import clsx from 'clsx';

import styles from './index.module.css';

const TS_SNIPPET = `\
import { HearthApiClient, createHearthAuth } from '@hearth-auth/sdk';

const client = new HearthApiClient({
  baseUrl: 'http://localhost:8420/realms/dev-realm',
  realmId: '<realm-id>',
});

// One helper runs the full OAuth 2.0 + PKCE handshake for you.
const auth = createHearthAuth(client, {
  clientId: '<client-id>',
  redirectUri: 'http://localhost:3000/callback',
  hearthUrl: 'http://localhost:8420',
  realmSlug: 'dev-realm',
});

await auth.startLogin();                  // "Log in" button → redirect to Hearth
// …on your /callback route:
const p = new URLSearchParams(window.location.search);
await auth.handleCallback(p.get('code'), p.get('state')); // tokens stored + auto-refreshed
`;

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

const RUST_SNIPPET = `\
use hearth_sdk::HearthClient;

let client = HearthClient::new("http://localhost:8420", "<realm-id>");

// 1. Redirect the user to log in (store verifier + state in the session).
// challenge = BASE64URL(SHA256(verifier))
let auth_url = format!("http://localhost:8420/realms/dev-realm/authorize?response_type=code&client_id=<client-id>&redirect_uri=http://localhost:3000/callback&scope=openid&state={state}&code_challenge={challenge}&code_challenge_method=S256");

// 2. On your /callback, exchange the code ("" = public client, no secret):
let tokens = client.exchange_code(&code, "<client-id>", "", "http://localhost:3000/callback", Some(&verifier)).await?;
`;

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
          Drop SDK login into your stack — TypeScript, Go, Python, PHP, or Rust. The full
          quickstart below covers bootstrapping a realm and registering a client; Node
          verifies the resulting tokens server-side.
        </p>
        <div className={styles.quickstartTabs}>
          <Tabs groupId="lang">
            <TabItem value="ts" label="TypeScript" default>
              <CodeBlock language="ts">{TS_SNIPPET}</CodeBlock>
            </TabItem>
            <TabItem value="go" label="Go">
              <CodeBlock language="go">{GO_SNIPPET}</CodeBlock>
            </TabItem>
            <TabItem value="python" label="Python">
              <CodeBlock language="python">{PYTHON_SNIPPET}</CodeBlock>
            </TabItem>
            <TabItem value="php" label="PHP">
              <CodeBlock language="php">{PHP_SNIPPET}</CodeBlock>
            </TabItem>
            <TabItem value="rust" label="Rust">
              <CodeBlock language="rust">{RUST_SNIPPET}</CodeBlock>
            </TabItem>
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

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
import { HearthApiClient, generateCodeVerifier, generateCodeChallenge } from '@hearth-auth/sdk';

const client    = new HearthApiClient({ baseUrl: 'http://localhost:8420', realmId: '<realm-id>' });
const app       = await client.registerClient({ clientName: 'quickstart', redirectUris: ['http://localhost:3000/callback'] });
const verifier  = generateCodeVerifier();
const challenge = await generateCodeChallenge(verifier);
const { code }  = await client.authorize({
  clientId: app.client_id, codeChallenge: challenge, codeChallengeMethod: 'S256',
  userId: '<user-id>',    // dev mode only — omit in production
});
const tokens = await client.exchangeCode({ clientId: app.client_id, code, codeVerifier: verifier });
const { permissions } = await client.permissions(tokens.access_token);
console.log('has hearth.admin:', permissions.includes('hearth.admin')); // → true
`;

const GO_SNIPPET = `\
// go get github.com/hearth-auth/hearth/sdks/go/hearth
client   := hearth.NewClient("http://localhost:8420", "<realm-id>")
app, _   := client.RegisterClient(ctx, hearth.RegisterClientRequest{
    ClientName: "quickstart", RedirectURIs: []string{"http://localhost:3000/callback"},
})
pkce, _  := hearth.GeneratePKCE()
auth, _  := client.Authorize(ctx, hearth.AuthorizeRequest{
    ClientID: app.ClientID, UserID: "<user-id>", // dev mode only — omit in production
    CodeChallenge: pkce.Challenge, CodeChallengeMethod: pkce.Method,
})
tokens, _ := client.ExchangeCode(ctx, hearth.TokenRequest{
    ClientID: app.ClientID, Code: auth.Code, CodeVerifier: pkce.Verifier,
})
fmt.Println("has hearth.admin:", client.HasPermission(tokens.AccessToken, "hearth.admin")) // → true
`;

const CURL_SNIPPET = `\
# Boot: docker run --rm -p 8420:8420 ghcr.io/hearth-auth/hearth:latest serve --dev --bind 0.0.0.0
BOOT=$(curl -fsS -X POST http://127.0.0.1:8420/admin/bootstrap)
REALM=$(echo "$BOOT" | jq -r .realm_id)
TOKEN=$(echo "$BOOT" | jq -r .access_token)

# Register a public client (PKCE — no secret needed)
CLIENT=$(curl -fsS -X POST http://127.0.0.1:8420/admin/clients \\
  -H "Authorization: Bearer $TOKEN" -H "X-Realm-ID: $REALM" \\
  -d '{"client_name":"quickstart","redirect_uris":["http://localhost:3000/callback"]}')

# Verify the OIDC discovery document is live
curl -fsS "http://127.0.0.1:8420/.well-known/openid-configuration?realm=$REALM" | jq .issuer
# → "http://127.0.0.1:8420/realms/<realm-id>"
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
          Boot Hearth, bootstrap a realm, run the PKCE flow from your stack.
        </p>
        <div className={styles.quickstartTabs}>
          <Tabs groupId="lang">
            <TabItem value="ts" label="TypeScript" default>
              <CodeBlock language="ts">{TS_SNIPPET}</CodeBlock>
            </TabItem>
            <TabItem value="go" label="Go">
              <CodeBlock language="go">{GO_SNIPPET}</CodeBlock>
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

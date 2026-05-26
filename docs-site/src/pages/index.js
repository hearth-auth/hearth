import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import clsx from 'clsx';

import styles from './index.module.css';

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
        <StatsBar />
        <FeaturesSection />
        <MigrateSection />
      </main>
    </Layout>
  );
}

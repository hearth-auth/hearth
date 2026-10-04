// SDK conformance runner (sdks/conformance/README.md).
//
// Reads a case file, runs each case through the public SDK API, and prints one
// JSON line per case on stdout. Uses only what src/index.ts exports.
import { readFileSync } from "node:fs";

import {
  Claims,
  ConfigurationError,
  DiscoveryError,
  HearthClient,
  IntrospectionError,
  JWKSFetchError,
  RequiredActionError,
  TokenAudienceError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenNotYetValidError,
} from "../src/index.js";

interface CaseConfig {
  base_url: string;
  realm: string;
  issuer: string;
  audience: string | null;
  client_id: string | null;
  client_secret: string | null;
}

interface Case {
  id: string;
  kind: "verify_token" | "client_credentials";
  token?: string;
  scope?: string;
  config: CaseConfig;
  claims: string[];
}

// openspec/specs/sdk-support-contract/spec.md names, in subclass-before-superclass order.
const SECTION_5_ERRORS: Array<[new (...args: never[]) => Error, string]> = [
  [ConfigurationError, "ConfigurationError"],
  [DiscoveryError, "DiscoveryError"],
  [JWKSFetchError, "JWKSFetchError"],
  [TokenExpiredError, "TokenExpiredError"],
  [TokenNotYetValidError, "TokenNotYetValidError"],
  [TokenIssuerError, "TokenIssuerError"],
  [TokenAudienceError, "TokenAudienceError"],
  [RequiredActionError, "RequiredActionError"],
  [IntrospectionError, "IntrospectionError"],
  [TokenInvalidError, "TokenInvalidError"],
];

function errorName(err: unknown): string {
  for (const [cls, name] of SECTION_5_ERRORS) {
    if (err instanceof cls) return name;
  }
  const type = err instanceof Error ? err.constructor.name : typeof err;
  return `Unexpected:${type}`;
}

function pickClaims(claims: Claims, names: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of names) {
    if (name === "sub") out.sub = claims.subject();
    else if (name === "scope") out.scope = claims.scope() || null;
    else if (name === "permissions") {
      const perms = claims.get("permissions");
      out.permissions = Array.isArray(perms) ? perms : [];
    } else out[name] = claims.get(name) ?? null;
  }
  return out;
}

// The SDK checks `aud` against `clientId`, so the verifying client carries the
// case's expected audience there.
function verifier(config: CaseConfig): HearthClient {
  return new HearthClient({
    issuerUrl: config.issuer,
    clientId: config.audience ?? undefined,
  });
}

async function runCase(c: Case): Promise<Record<string, unknown>> {
  try {
    let token = c.token ?? "";
    if (c.kind === "client_credentials") {
      const client = new HearthClient({
        issuerUrl: c.config.issuer,
        clientId: c.config.client_id ?? undefined,
        clientSecret: c.config.client_secret ?? undefined,
      });
      token = (await client.clientCredentials(c.scope)).access_token;
    }
    const claims = await verifier(c.config).verifyToken(token);
    return { id: c.id, outcome: "ok", claims: pickClaims(claims, c.claims) };
  } catch (err) {
    return { id: c.id, outcome: "error", error: errorName(err) };
  }
}

async function main(): Promise<void> {
  const path = process.argv[2];
  if (!path) {
    process.stderr.write("usage: run.sh <cases.json>\n");
    process.exit(2);
  }
  const { cases } = JSON.parse(readFileSync(path, "utf8")) as { cases: Case[] };
  for (const c of cases) {
    process.stdout.write(JSON.stringify(await runCase(c)) + "\n");
  }
}

await main();

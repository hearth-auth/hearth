/** §4 — VerifiedToken: typed claims accessors. */

import type { JWTPayload } from "jose";

interface RawPayload extends JWTPayload {
  scope?: string;
  scopes?: string[];
  [key: string]: unknown;
}

/** Timing-safe string comparison using Web Crypto (available in all modern browsers and Workers). */
async function timingSafeStringEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const len = Math.max(a.length, b.length);
  const bufA = enc.encode(a.padEnd(len, "\0"));
  const bufB = enc.encode(b.padEnd(len, "\0"));

  // HMAC with a random key — equal inputs produce equal outputs independent of timing
  const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const [macA, macB] = await Promise.all([
    crypto.subtle.sign("HMAC", key, bufA),
    crypto.subtle.sign("HMAC", key, bufB),
  ]);

  const viewA = new Uint8Array(macA);
  const viewB = new Uint8Array(macB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) diff |= viewA[i] ^ viewB[i];
  return diff === 0 && a.length === b.length;
}

export class VerifiedToken {
  private readonly _payload: RawPayload;
  private readonly _header: Record<string, unknown>;

  constructor(payload: JWTPayload | Record<string, unknown>, header: Record<string, unknown>) {
    this._payload = payload as unknown as RawPayload;
    this._header = header;
  }

  /** The `sub` claim. Returns empty string if absent. */
  subject(): string {
    return this._payload.sub ?? "";
  }

  /** The `iss` claim. Returns empty string if absent. */
  issuer(): string {
    return this._payload.iss ?? "";
  }

  /** The `aud` claim normalized to an array. */
  audience(): string[] {
    const aud = this._payload.aud;
    if (!aud) return [];
    return Array.isArray(aud) ? aud : [aud];
  }

  /** The `iat` claim as a Date, or null if absent. */
  issuedAt(): Date | null {
    return this._payload.iat !== undefined ? new Date(this._payload.iat * 1000) : null;
  }

  /** The `exp` claim as a Date, or null if absent. */
  expiresAt(): Date | null {
    return this._payload.exp !== undefined ? new Date(this._payload.exp * 1000) : null;
  }

  /** The `nbf` claim as a Date, or null if absent. */
  notBefore(): Date | null {
    return this._payload.nbf !== undefined ? new Date(this._payload.nbf * 1000) : null;
  }

  /** The raw `scope` string claim (space-separated). */
  scope(): string {
    return this._payload.scope ?? "";
  }

  /** The `scope` claim split into individual values. */
  scopes(): string[] {
    if (this._payload.scopes) return [...this._payload.scopes];
    const sc = this._payload.scope;
    if (!sc) return [];
    return sc.split(/\s+/).filter(Boolean);
  }

  /** Get an arbitrary claim by key. */
  get(key: string): unknown {
    return this._payload[key];
  }

  /** Return the raw JWT payload (frozen copy). */
  raw(): Readonly<RawPayload> {
    return Object.freeze({ ...this._payload });
  }

  /** Timing-safe check: true if the token contains the given scope. */
  async hasScope(s: string): Promise<boolean> {
    const all = this.scopes();
    const results = await Promise.all(all.map((sc) => timingSafeStringEqual(sc, s)));
    return results.some(Boolean);
  }
}

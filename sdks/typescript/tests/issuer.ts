/**
 * An in-memory stand-in for a Hearth realm: an Ed25519 key pair, the realm's
 * discovery document and JWKS, and a signer for access tokens that verify
 * against them. `fetchImpl` answers the discovery and JWKS URLs and passes any
 * other request to `fallback`.
 */
import { SignJWT, exportJWK, generateKeyPair } from "jose";

export const ISSUER = "https://hearth.example.com/realms/acme";
const KID = "test-key";

export interface TestIssuer {
  issuer: string;
  /** Sign an access token. `aud` defaults to `hearth`, `iss` to the issuer, `exp` to 1 h. */
  sign(claims?: Record<string, unknown>): Promise<string>;
  /** Re-encode a signed token's payload with `changes`, keeping the original signature. */
  tamper(token: string, changes: Record<string, unknown>): string;
  /** A `fetch` that serves discovery and the JWKS, and defers anything else to `fallback`. */
  fetchImpl(fallback?: (url: string) => Promise<Response>): (input: unknown) => Promise<Response>;
}

export async function makeIssuer(issuer = ISSUER): Promise<TestIssuer> {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const jwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA", use: "sig" };
  const json = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  return {
    issuer,
    sign(claims = {}) {
      return new SignJWT({ aud: "hearth", ...claims })
        .setProtectedHeader({ alg: "EdDSA", kid: KID })
        .setIssuedAt()
        .setIssuer(issuer)
        .setExpirationTime("1h")
        .sign(privateKey);
    },
    tamper(token, changes) {
      const [header, payload, signature] = token.split(".");
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<
        string,
        unknown
      >;
      const forged = Buffer.from(JSON.stringify({ ...claims, ...changes }), "utf8").toString(
        "base64url",
      );
      return `${header}.${forged}.${signature}`;
    },
    fetchImpl(fallback = () => Promise.reject(new Error("offline"))) {
      return (input: unknown) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url === `${issuer}/.well-known/openid-configuration`) {
          return Promise.resolve(json({ issuer, jwks_uri: `${issuer}/.well-known/jwks.json` }));
        }
        if (url === `${issuer}/.well-known/jwks.json`) {
          return Promise.resolve(json({ keys: [jwk] }));
        }
        return fallback(url);
      };
    },
  };
}

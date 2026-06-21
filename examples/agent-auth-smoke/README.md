# Agent Auth Smoke Test

End-to-end smoke test for Hearth's Agent Auth M5 surface (HEA-1409).

## What it tests

| Step | Standard | Description |
|------|----------|-------------|
| Agent CRUD | AGENT_AUTH §1.2 | Create agents, issue API keys, verify agent card |
| DPoP-bound token | RFC 9449 | EC P-256 key pair, JWK thumbprint, `cnf.jkt` binding |
| RFC 8693 exchange | RFC 8693 | Token exchange with `act` chain and `on_behalf_of` claim |
| AAT issuance | draft-niyikiza AAT | Root AAT for agent, child derivation with scope narrowing |
| Transaction tokens | AGENT_AUTH §8.5 | Issue → consume → replay prevention (single-use) |
| Agent Card | A2A v0.3 | `GET /.well-known/agent.json?agent_id=…` |
| PRM | RFC 9728 | `GET /.well-known/oauth-protected-resource` |

## Usage

```bash
# Run standalone (builds hearth from source)
bash examples/agent-auth-smoke/smoke.sh

# Run as part of the full SDK smoke suite
make sdk-smoke-local
```

## Prerequisites

- `cargo` — builds `hearth` in debug mode
- `node ≥ 18` — native crypto for DPoP proof generation (no extra packages)
- `jq`, `curl`, `python3`

## Config

The script writes a temporary `hearth.yaml` enabling:
```yaml
agent_auth:
  capabilities:
    identity: true   # /v1/agents, /.well-known/agent.json
    advanced: true   # /v1/aats, /v1/transaction-tokens
```

The server starts in `--dev` mode (ephemeral storage, no TLS, bootstrap endpoint active).

## DPoP proof construction

The Node.js inline script uses only `node:crypto` (no npm packages):

1. `crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })` — generate key
2. Canonical JWK: `{crv, kty, x, y}` (lexicographic, RFC 7638 §3)
3. JWK thumbprint: `SHA-256(canonical)` encoded as `base64url`
4. DPoP proof JWT: `{alg: ES256, jwk: …, typ: dpop+jwt}` header + `{htm, htu, iat, jti, nonce}` claims
5. Sign with `crypto.sign('SHA256', …, { dsaEncoding: 'ieee-p1363' })` (raw r‖s, not DER)
6. Verify `cnf.jkt` in issued access token matches computed thumbprint

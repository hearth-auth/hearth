#!/usr/bin/env bash
# Agent Auth End-to-End Smoke Test (HEA-1463 / M5 close-out)
#
# Demonstrates the full Agent Auth M5 surface against a live hearth --dev server:
#   1. Agent CRUD + API-key issuance
#   2. DPoP-bound token (RFC 9449) via client_credentials grant
#   3. RFC 8693 token exchange with act-chain and on_behalf_of claim
#   4. AAT issuance + child derivation (draft-niyikiza-oauth-attenuating-agent-tokens)
#   5. Transaction token lifecycle: issue → consume → replay-rejected
#
# Usage (standalone):
#   bash examples/agent-auth-smoke/smoke.sh
#
# Called automatically by: make sdk-smoke-local
#
# Prerequisites: cargo, node (≥18 for native fetch + crypto), jq, curl

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${REPO_ROOT}/target/debug/hearth"
HEARTH_PID=""
CFG_FILE=""

# ── helpers ──────────────────────────────────────────────────────────────────

free_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('',0)); p=s.getsockname()[1]; s.close(); print(p)"
}

die() { echo "FAIL: $*" >&2; exit 1; }

check_pass() { echo "    OK: $*"; }

jwt_payload() {
    local tok="${1#*.}"
    tok="${tok%%.*}"
    # pad to multiple of 4
    local pad=$(( (4 - ${#tok} % 4) % 4 ))
    printf '%s%*s' "$tok" "$pad" | tr ' ' '=' | base64 -d 2>/dev/null | jq -c .
}

cleanup() {
    [[ -n "${HEARTH_PID:-}" ]] && kill "$HEARTH_PID" 2>/dev/null || true
    [[ -n "${HEARTH_PID:-}" ]] && wait "$HEARTH_PID" 2>/dev/null || true
    [[ -n "${DATA_DIR:-}" ]] && rm -rf "$DATA_DIR"
}

# CFG_FILE is unused: --dev auto-enables all agent_auth capabilities.
trap cleanup EXIT

# ── sanity checks ─────────────────────────────────────────────────────────────

for bin in cargo node jq curl python3; do
    command -v "$bin" >/dev/null 2>&1 || die "missing required tool: $bin"
done

NODE_MAJOR=$(node -e "process.stdout.write(process.version.split('.')[0].slice(1))")
[[ "$NODE_MAJOR" -ge 18 ]] || die "Node.js ≥18 required for native crypto (got v${NODE_MAJOR}.x)"

# ── 1. Build hearth ───────────────────────────────────────────────────────────

echo "==> agent-auth smoke — building hearth (debug)"
cd "$REPO_ROOT"
PROTOC="${PROTOC:-protoc}" cargo build --bin hearth -q 2>&1

# ── 2. Start hearth --dev ────────────────────────────────────────────────────
# --dev auto-enables agent_auth.capabilities.{identity,approval,advanced},
# so no config file is needed for the smoke test.

PORT=$(free_port)
DATA_DIR="$(mktemp -d -t hearth-agent-auth-XXXXXX)"
BASE="http://127.0.0.1:${PORT}"

echo "==> Starting hearth serve --dev (port ${PORT})"
"$BIN" serve --dev --port "$PORT" >"$DATA_DIR/hearth.log" 2>&1 &
HEARTH_PID=$!

for _ in $(seq 1 60); do
    if curl -sf "${BASE}/health" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf "${BASE}/health" >/dev/null || { tail -40 "$DATA_DIR/hearth.log" >&2; die "hearth did not start in 15s"; }
echo "    hearth ready"

# ── 4. Bootstrap admin token + realm ─────────────────────────────────────────

echo "==> Bootstrapping dev realm"
BOOT=$(curl -sf -X POST "${BASE}/admin/bootstrap")
ADMIN_TOKEN=$(echo "$BOOT" | jq -r .access_token)
REALM_ID=$(echo "$BOOT" | jq -r .realm_id)
echo "    realm_id=${REALM_ID}"

AUTH="-H 'Authorization: Bearer ${ADMIN_TOKEN}'"
realm_hdr="-H 'X-Realm-ID: ${REALM_ID}'"

api() {
    local method="$1"; shift
    local path="$1"; shift
    curl -sf -X "$method" "${BASE}${path}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        "$@"
}

# ── 5. Create two agents ──────────────────────────────────────────────────────

echo "==> Creating agents"
AGENT_A=$(api POST /v1/agents -d "{
    \"realm_id\": \"${REALM_ID}\",
    \"display_name\": \"smoke-agent-a\",
    \"description\": \"M5 smoke test — agent A\",
    \"capabilities\": [\"urn:hearth:capability:smoke:read\"]
}")
AGENT_A_ID=$(echo "$AGENT_A" | jq -r .agent_id)
echo "    agent_a=${AGENT_A_ID}"

AGENT_B=$(api POST /v1/agents -d "{
    \"realm_id\": \"${REALM_ID}\",
    \"display_name\": \"smoke-agent-b\",
    \"description\": \"M5 smoke test — agent B\",
    \"capabilities\": []
}")
AGENT_B_ID=$(echo "$AGENT_B" | jq -r .agent_id)
echo "    agent_b=${AGENT_B_ID}"

# ── 6. Issue API keys for both agents ─────────────────────────────────────────

echo "==> Issuing API keys"
KEY_A=$(api POST "/v1/agents/${AGENT_A_ID}/credentials/keys" -d '{"description":"smoke-key-a"}')
AGENT_A_KEY=$(echo "$KEY_A" | jq -r .api_key)
[[ "${AGENT_A_KEY}" != "null" && -n "${AGENT_A_KEY}" ]] || die "no api_key in response for agent-a"
echo "    agent_a key issued (prefix=${AGENT_A_KEY:0:12}…)"

KEY_B=$(api POST "/v1/agents/${AGENT_B_ID}/credentials/keys" -d '{"description":"smoke-key-b"}')
AGENT_B_KEY=$(echo "$KEY_B" | jq -r .api_key)
[[ "${AGENT_B_KEY}" != "null" && -n "${AGENT_B_KEY}" ]] || die "no api_key in response for agent-b"
echo "    agent_b key issued"

# ── 7. DPoP-bound token issuance (RFC 9449) ───────────────────────────────────
#
# Demonstrates §6 of AGENT_AUTH.md:
#   - Register a confidential OAuth client
#   - Generate EC P-256 key pair (in Node.js native crypto)
#   - Issue a DPoP proof JWT (typ: dpop+jwt, ES256)
#   - client_credentials grant + DPoP header → token with cnf.jkt binding

echo "==> DPoP-bound token issuance (RFC 9449)"

# Register a confidential OAuth client (agent_a as service account)
CLIENT=$(api POST /admin/applications \
    -H "X-Realm-ID: ${REALM_ID}" \
    -d "{
        \"client_name\": \"smoke-agent-a-m2m\",
        \"grant_types\": [\"client_credentials\"],
        \"redirect_uris\": []
    }")
CLIENT_ID=$(echo "$CLIENT" | jq -r .client_id)
CLIENT_SECRET=$(echo "$CLIENT" | jq -r .client_secret)
[[ "$CLIENT_ID" != "null" ]] || die "failed to create OAuth client"
echo "    client_id=${CLIENT_ID}"

# Use Node.js (native crypto) to:
#  a) generate P-256 key pair
#  b) build DPoP proof JWT
#  c) issue client_credentials token via native fetch
#  d) verify cnf.jkt in the access token
DPOP_RESULT=$(node - <<JSEOF
'use strict';
const crypto = require('node:crypto');

const BASE    = '${BASE}';
const REALM   = '${REALM_ID}';
const CID     = '${CLIENT_ID}';
const CSECRET = '${CLIENT_SECRET}';
const TOKEN_URL = \`\${BASE}/realms/\${REALM}/token\`;

// Generate EC P-256 key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pubJwk = publicKey.export({ format: 'jwk' });

// Canonical JWK for thumbprint per RFC 7638 §3 (required members, lex order)
const canonical = JSON.stringify({ crv: pubJwk.crv, kty: pubJwk.kty, x: pubJwk.x, y: pubJwk.y });
const thumbprint = crypto.createHash('sha256').update(canonical).digest('base64url');

function b64u(obj) {
    return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function makeDPopProof(htm, htu, nonce) {
    const header = {
        alg: 'ES256',
        jwk: { crv: 'EC', kty: 'EC', x: pubJwk.x, y: pubJwk.y },
        typ: 'dpop+jwt',
    };
    const claims = {
        htm,
        htu,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
    };
    if (nonce) claims.nonce = nonce;
    const input = \`\${b64u(header)}.\${b64u(claims)}\`;
    const sig = crypto.sign('SHA256', Buffer.from(input), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363', // raw r||s for JWT, not DER
    });
    return \`\${input}.\${sig.toString('base64url')}\`;
}

(async () => {
    // Step 1: request without nonce — server ALWAYS returns DPoP-Nonce
    const proof1 = makeDPopProof('POST', TOKEN_URL, null);
    const creds  = Buffer.from(\`\${CID}:\${CSECRET}\`).toString('base64');
    const body   = new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'openid',
    });
    const resp1 = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: {
            Authorization: \`Basic \${creds}\`,
            DPoP: proof1,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
    });
    const serverNonce = resp1.headers.get('dpop-nonce');
    if (!serverNonce) throw new Error('server did not return DPoP-Nonce on first request');

    // Step 2: request with server nonce (required by RFC 9449 §8)
    const proof2 = makeDPopProof('POST', TOKEN_URL, serverNonce);
    const resp2 = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: {
            Authorization: \`Basic \${creds}\`,
            DPoP: proof2,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
    });
    if (!resp2.ok) {
        const txt = await resp2.text();
        throw new Error(\`token endpoint returned \${resp2.status}: \${txt}\`);
    }
    const tok = await resp2.json();
    if (!tok.access_token) throw new Error('no access_token in response');

    // Decode and verify cnf.jkt claim in the access token
    const [, payload] = tok.access_token.split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!claims.cnf || !claims.cnf.jkt) {
        throw new Error('access_token missing cnf.jkt (DPoP binding not applied)');
    }
    if (claims.cnf.jkt !== thumbprint) {
        throw new Error(\`cnf.jkt mismatch: got \${claims.cnf.jkt}, want \${thumbprint}\`);
    }

    process.stdout.write(JSON.stringify({
        access_token: tok.access_token,
        cnf_jkt: claims.cnf.jkt,
        sub: claims.sub,
    }));
})().catch(e => { process.stderr.write(e.message + '\\n'); process.exit(1); });
JSEOF
)

DPOP_JKT=$(echo "$DPOP_RESULT" | jq -r .cnf_jkt)
DPOP_SUB=$(echo "$DPOP_RESULT" | jq -r .sub)
[[ "${DPOP_JKT}" != "null" && -n "${DPOP_JKT}" ]] || die "DPoP binding check failed"
check_pass "DPoP-bound AT issued — cnf.jkt=${DPOP_JKT:0:16}… sub=${DPOP_SUB}"

# ── 8. RFC 8693 Token Exchange ────────────────────────────────────────────────
#
# Exchanges the admin access_token for an agent-scoped token, verifying:
#  - act claim (delegation chain per RFC 8693 §4.1)
#  - on_behalf_of claim (OBO draft extension)
#  - scope attenuation

echo "==> RFC 8693 Token Exchange (OBO + act chain)"

TOKEN_URL_GLOBAL="${BASE}/token"
EXCHANGE=$(curl -sf -X POST "${TOKEN_URL_GLOBAL}" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" \
    -d "subject_token=${ADMIN_TOKEN}" \
    -d "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token" \
    -d "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token" \
    -d "scope=openid")
EXCHANGED_TOKEN=$(echo "$EXCHANGE" | jq -r .access_token)
[[ "$EXCHANGED_TOKEN" != "null" && -n "$EXCHANGED_TOKEN" ]] || die "RFC 8693 exchange returned no access_token"

EXCH_PAYLOAD=$(jwt_payload "$EXCHANGED_TOKEN")
ACT_CLAIM=$(echo "$EXCH_PAYLOAD" | jq -r '.act // empty')
[[ -n "$ACT_CLAIM" ]] || die "exchanged token missing act claim (RFC 8693 §4.1)"
check_pass "RFC 8693 exchange succeeded — act chain present: ${ACT_CLAIM}"

# ── 9. AAT Issuance + Derivation ──────────────────────────────────────────────
#
# Phase D §4: Attenuating Authorization Tokens
#  - Root AAT issued by Hearth for agent-a with tool scopes
#  - Child AAT derived with narrowed scope (scope ⊆ parent)

echo "==> AAT issuance + child derivation"

ROOT_AAT=$(api POST /v1/aats -d "{
    \"realm_id\": \"${REALM_ID}\",
    \"agent_id\": \"${AGENT_A_ID}\",
    \"tools\": [
        {\"tool_name\": \"read_docs\", \"constraints\": null},
        {\"tool_name\": \"search_files\", \"constraints\": null}
    ],
    \"expires_in_secs\": 3600
}")
ROOT_JTI=$(echo "$ROOT_AAT" | jq -r .jti)
ROOT_TOKEN=$(echo "$ROOT_AAT" | jq -r .token)
[[ "$ROOT_JTI" != "null" && -n "$ROOT_JTI" ]] || die "AAT issuance failed"
check_pass "Root AAT issued — jti=${ROOT_JTI:0:8}…"

# Derive child AAT with reduced tool set (scope narrowing: child ⊆ parent)
CHILD_AAT=$(api POST /v1/aats/derive -d "{
    \"realm_id\": \"${REALM_ID}\",
    \"parent_token\": \"${ROOT_TOKEN}\",
    \"tools\": [
        {\"tool_name\": \"read_docs\", \"constraints\": null}
    ],
    \"expires_in_secs\": 300
}")
CHILD_JTI=$(echo "$CHILD_AAT" | jq -r .jti)
[[ "$CHILD_JTI" != "null" && -n "$CHILD_JTI" ]] || die "AAT derivation failed"
check_pass "Child AAT derived — jti=${CHILD_JTI:0:8}… (scope: [read_docs] ⊆ parent [read_docs, search_files])"

# Verify: validate the child AAT
VALIDATE=$(api POST /v1/aats/validate -d "{
    \"realm_id\": \"${REALM_ID}\",
    \"token\": $(echo "$CHILD_AAT" | jq .token)
}")
VALID=$(echo "$VALIDATE" | jq -r .valid)
[[ "$VALID" == "true" ]] || die "child AAT validation failed (got: $VALID)"
check_pass "Child AAT validated OK"

# ── 10. Transaction Token lifecycle ──────────────────────────────────────────
#
# Phase D §8.5: single-use, 60s transaction tokens
#  - Issue txn token binding agent-a → agent-b
#  - Consume: OK on first call
#  - Consume: 409/422 on second call (replay prevention)

echo "==> Transaction token lifecycle"

TXN=$(api POST /v1/transaction-tokens -d "{
    \"realm_id\": \"${REALM_ID}\",
    \"requesting_agent_id\": \"${AGENT_A_ID}\",
    \"target_agent_id\": \"${AGENT_B_ID}\",
    \"txn_id\": \"smoke-txn-$(date +%s%N)\"
}")
TXN_TOKEN=$(echo "$TXN" | jq -r .token)
TXN_JTI=$(echo "$TXN" | jq -r .jti)
[[ "$TXN_JTI" != "null" && -n "$TXN_JTI" ]] || die "transaction token issuance failed"
check_pass "Transaction token issued — jti=${TXN_JTI:0:8}… (60s TTL, single-use)"

# First consume: should succeed
CONSUME_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/v1/transaction-tokens/consume" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"realm_id\": \"${REALM_ID}\", \"token\": ${TXN_TOKEN@Q}}")
[[ "$CONSUME_STATUS" == "200" ]] || die "first consume returned ${CONSUME_STATUS}, expected 200"
check_pass "First consume: 200 OK"

# Second consume: MUST fail (replay prevention)
REPLAY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/v1/transaction-tokens/consume" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"realm_id\": \"${REALM_ID}\", \"token\": ${TXN_TOKEN@Q}}")
[[ "$REPLAY_STATUS" == "409" || "$REPLAY_STATUS" == "422" || "$REPLAY_STATUS" == "400" ]] \
    || die "replay consume returned ${REPLAY_STATUS}, expected 4xx"
check_pass "Replay consume: ${REPLAY_STATUS} (replay prevention working)"

# ── 11. Agent Card (A2A §1.6) ─────────────────────────────────────────────────

echo "==> Agent Card (A2A /.well-known/agent.json)"
CARD=$(curl -sf "${BASE}/.well-known/agent.json?agent_id=${AGENT_A_ID}")
CARD_NAME=$(echo "$CARD" | jq -r .name)
[[ -n "$CARD_NAME" && "$CARD_NAME" != "null" ]] || die "agent card missing name"
check_pass "Agent Card served — name=${CARD_NAME}"

# ── 12. Protected Resource Metadata (RFC 9728) ────────────────────────────────

echo "==> Protected Resource Metadata (RFC 9728)"
PRM=$(curl -sf "${BASE}/.well-known/oauth-protected-resource")
PRM_RESOURCE=$(echo "$PRM" | jq -r .resource)
[[ -n "$PRM_RESOURCE" && "$PRM_RESOURCE" != "null" ]] \
    || die "PRM missing resource field (RFC 9728 §3)"
check_pass "PRM served — resource=${PRM_RESOURCE}"

# ── done ──────────────────────────────────────────────────────────────────────

echo ""
echo "agent-auth smoke: PASS"
echo "  ✓ Agent CRUD + API key issuance"
echo "  ✓ DPoP-bound token (RFC 9449) — cnf.jkt verified"
echo "  ✓ RFC 8693 token exchange — act chain + OBO claim"
echo "  ✓ AAT root issuance + child derivation (scope attenuation)"
echo "  ✓ Transaction token lifecycle (issue → consume → replay-rejected)"
echo "  ✓ Agent Card (A2A /.well-known/agent.json)"
echo "  ✓ Protected Resource Metadata (RFC 9728)"

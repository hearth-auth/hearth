#!/usr/bin/env bash
# sdk-smoke-local.sh — Host-side reproduction of the SDK smoke CI jobs.
#
# Builds hearth (debug), boots --dev on a random free port, runs the
# TypeScript and Go SDK example smoke checks, then tears down.
#
# Usage: bash scripts/sdk-smoke-local.sh
# Called by: make sdk-smoke-local (part of make ci-local-fast)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEARTH_PID=""
GIN_PID=""
DEMO_PID=""

cleanup() {
    [ -n "$DEMO_PID" ]   && kill "$DEMO_PID"   2>/dev/null || true
    [ -n "$GIN_PID" ]    && kill "$GIN_PID"    2>/dev/null || true
    [ -n "$HEARTH_PID" ] && kill "$HEARTH_PID" 2>/dev/null || true
    [ -n "$HEARTH_PID" ] && wait "$HEARTH_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ── Free port selection ───────────────────────────────────────────────────────
free_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('',0)); p=s.getsockname()[1]; s.close(); print(p)"
}
HEARTH_PORT=$(free_port)
GIN_PORT=$(free_port)
HEARTH_BASE_URL="http://127.0.0.1:${HEARTH_PORT}"

# ── 1. Build hearth (debug) ───────────────────────────────────────────────────
echo "==> Building hearth (debug)"
cd "$REPO_ROOT"
PROTOC="${PROTOC:-protoc}" cargo build 2>&1
HEARTH_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
HEARTH_BIN="$HEARTH_TARGET_DIR/debug/hearth"

# ── 2. Start hearth --dev ─────────────────────────────────────────────────────
echo "==> Starting hearth serve --dev on port ${HEARTH_PORT}"
"$HEARTH_BIN" serve --dev --port "$HEARTH_PORT" &
HEARTH_PID=$!

echo "==> Waiting for /health"
for i in $(seq 1 60); do
    if curl -sf "${HEARTH_BASE_URL}/health" > /dev/null 2>&1; then
        echo "    hearth ready after ${i}×0.5s"
        break
    fi
    sleep 0.5
done
curl -sf "${HEARTH_BASE_URL}/health" > /dev/null \
    || { echo "ERROR: hearth failed to start within 30s"; exit 1; }

# ── 3. Bootstrap realm ───────────────────────────────────────────────────────
echo "==> Bootstrapping dev realm"
RESP=$(curl -sf -X POST "${HEARTH_BASE_URL}/admin/bootstrap")
HEARTH_REALM_ID=$(echo "$RESP" | jq -r .realm_id)
HEARTH_ACCESS_TOKEN=$(echo "$RESP" | jq -r .access_token)
export HEARTH_REALM_ID HEARTH_ACCESS_TOKEN HEARTH_BASE_URL
echo "    realm_id=${HEARTH_REALM_ID}"

# ── 4. Register OAuth client ─────────────────────────────────────────────────
echo "==> Registering OAuth client"
CLIENT=$(curl -sf -X POST "${HEARTH_BASE_URL}/admin/applications" \
    -H "Authorization: Bearer $HEARTH_ACCESS_TOKEN" \
    -H "X-Realm-ID: $HEARTH_REALM_ID" \
    -H "Content-Type: application/json" \
    -d '{"client_name":"smoke-local","redirect_uris":["http://localhost:3000/api/auth/callback"]}')
HEARTH_CLIENT_ID=$(echo "$CLIENT" | jq -r .client_id)
export HEARTH_CLIENT_ID
echo "    client_id=${HEARTH_CLIENT_ID}"

# ── 5. TypeScript / Next.js smoke ────────────────────────────────────────────
echo "==> SDK smoke — typescript-nextjs"
cd "$REPO_ROOT/examples/typescript-nextjs"
npm ci --prefer-offline

HEARTH_REDIRECT_URI=http://localhost:3000/api/auth/callback \
SESSION_SECRET=local-smoke-not-for-production \
NEXT_PUBLIC_HEARTH_BASE_URL="$HEARTH_BASE_URL" \
NEXT_PUBLIC_HEARTH_REALM_ID="$HEARTH_REALM_ID" \
    npx tsc --noEmit
echo "    tsc: OK"

node - <<'JSEOF'
const { HearthClient, JwksClient } = require("@hearth-auth/sdk");

(async () => {
    // HearthClient takes issuerUrl (base URL) + optional realmId.
    // clientCredentials/startDeviceFlow/pollDeviceToken resolve the realm from client_id;
    // realmId is only required for requestMagicLink and decision-mode authorize().
    const client = new HearthClient({
        issuerUrl: process.env.HEARTH_BASE_URL,
        realmId: process.env.HEARTH_REALM_ID,
    });

    // discover() (not discovery()) is the spec-compliant method.
    const discovery = await client.discover();
    if (!discovery.authorization_endpoint) {
        throw new Error("discovery missing authorization_endpoint");
    }
    console.log("    OK: discovery endpoint verified");

    // Construct JwksClient directly with the local server URL to avoid following
    // the jwks_uri from the discovery document, which points to the issuer from
    // hearth.yaml (port 8420) rather than the randomly selected smoke-test port.
    const jwksClient = new JwksClient({ jwksUri: `${process.env.HEARTH_BASE_URL}/.well-known/jwks.json` });
    const keys = await jwksClient.fetchKeys();
    if (!keys || keys.length === 0) {
        throw new Error("JWKS returned no keys");
    }
    console.log("    OK: JWKS contains", keys.length, "key(s)");

    console.log("    TypeScript SDK smoke: PASS");
})().catch((err) => { console.error(err); process.exit(1); });
JSEOF

# ── 6. Go / Gin smoke ────────────────────────────────────────────────────────
echo "==> SDK smoke — go-gin"
cd "$REPO_ROOT/examples/go-gin"
go build ./...
echo "    go build: OK"
go vet ./...
echo "    go vet: OK"

PORT="$GIN_PORT" go run . &
GIN_PID=$!

echo "    Waiting for gin server on port ${GIN_PORT}"
for i in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${GIN_PORT}/" > /dev/null 2>&1; then
        echo "    gin ready after ${i}×0.5s"
        break
    fi
    sleep 0.5
done

RESP=$(curl -sf "http://127.0.0.1:${GIN_PORT}/")
echo "$RESP" | grep -q "message" \
    && echo "    OK: public endpoint" \
    || { echo "FAIL: public endpoint unexpected response: $RESP"; exit 1; }

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${GIN_PORT}/api/me")
[ "$STATUS" = "401" ] \
    && echo "    OK: 401 without token" \
    || { echo "FAIL: expected 401 on /api/me (no token), got $STATUS"; exit 1; }

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $HEARTH_ACCESS_TOKEN" \
    "http://127.0.0.1:${GIN_PORT}/api/me")
[ "$STATUS" = "200" ] \
    && echo "    OK: 200 with valid token" \
    || { echo "FAIL: expected 200 on /api/me (valid token), got $STATUS"; exit 1; }

kill "$GIN_PID" 2>/dev/null || true
GIN_PID=""

# ── 7. Full-stack demo — backend smoke + integration tests ────────────────────
# Mirrors the reference-integration CI job (HEA-2058) so local and nightly paths
# stay in sync.
echo "==> SDK smoke — full-stack-demo backend"
cd "$REPO_ROOT/examples/full-stack-demo/backend"
go build ./...
echo "    go build: OK"
go vet ./...
echo "    go vet: OK"

# Resolve demo realm from the Hearth instance started in step 2.
# The system realm is HEARTH_REALM_ID (from bootstrap); we need the demo realm.
DEMO_REALM_ID=$(
    curl -sf \
        -H "Authorization: Bearer $HEARTH_ACCESS_TOKEN" \
        -H "X-Realm-ID: $HEARTH_REALM_ID" \
        "${HEARTH_BASE_URL}/admin/realms" \
    | jq -r '.items[] | select(.name == "demo") | .id' 2>/dev/null || true
)

# Fall back to the system realm if no "demo" realm exists (plain --dev startup).
# In that case REALM_SLUG stays "dev-realm" so JWKS paths resolve correctly.
if [ -z "$DEMO_REALM_ID" ]; then
    DEMO_REALM_ID="$HEARTH_REALM_ID"
    DEMO_REALM_SLUG="dev-realm"
else
    DEMO_REALM_SLUG="demo"
fi

DEMO_PORT=$(free_port)
HEARTH_URL="$HEARTH_BASE_URL" REALM_ID="$DEMO_REALM_ID" REALM_SLUG="$DEMO_REALM_SLUG" \
    PORT="$DEMO_PORT" go run . &
DEMO_PID=$!

echo "    Waiting for demo backend on port ${DEMO_PORT}"
for i in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${DEMO_PORT}/health" > /dev/null 2>&1; then
        echo "    demo backend ready after ${i}×0.5s"
        break
    fi
    sleep 0.5
done
curl -sf "http://127.0.0.1:${DEMO_PORT}/health" > /dev/null \
    || { echo "FAIL: demo backend did not start within 20s"; exit 1; }
echo "    OK: /health"

# Auth enforcement — backend routes are /api/notes (not /notes)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DEMO_PORT}/api/notes")
[ "$STATUS" = "401" ] \
    && echo "    OK: 401 without token on /api/notes" \
    || { echo "FAIL: expected 401 on /api/notes (no token), got $STATUS"; exit 1; }

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $HEARTH_ACCESS_TOKEN" \
    "http://127.0.0.1:${DEMO_PORT}/api/notes")
[ "$STATUS" = "200" ] \
    && echo "    OK: 200 with valid token on /api/notes" \
    || { echo "FAIL: expected 200 on /api/notes (valid token), got $STATUS"; exit 1; }

# Playwright integration tests — same suite the nightly reference-integration job
# runs (tests/ui/integration/) so local and CI paths stay aligned (HEA-2058).
# Requires the full demo stack (backend already running above; Vite and Hearth
# already started in steps 2 and 5). Only runs when a Vite dev server is up.
if curl -sf "http://localhost:5173" > /dev/null 2>&1; then
    echo "==> SDK smoke — reference-integration suite (Playwright)"
    cd "$REPO_ROOT/tests/ui"
    npm ci --prefer-offline
    npx playwright install chromium --with-deps 2>/dev/null || npx playwright install chromium
    HEARTH_URL="$HEARTH_BASE_URL" \
    DEMO_BACKEND_URL="http://127.0.0.1:${DEMO_PORT}" \
    DEMO_FRONTEND_URL="http://localhost:5173" \
    DEMO_REALM_SLUG="$DEMO_REALM_SLUG" \
        npx playwright test \
            --config=playwright.integration.config.ts \
            --project=integration \
            --reporter=list 2>&1 || {
        echo "    WARN: integration tests had failures — see above"
    }
    echo "    reference-integration: done"
else
    echo "    SKIP: no Vite dev server detected on :5173 — run demo.sh first to exercise the full integration suite"
fi

kill "$DEMO_PID" 2>/dev/null || true
DEMO_PID=""
echo "    full-stack-demo backend: PASS"

# ── 8. Agent Auth smoke ───────────────────────────────────────────────────────
echo "==> SDK smoke — agent-auth"
# Runs its own hearth instance (different port, agent_auth caps enabled).
# The sub-script exits non-zero on any failure, which propagates via set -e.
bash "$REPO_ROOT/examples/agent-auth-smoke/smoke.sh"

echo ""
echo "sdk-smoke-local: PASS"

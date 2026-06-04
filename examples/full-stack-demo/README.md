# Hearth Full-Stack Demo

A runnable end-to-end example showing Hearth as the identity layer for a
full-stack application: Vite/React SPA (frontend) + Go + Gin API server (backend).

## Architecture

```
┌──────────────────┐   PKCE / OIDC    ┌────────────────────┐
│  Frontend (Vite) │ ─────────────── ▶ │  Hearth  :8420     │
│  :5173           │ ◀─ access token ─ │  (identity server) │
└──────────────────┘                   └────────────────────┘
        │                                        │
        │  Bearer token                          │ JWKS
        ▼                                        ▼
┌──────────────────┐   verify JWT      ┌────────────────────┐
│  Backend  :8421  │ ◀──────────────── │  /demo/.well-known │
│  (API server)    │                   │  /jwks.json        │
└──────────────────┘                   └────────────────────┘
```

**Realm:** `demo`  
**OAuth application:** `hearth-hub` — public client, PKCE, redirect `http://localhost:5173/callback`  
**Roles:** `viewer` · `editor` · `admin` (mapped to `content.*` permissions)

## Prerequisites

| Dependency | Version | Required for |
|------------|---------|-------------|
| [Rust + Cargo](https://rustup.rs) | stable | Building Hearth from source |
| Go | 1.21+ | Building and running the backend |
| Node.js | 18+ | Running the Vite/React frontend |
| `curl` | any | `demo.sh` bootstrap + health checks |
| `jq` | any | `demo.sh` JSON parsing |

## Quick start

```bash
cd examples/full-stack-demo
./demo.sh
```

The script:
1. Builds Hearth from source (`cargo build --release`).
2. Starts Hearth on **http://localhost:8420** with the `demo` realm pre-wired.
3. Bootstraps the system and obtains an admin token.
4. Seeds three demo users with their roles.
5. Leaves Hearth running — press **Ctrl-C** to stop.

The script is **idempotent** — safe to run more than once.

## Demo users

| Email                    | Password        | Role   | Permissions                             |
|--------------------------|-----------------|--------|-----------------------------------------|
| `viewer@hearth.test`     | `HearthTest123!` | viewer | `content.read`                          |
| `editor@hearth.test`     | `HearthTest123!` | editor | `content.read`, `content.write`         |
| `admin@hearth.test`      | `HearthTest123!` | admin  | `content.read`, `content.write`, `content.admin` |

## Useful URLs (while demo.sh is running)

| URL | Purpose |
|-----|---------|
| `http://localhost:8420/health` | Server health check |
| `http://localhost:8420/ui/admin/login` | Admin UI login |
| `http://localhost:8420/dev/mail` | In-process mail catcher (--dev mode) |
| `http://localhost:8420/demo/.well-known/openid-configuration` | OIDC Discovery |
| `http://localhost:8420/demo/.well-known/jwks.json` | JWKS (for backend JWT verification) |

Admin UI credentials: `admin@hearth.test` / `HearthTest123!`

## Phase 2 — Frontend (Vite/React)

Built. Source lives in `frontend/`.

**Setup:**

```bash
cd frontend
cp .env.example .env
# Edit .env — paste the realm UUID printed by demo.sh into VITE_REALM_ID.
npm install
npm run dev     # http://localhost:5173
```

**What the app demonstrates:**

| Feature | Where |
|---------|-------|
| PKCE authorization-code flow | `src/auth/pkce.ts` + `src/auth/index.ts` |
| Access token in memory, refresh in `localStorage` | `src/auth/session.ts` |
| Silent refresh (fires before expiry) | `scheduleSilentRefresh` in session.ts |
| RP-initiated OIDC logout with `id_token_hint` | `HearthAuthClient.logout()` |
| `HearthProvider` + `createHearth` | `src/main.tsx` |
| `useHasRole` / `useHasPermission` hooks | `Dashboard.tsx`, `Notes.tsx`, `Admin.tsx` |
| `useInGroup` / `useInOrg` hooks | `Dashboard.tsx` (ClaimProbe component) |
| `<RoleGate>` component | `Notes.tsx` — hides "New Note" from viewers |
| Admin-only route | `Admin.tsx` redirects non-admins silently |

**Token storage note:** access tokens live in JS memory (cleared on page close).
Refresh tokens use `localStorage`. For production, replace with an HttpOnly-cookie
BFF so refresh tokens are never accessible to JavaScript.

## Phase 3 — Backend (Go + Gin)

`backend/` contains a Go + Gin API server that verifies Hearth JWTs via JWKS
and enforces `content.*` permissions using the `hearth-go` SDK.

```bash
cd backend
cp .env.example .env   # fill in HEARTH_URL and REALM_ID
go run .               # http://localhost:8421
```

**What the backend demonstrates:**

| Feature | Where |
|---------|-------|
| JWKS auto-discovery on startup + key-rotation re-fetch | `middleware/auth.go` |
| `RequirePermission` middleware (`content.write`) | `middleware/rbac.go` |
| `RequireRole` middleware (`admin`) | `middleware/rbac.go` |
| Notes CRUD with per-route RBAC enforcement | `handlers/notes.go` |
| Admin user list via `client.Admin(token).ListUsers()` | `handlers/admin.go` |
| Thread-safe in-memory store (`sync.RWMutex`) | `store/notes.go` |
| CORS explicit origin allowlist (not wildcard) | `main.go` `corsMiddleware` |
| Table-driven handler tests with mock JWKS | `handlers/*_test.go` |

**Routes:**

| Method | Path | Required | Description |
|--------|------|----------|-------------|
| `GET` | `/health` | — | Liveness probe |
| `GET` | `/notes` | any auth | List all notes |
| `POST` | `/notes` | `content.write` | Create a note |
| `PATCH` | `/notes/:id` | `content.write` | Update a note |
| `DELETE` | `/notes/:id` | `admin` role | Delete a note |
| `GET` | `/admin/users` | `admin` role | List users via Hearth Admin API |

## Feature walkthrough

Once all three phases are complete:

1. Open `http://localhost:5173` and click **Sign in**.
2. You are redirected to Hearth's hosted login page for the `demo` realm.
3. Log in as `viewer@hearth.test` — the app shows read-only content; **New Note** is hidden.
4. Log out, sign in as `editor@hearth.test` — the **New Note** button appears.
5. Sign in as `admin@hearth.test` — the **Users** tab and note **Delete** buttons are visible.
6. All three flows use the same PKCE authorization code grant; the backend
   verifies the JWT signature against Hearth's JWKS and checks RBAC claims
   via the `hearth-go` SDK.

### Verifying role enforcement via curl

Once you have an access token from the frontend (copy it from the browser's
Network tab on any authenticated request), you can verify the backend enforces
permissions at the API layer too:

```bash
VIEWER_TOKEN="<paste viewer access token here>"
EDITOR_TOKEN="<paste editor access token here>"

# Viewer can read notes
curl -sf -H "Authorization: Bearer $VIEWER_TOKEN" http://localhost:8421/notes | jq .

# Viewer cannot create a note (403 Forbidden — lacks content.write)
curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "Authorization: Bearer $VIEWER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","body":"Hello"}' \
  http://localhost:8421/notes
# → 403

# Editor can create a note
curl -sf -X POST \
  -H "Authorization: Bearer $EDITOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"My note","body":"Content here"}' \
  http://localhost:8421/notes | jq .

# Non-admin cannot list users (403 Forbidden — lacks admin role)
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $EDITOR_TOKEN" \
  http://localhost:8421/admin/users
# → 403

# Unauthenticated requests are rejected (401)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8421/notes
# → 401
```

### Verifying token refresh

Shorten the access token TTL in `hearth.yaml` (`token.access_token_ttl: 30s`)
and watch the browser console — `scheduleSilentRefresh` fires ~10 s before
expiry, exchanges the refresh token for a new access token, and resumes the
session without interruption.

## Production deployment notes

This demo uses a simplified token-handling approach suitable for local
development. Before deploying to production, review these differences:

| Area | This demo | Production recommendation |
|------|-----------|--------------------------|
| **Refresh token storage** | `localStorage` (readable by JS) | HttpOnly `__Secure-` cookie via a BFF (Backend-for-Frontend) |
| **Access token storage** | JS memory (lost on page close) | JS memory is correct — keep this |
| **BFF pattern** | Not used | A thin server-side component (e.g. Next.js API routes) handles the token exchange and sets `HttpOnly` cookies so refresh tokens are never accessible to JavaScript or XSS payloads |
| **TLS** | Disabled (`hearth.yaml`) | Enable TLS termination at Hearth or a reverse proxy; all cookies must be `Secure` |
| **CORS** | Explicit origin allowlist | Keep the explicit allowlist — never use `*` for authenticated APIs |
| **OIDC issuer** | `http://localhost:8420` | Use a stable HTTPS issuer URL that matches your DNS |
| **Storage** | In-memory (ephemeral) | Use the WAL-backed disk storage engine for durability |

See [Hearth's configuration reference](../../docs/specs/CONFIGURATION.md) for
the full `hearth.yaml` schema.

## Configuration

`hearth.yaml` in this directory is the demo config. Key settings:

| Key | Value | Why |
|-----|-------|-----|
| `oidc.issuer` | `http://localhost:8420` | Dev-only localhost issuer |
| `realms.demo.applications.hearth-hub.confidential` | `false` | Public client — no secret, PKCE required |
| `storage.fsync` | `false` | In-memory dev mode — no durability needed |
| `email.transport` | `mailcatcher` | Captures mail in-process; no SMTP required |

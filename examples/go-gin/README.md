# Hearth + Go / Gin Example

A minimal [Gin](https://github.com/gin-gonic/gin) HTTP server demonstrating:

- JWT verification using Hearth's JWKS endpoint
- RBAC middleware using `HasPermission` / `HasRole` from the Hearth Go SDK
- Automatic JWKS refresh on key rotation
- Protected and public route separation

## Prerequisites

- Go 1.22+
- A running Hearth instance (`make dev` from the repo root, or `docker compose up`)
- A valid Hearth access token (see step 1 below)

## Quick start

### 1. Start Hearth and get a token

```bash
# from the hearth repo root
make dev
```

Bootstrap returns a realm, admin user, and tokens:

```bash
curl -X POST http://127.0.0.1:8420/admin/bootstrap
# → { "realm_id": "…", "access_token": "…", "refresh_token": "…" }
```

Save `realm_id` and `access_token`.

### 2. Configure the app

```bash
cd examples/go-gin
cp .env.example .env
```

Edit `.env`:

```
HEARTH_BASE_URL=http://127.0.0.1:8420
HEARTH_REALM_ID=<realm_id>
PORT=8080
```

### 3. Run the server

```bash
source .env
go run .
```

### 4. Test the endpoints

```bash
export TOKEN=<access_token from bootstrap>

# Public endpoint
curl http://localhost:8080/

# Protected — returns JWT claims + live RBAC permissions
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me

# Admin-gated — requires hearth.admin permission
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin-only
```

## How authentication works

```
Client → GET /api/me
           Bearer <token>
             ↓
         requireAuth middleware
             ↓ fetch JWKS from Hearth on first request (cached)
             ↓ jwt.Parse(token, keySet) — verifies Ed25519 signature
             ↓ store parsed token in gin context
           handler
             ↓ hearth.HasPermission(token, "...") — local JWT decode
             ↓ hearth.Permissions(ctx, token)     — live server check
           response
```

The JWKS is fetched once at startup and cached in memory. If verification fails
with a known-good token, the middleware re-fetches the JWKS once (handles server
key rotation) before returning 401.

## RBAC middleware

`requirePermission(perm)` and `requireRole(role)` are Gin handler factories that
chain after `requireAuth`. They call the Hearth SDK's zero-network helpers which
decode claims from the JWT locally:

```go
protected.GET("/admin-only",
    s.requirePermission("hearth.admin"),
    s.handleAdminOnly,
)
```

For multi-permission checks, chain multiple middleware:

```go
protected.GET("/billing",
    s.requireRole("billing-admin"),
    s.requirePermission("invoices.read"),
    s.handleBilling,
)
```

## Project structure

```
├── main.go         # server, routes, middleware, handlers
├── go.mod
├── .env.example
└── README.md
```

Everything lives in `main.go` for readability. In a production app, split into
`middleware/`, `handlers/`, and a proper config package.

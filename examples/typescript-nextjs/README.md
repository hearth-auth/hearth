# Hearth + Next.js 14 Example

A minimal Next.js 14 (App Router) application demonstrating:

- Standard OIDC authorization code flow with PKCE via Hearth
- HTTP-only cookie session storage (tokens never exposed to JavaScript)
- Edge middleware route protection using Hearth's JWKS
- Client-side RBAC with `useHasPermission` / `useHasRole` hooks from `@hearth-auth/sdk`

## Prerequisites

- Node.js 18+
- A running Hearth instance (`make dev` from the repo root, or `docker compose up`)
- An OAuth client registered in your Hearth realm

## Quick start

### 1. Start Hearth in dev mode

```bash
# from the hearth repo root
make dev
```

Dev mode binds to `http://127.0.0.1:8420` with in-memory storage. The first
request to `/admin/bootstrap` creates a realm, admin user, and returns tokens.

```bash
curl -X POST http://127.0.0.1:8420/admin/bootstrap
# → { "realm_id": "…", "access_token": "…", … }
```

Save `realm_id` and `access_token` from the response.

### 2. Register an OAuth client

```bash
export ACCESS_TOKEN=<access_token from bootstrap>
export REALM_ID=<realm_id from bootstrap>

curl -X POST http://127.0.0.1:8420/admin/realms/$REALM_ID/clients \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "nextjs-example",
    "redirect_uris": ["http://localhost:3000/api/auth/callback"]
  }'
# → { "client_id": "…", … }
```

Save `client_id`.

### 3. Configure the app

```bash
cd examples/typescript-nextjs
cp .env.example .env.local
```

Edit `.env.local`:

```
HEARTH_BASE_URL=http://127.0.0.1:8420
HEARTH_REALM_ID=<realm_id>
HEARTH_CLIENT_ID=<client_id>
HEARTH_REDIRECT_URI=http://localhost:3000/api/auth/callback
SESSION_SECRET=<openssl rand -base64 32>

# Public env vars — safe to expose to the browser
NEXT_PUBLIC_HEARTH_BASE_URL=http://127.0.0.1:8420
NEXT_PUBLIC_HEARTH_REALM_ID=<realm_id>
```

### 4. Install and run

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Click **Sign in with Hearth** —
you'll be redirected to Hearth's login page. After authenticating you land on the
protected `/dashboard` page.

## How it works

```
Browser → GET /api/auth/login
            ↓ generates PKCE verifier + challenge, stores in httpOnly cookies
          redirect → Hearth /authorize?code_challenge=…
            ↓ user authenticates at Hearth's login UI
          redirect → /api/auth/callback?code=…
            ↓ server exchanges code for tokens (codeVerifier from cookie)
          redirect → /dashboard (tokens in httpOnly cookies)
```

The `middleware.ts` file runs on Next.js Edge Runtime and verifies the
`access_token` cookie on every `/dashboard/*` request by fetching Hearth's
JWKS and validating the JWT signature.

## RBAC on the client

The dashboard page uses `HearthProvider` and React hooks to show/hide UI
elements based on the JWT claims baked in at token issuance:

```tsx
const canPublish = useHasPermission("docs.publish"); // local JWT decode
const isAdmin    = useHasRole("admin");              // local JWT decode
```

For post-issuance accuracy (e.g., after an admin grants a new role), call
`hearth.client.permissions()` which hits `GET /v1/me/permissions` on the server.

## Project structure

```
├── app/
│   ├── api/auth/
│   │   ├── login/route.ts      # initiates PKCE OAuth redirect
│   │   ├── callback/route.ts   # exchanges code, sets cookies
│   │   └── logout/route.ts     # clears cookies
│   ├── dashboard/page.tsx      # protected page with RBAC hooks
│   ├── layout.tsx
│   └── page.tsx                # home / login prompt
├── lib/
│   └── hearth.ts               # HearthClient + JWKS setup
├── middleware.ts                # Edge JWT guard for /dashboard/*
└── .env.example
```

# Hearth Full-Stack Demo

A minimal full-stack application showing end-to-end Hearth integration:

- **Frontend** — React + Vite SPA authenticated via PKCE/OIDC using `@hearth/sdk`
- **Backend** — Go/Gin API server that validates Hearth JWTs and calls the admin API

One command gets you from zero to a running, authenticated app.

## Prerequisites

| Tool | Version |
|------|---------|
| Rust / Cargo | stable |
| Go | 1.21+ |
| Node.js / npm | 18+ |

## Quick start

```bash
cd examples/full-stack-demo
./demo.sh
```

Then open **http://localhost:5173** and sign in with one of the demo accounts:

| Email | Password | Role |
|-------|----------|------|
| viewer@hearth.test | HearthTest123! | viewer |
| editor@hearth.test | HearthTest123! | editor |
| admin@hearth.test  | HearthTest123! | admin |

## Architecture

```
Browser ──PKCE/OIDC──▶ Hearth :8420
   │
   │  Bearer token
   ▼
Go API :8080
   │  Admin API (Bearer forwarding)
   └──────────────────▶ Hearth :8420
```

| Service | Default port | Log |
|---------|--------------|-----|
| Hearth | 8420 | `.hearth.log` |
| Go API | 8080 | `.backend.log` |
| Vite SPA | 5173 | `.frontend.log` |

## What it demonstrates

### Frontend (`frontend/src/App.tsx`)

The SPA uses every ergonomic added in the HEA-1297 audit cycle. Zero custom
auth code — everything comes from `@hearth/sdk`:

| SDK export | Replaces |
|------------|---------|
| `createHearth()` | Dual-construct pattern |
| `HearthProvider` | Manual context wiring |
| `useSession()` | Custom session-restore loop |
| `<HearthCallback>` | Custom `Callback.tsx` |
| `<RequireAuth>` | Custom `ProtectedRoute.tsx` |
| `<Authorized>` | Custom `RoleGate.tsx` |
| `useUser()` | Manual JWT decoding |
| `useApiClient()` | Custom `api.ts` fetch wrapper |

### Backend (`backend/`)

- `middleware/auth.go` — JWKS-based JWT validation (Ed25519/EC keys)
- `handlers/admin.go` — `GET /v1/admin/users` via `client.Admin(token).ListUsers()`
- `handlers/notes.go` — `GET/POST /v1/notes`, `PATCH/DELETE /v1/notes/:id`
- Role gates: viewer → read notes; editor → create/update; admin → delete + user list

## Configuration

Copy and edit the example files — `demo.sh` writes them automatically on first run:

```bash
cp frontend/.env.example frontend/.env
cp backend/.env.example  backend/.env
```

| Variable | Default | Notes |
|----------|---------|-------|
| `VITE_HEARTH_URL` | `http://localhost:8420` | Hearth server URL |
| `VITE_REALM` | written by `demo.sh` | Realm UUID or slug |
| `VITE_CLIENT_ID` | `hearth-hub` | OAuth client ID |
| `HEARTH_URL` | `http://localhost:8420` | Hearth server URL (backend) |
| `REALM_ID` | written by `demo.sh` | Realm UUID |
| `PORT` | `8080` | Backend listen port |

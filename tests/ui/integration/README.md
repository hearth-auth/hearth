# Reference-integration Playwright suite (HEA-2056)

Machine-verified reference integration for `examples/full-stack-demo/`. These
specs drive the **real SPA** (Vite `:5173`) against a **real Hearth** (`:8420`,
`--dev`) and the **real Go backend** (`:8421`), asserting end-to-end auth
behavior on both the UI and API planes.

## Running

```bash
# From the repo root — boots the full stack (reusing the demo's demo.sh),
# runs the suite, and tears everything down.
cd tests/ui && npm run test:integration

# Or directly, with a spec filter:
bash tests/ui/integration/run-integration.sh 03-permission
```

`run-integration.sh` sets the env the suite needs (a fixed
`HEARTH_MAILCATCHER_PASSWORD`, `HEARTH_SKIP_GLOBAL_SETUP=1`) and boots the three
tiers via the demo's own `demo.sh` — no forked boot logic.

To run against a stack you already booted yourself (e.g. via `demo.sh`):

```bash
HEARTH_SKIP_GLOBAL_SETUP=1 HEARTH_MAILCATCHER_PASSWORD=<pw> \
  bash tests/ui/pw-run.sh test --project=integration
```

The demo realm id is resolved dynamically at runtime (via `POST /admin/bootstrap`
+ `GET /admin/realms`), so nothing is hard-coded to a specific boot.

## Flows

| Spec | Flow | Planes asserted |
|------|------|-----------------|
| `01-login` | Auth-code + PKCE login | SPA lands on Dashboard; token live at userinfo |
| `02-self-registration` | New user signs up → verifies email → logs in | Hosted register + mailcatcher + SPA login |
| `03-permission-enforcement` | Non-admin denied admin | **UI** (no nav, `/admin` redirect) **and API** (backend 403) |
| `04-token-revocation` | Revocation propagates | Hearth 401 + SPA logged out on reload |
| `05-jwks-rotation` | Signing-key rotation mid-session | Backend re-fetches JWKS and recovers |
| `06-refresh-at-expiry` | Silent refresh | SPA stays authenticated after losing its access token |

## Findings (per the issue's "finding, not a fixup" rule)

1. **Resource server does not enforce revocation.** `backend/middleware/auth.go`
   validates the JWT **signature only** — no introspection / revocation check —
   so a revoked-but-unexpired access token is still accepted on `/api/notes`.
   Revocation IS enforced at Hearth's control plane (`/userinfo` → 401) and at
   the SPA's refresh boundary. Flow 4 asserts the enforceable planes and encodes
   the backend gap as an expected-fail (`test.fail`) tripwire; it flips to a hard
   failure the moment the backend starts introspecting. Fixing it requires
   editing demo backend source, which this issue scopes out.

2. **Demo backend does not build headless from a clean tree.** `backend/go.mod`
   pins transitive deps below what a current Go toolchain resolves, so bare
   `go run .` (as `demo.sh` invokes) errors with *"updates to go.mod needed"*.
   The runner works around it with `GOFLAGS=-mod=mod` and restores the churn on
   exit. A durable fix (`go mod tidy` committed) belongs in the demo, not here.

3. **The SPA has no first-party signup UI.** Self-registration is delegated to
   Hearth's hosted pages (the OIDC-correct design); the demo's `Login.tsx` only
   offers "Sign in with Hearth". Flow 2 reaches signup via the hosted
   "Create account" link, which requires `registration_policy: open` on the demo
   realm (added as config plumbing in `examples/full-stack-demo/hearth.yaml`).

## Config plumbing applied (allowed by scope)

- `examples/full-stack-demo/hearth.yaml`: added `auth.registration.mode: open`
  to the `demo` realm so the self-registration flow can run. No demo **product**
  code (TS/Go source) was changed.

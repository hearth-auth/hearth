## SDK Exports (TS / Go / PHP)

Code-derived inventory of the public API surface of the TypeScript, Go, and PHP
SDKs under `sdks/`, cross-referenced against the common contract in
`docs/specs/SDK.md` (canonical mapping in §2.5, Claims §4, OAuth flows §4.5,
Admin SDK §12). "In SDK.md contract?" = the symbol maps to a spec-required
operation. Symbols marked **Extra** exist in code but are not mandated by the
spec (still valid, but a parity signal). File:line points at the definition.

Entry points read:
- TS: `sdks/typescript/src/index.ts` (re-exports), `hearth-client.ts`, `claims.ts`, `admin.ts`, `browser-auth.ts`
- Go: `sdks/go/hearth/client.go`, `flows.go`, `login.go`, `verify.go`, `claims.go`, `admin.go`, `webauthn.go`, `jwks.go`, `pkce.go`, `middleware.go`
- PHP: `sdks/php/src/HearthClient.php`, `AdminClient.php`, `Claims.php`

---

### TypeScript SDK

Primary export surface from `index.ts`. `HearthClient` is the resource-server
entry point; `AdminClient`, `Claims`, browser-auth helpers, React hooks and
middleware are separate exports.

| SDK | Exported symbol | File:line | In SDK.md contract? |
|-----|-----------------|-----------|---------------------|
| TS | `HearthClient` (class) | hearth-client.ts:? (default export) | Yes (§1 entry point) |
| TS | `HearthClient.discover()` | hearth-client.ts:135 | Yes (§1 discovery) |
| TS | `HearthClient.jwksClient()` | hearth-client.ts:180 | Yes (§2) |
| TS | `HearthClient.introspectionClient()` | hearth-client.ts:200 | Yes (§3) |
| TS | `HearthClient.authorize()` | hearth-client.ts:238 | Yes (authorize/decision) |
| TS | `HearthClient.introspect()` | hearth-client.ts:281 | Yes (§3) |
| TS | `HearthClient.verifyToken()` | hearth-client.ts:315 | Yes (§2.1 REQUIRED) |
| TS | `HearthClient.clientCredentials()` | hearth-client.ts:334 | Yes (§4.5.1) |
| TS | `HearthClient.startDeviceFlow()` | hearth-client.ts:358 | Yes (§4.5.2) |
| TS | `HearthClient.pollDeviceToken()` | hearth-client.ts:383 | Yes (§4.5.2) |
| TS | `HearthClient.requestMagicLink()` | hearth-client.ts:443 | Yes (§4.5.3) |
| TS | `HearthClient.exchangeMagicLink()` | hearth-client.ts:471 | Yes (magic-link completion) |
| TS | `Claims` (class) + decode/subject/issuer/audiences/expiry/issuedAt/jwtID/scope/scopes/hasScope/hasRole/hasPermission/inGroup/inOrg/tokenType/organizationId/orgGroups/get | claims.ts:56–177 | Yes (§4, all 18 methods present) |
| TS | `AdminClient` — Users/Realms/Clients/Roles/Groups CRUD + list + addOrgMember/listOrgMembers/removeOrgMember | admin.ts:28–248 | Yes (§12) |
| TS | `JwksClient`, `IntrospectionClient` | index.ts:20,22 | Yes (§2/§3 primitives) |
| TS | PKCE: `generateCodeVerifier`, `generateCodeChallenge`, `buildAuthorizationUrl`, `startLogin` | index.ts:5–10 (pkce.ts) | Yes (§7) |
| TS | `requirePermission` middleware | index.ts:48 (middleware.ts) | Yes (§6) |
| TS | 15 error classes (AuthorizationModeMismatch…TokenNotYetValid) | index.ts:29–45 (errors.ts) | Yes (§5) |
| TS | Browser auth: `getAccessToken/getRefreshToken/getIdToken/isAuthenticated/clearTokens/createHearthAuth` + `HearthBrowserAuth` (startLogin/handleCallback/refreshAccessToken/logout) | browser-auth.ts:16–78 | Yes (§7 browser SDK) |
| TS | React: `HearthProvider`, `useHasPermission/useHasRole/useInGroup/useInOrg` | index.ts:64–71 (react.tsx) | **Extra** (TS-only convenience) |
| TS | `createHearth` facade, `HearthApiClient` (legacy) | index.ts:55,58 | **Extra** (back-compat) |

**TS notable absences (on `HearthClient`):** no `getMyPermissions`/`UserInfo`,
no `registerClient`, no WebAuthn, no `refreshToken`/`exchangeCode`, no
`getSessionVersion` — all of which Go and PHP expose. TS AdminClient uses loose
`Record<string, unknown>` params/returns for Clients/Roles/Groups vs. the typed
DTOs in Go/PHP.

---

### Go SDK

`Client` (`client.go`) is the primary type; `AdminClient` returned via
`Client.Admin(token)`. Package-level constructors and helpers.

| SDK | Exported symbol | File:line | In SDK.md contract? |
|-----|-----------------|-----------|---------------------|
| Go | `NewClient` / `Bootstrap` / options `WithClientCredentials`/`WithJWKSTTL`/`WithSessionVersions` | client.go:92,128,57,65,80 | Yes (§1) |
| Go | `Client.BeginLogin` / `Client.CompleteLogin` | login.go:22,68 | Yes (§7 PKCE login) |
| Go | `Client.VerifyToken(ctx, token, aud...)` | verify.go:90 | Yes (§2.1 REQUIRED) |
| Go | `Client.ClientCredentials` | flows.go:19 | Yes (§4.5.1) |
| Go | `Client.StartDeviceFlow` | flows.go:47 | Yes (§4.5.2) |
| Go | `Client.PollDeviceToken` ⚠ (no interval arg) | flows.go:78 | Yes (§4.5.2, signature drift per §2.5) |
| Go | `Client.RequestMagicLink` / `Client.ExchangeMagicLink` | flows.go:139,176 | Yes (§4.5.3) |
| Go | `Client.Authorize` / `ExchangeCode` / `RefreshTokens` / `RegisterClient` | client.go:150,162,171,141 | Yes (OAuth core) |
| Go | `Client.Introspect` | client.go:300 | Yes (§3) |
| Go | `Client.HasPermission/HasRole/InGroup/InOrg` (token convenience) | client.go:234–255 | **Extra** (mirrors Claims on Client) |
| Go | `Client.Permissions` / `UserInfo` / `CheckPermission` | client.go:263,279,330 | Yes (permissions/userinfo endpoints) |
| Go | `Client.StartWebAuthnRegistration/Finish…/StartWebAuthnAuthentication/Finish…` | webauthn.go:16,31,48,67 | Yes (WebAuthn) |
| Go | `Client.Stop` / `SessionVersionCacheAge` | client.go:107,119 | **Extra** (lifecycle/cache) |
| Go | `Client.Admin(token) *AdminClient` | client.go:352 | Yes (§12 entry) |
| Go | `AdminClient` — Users/Realms/Clients/Roles/Groups CRUD+List, OrgMembers Add/Get/Update/Remove/List | admin.go:20–270 | Yes (§12; typed DTOs, incl. GetOrgMember which TS lacks) |
| Go | `Claims` + Subject/Scope/Issuer/Audiences/Expiry/IssuedAt/JwtID/Scopes/HasScope/HasRole/HasPermission/InGroup/InOrg/TokenType/OrganizationId/OrgGroups/Get, `ParseClaims` | claims.go:73–176 | Yes (§4) |
| Go | `GeneratePKCE` / `NewJwksCache`+`GetKey` | pkce.go:30, jwks.go:53,75 | Yes (§7/§2) |
| Go | `RequirePermission` middleware | middleware.go:81 | Yes (§6) |
| Go | 12 typed error structs (ConfigurationError…RequiredActionError) | errors.go:20–189 | Yes (§5) |

---

### PHP SDK

`HearthClient` primary; `AdminClient` separate; `Claims` value object.
Laravel `HearthServiceProvider`/`HearthMiddleware` and PSR-15 middleware also shipped.

| SDK | Exported symbol | File:line | In SDK.md contract? |
|-----|-----------------|-----------|---------------------|
| PHP | `HearthClient::beginLogin` / `completeLogin` / `buildAuthorizeUrl` | HearthClient.php:122,145,170 | Yes (§7) |
| PHP | `HearthClient::exchangeCode` / `refreshToken` | HearthClient.php:225,260 | Yes (OAuth core) |
| PHP | `HearthClient::clientCredentials` | HearthClient.php:294 | Yes (§4.5.1) |
| PHP | `HearthClient::startDeviceFlow` / `pollDeviceToken` | HearthClient.php:334,370 | Yes (§4.5.2) |
| PHP | `HearthClient::requestMagicLink` / `exchangeMagicLink` | HearthClient.php:434,478 | Yes (§4.5.3) |
| PHP | `HearthClient::registerClient` | HearthClient.php:512 | Yes (DCR) |
| PHP | `HearthClient::verifyToken` | HearthClient.php:540 | Yes (§2.1 REQUIRED) |
| PHP | `HearthClient::getMyPermissions` / `checkDecision` / `getUserInfo` | HearthClient.php:566,595,611 | Yes (permissions/userinfo) |
| PHP | `HearthClient::startWebAuthnRegistration/finish…/startWebAuthnAuthentication/finish…` | HearthClient.php:646,663,679,696 | Yes (WebAuthn) |
| PHP | `HearthClient::getSessionVersion` | HearthClient.php:720 | Yes (session-version §2.5) |
| PHP | `HearthClient::bootstrap` | HearthClient.php:745 | **Extra** (dev bootstrap) |
| PHP | `HearthClient::getJwksClient/getTokenVerifier/getIntrospectionClient/discoverEndpoint` | HearthClient.php:759–823 | Yes (§2/§3 primitives) |
| PHP | `AdminClient` — Users/Realms/Clients/Roles/Groups CRUD+List, OrgMembers Add/Get/Update/Remove/List | AdminClient.php:74–383 | Yes (§12; typed via PageResponse) |
| PHP | `Claims` + subject/issuer/audiences/expiry/issuedAt/jwtID/scope/scopes/hasScope/hasRole/hasPermission/inGroup/inOrg/tokenType/organizationId/orgGroups/get + roles()/permissions()/groups() | Claims.php:27–235 | Yes (§4; roles()/permissions()/groups() are **Extra** accessors) |
| PHP | `TokenVerifier`, `JwksClient`, `IntrospectionClient` | src/TokenVerifier.php etc. | Yes (§2/§3) |
| PHP | Laravel `HearthServiceProvider` + PSR-15/Laravel `HearthMiddleware` | src/Laravel/*, src/Middleware/* | Yes (§6, framework glue = Extra) |

---

### Parity analysis

**Method counts (primary client + admin + claims):**

| SDK | Primary client methods | AdminClient methods | Claims methods |
|-----|------------------------|---------------------|----------------|
| TS  | 11 (+ browser-auth 6 fns/4-method facade, React hooks) | 28 | 18 (+`decode`, `assertValid`) |
| Go  | 24 (incl. WebAuthn 4, HasX 4, Permissions/UserInfo/CheckPermission, Stop/cache) | 26 | 18 (+`ParseClaims`) |
| PHP | 25 (incl. WebAuthn 4, getMyPermissions/checkDecision/getUserInfo, getSessionVersion) | 29 | 18 (+`roles/permissions/groups`) |

**Gaps vs. the three-way parity:**
1. **WebAuthn** — present in Go (4 methods) and PHP (4 methods); **absent from
   the TS `HearthClient`** (no WebAuthn surface anywhere in the TS SDK).
2. **`registerClient` (Dynamic Client Registration)** — Go (`RegisterClient`)
   and PHP (`registerClient`) expose it; **TS `HearthClient` does not** (only a
   `RegisterClientParams` type is exported, no method).
3. **Permissions / UserInfo endpoints** — Go (`Permissions`, `UserInfo`,
   `CheckPermission`) and PHP (`getMyPermissions`, `getUserInfo`,
   `checkDecision`) expose live authz/userinfo calls; **TS `HearthClient`
   exposes neither** (only the `MePermissionsResponse`/`UserInfoResponse` types).
4. **`refreshToken` / `exchangeCode`** — first-class on Go
   (`RefreshTokens`/`ExchangeCode`) and PHP (`refreshToken`/`exchangeCode`);
   on TS these live only in the legacy `HearthApiClient`/browser-auth facade,
   not on the primary `HearthClient`.
5. **`getSessionVersion`** — explicit method in PHP (`getSessionVersion`); Go
   exposes cache age (`SessionVersionCacheAge`) + option; TS ships
   `SessionVersionCache` as a standalone export. Three different shapes for the
   same §2.5 concern.
6. **AdminClient `GetOrgMember`** — present in Go (`GetOrgMember`) and PHP
   (`getOrgMember`); **missing in TS AdminClient** (has add/list/remove only).
7. **AdminClient typing** — TS uses untyped `Record<string, unknown>` for
   Clients/Roles/Groups params & returns; Go and PHP use typed DTOs. Weaker
   contract enforcement in TS.

**Gaps / drift vs. `SDK.md`:**
- **Go `PollDeviceToken` signature drift** — spec §2.5 flags it ⚠: takes only
  `deviceCode` (no `interval`), unlike the canonical `pollDeviceToken(deviceCode,
  interval)`. TS and PHP both include the interval argument.
- **Spec §2.5 ⚠ markers** in the mapping table already document Kotlin
  `deviceAuthorization`/no-`requestMagicLink` and Rust `initiate_magic_link`
  deviations — out of scope for TS/Go/PHP here, but confirm the spec anticipates
  per-SDK naming drift.
- **All three SDKs satisfy the mandatory core**: `verifyToken` (JWKS Ed25519),
  `introspect`, `clientCredentials`, `startDeviceFlow`, `pollDeviceToken`,
  `requestMagicLink`, full §4 Claims (18 methods each), the §5 error taxonomy,
  §6 middleware, and the §12 AdminClient minimum operations. No spec-required
  operation is entirely missing from any of the three.

**Net:** TS is the weakest for parity — it omits WebAuthn, DCR, permissions/
userinfo, and `GetOrgMember`, and under-types its AdminClient. Go and PHP are
near-identical in coverage; Go's only notable divergence is the
`PollDeviceToken` interval-less signature already flagged by the spec.

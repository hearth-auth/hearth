# Hearth Go SDK

Go client for the [Hearth](https://github.com/hearth-auth/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).

## Installation

```bash
go get github.com/hearth-auth/hearth/sdks/go@v1.0.0
```

| SDK version | Minimum Hearth server |
|-------------|----------------------|
| 1.0.x       | 1.0.0                |

## Quick start

```go
import "github.com/hearth-auth/hearth/sdks/go/hearth"

client := hearth.NewClient("https://hearth.example.com", "<your-realm-id>")
```

`Client` wraps the Hearth HTTP API for auth code flows, token management, JWKS retrieval, and live RBAC claim resolution. All methods are safe to call concurrently.

---

## Auth code flow (with PKCE)

PKCE is the secure default for every OAuth authorization code flow — required for public clients, recommended for confidential clients.

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/hearth-auth/hearth/sdks/go/hearth"
)

func pkce() (verifier, challenge string) {
    raw := make([]byte, 32)
    rand.Read(raw)
    verifier = hex.EncodeToString(raw) // 64 unreserved chars, valid per RFC 7636
    sum := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(sum[:])
    return
}

func main() {
    ctx := context.Background()
    client := hearth.NewClient("https://hearth.example.com", "<your-realm-id>")

    // 1. Generate PKCE verifier and challenge
    codeVerifier, codeChallenge := pkce()

    // 2. Start the authorization request
    authResp, err := client.Authorize(ctx, hearth.AuthorizeRequest{
        ClientID:    "<client-id>",
        RedirectURI: "https://app.example.com/callback",
        Scope:       "openid profile email",
        State:       hex.EncodeToString(func() []byte { b := make([]byte, 16); rand.Read(b); return b }()),
        UserID:      "<authenticated-user-uuid>", // resolved user on your backend
    })
    if err != nil {
        panic(err)
    }

    // 3. Exchange the code for tokens
    tokens, err := client.ExchangeCode(ctx, hearth.TokenRequest{
        ClientID:    "<client-id>",
        Code:        authResp.Code,
        RedirectURI: "https://app.example.com/callback",
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("access_token:", tokens.AccessToken)
    fmt.Println("expires_in:  ", tokens.ExpiresIn)

    // 4. Refresh before expiry
    refreshed, err := client.RefreshTokens(ctx, "<client-id>", tokens.RefreshToken)
    _ = refreshed
    _ = codeVerifier
    _ = codeChallenge
}
```

> **PKCE:** Pass `codeVerifier` / `codeChallenge` through your existing auth-request mechanism. `AuthorizeRequest` does not yet carry PKCE fields directly — send them as additional form parameters or open an issue if you need first-class PKCE support in the SDK.

---

## RBAC capabilities

All synchronous helpers decode the JWT **locally** — no network call, no lock, no cache. They return `false` for an empty or malformed token.

### `HasPermission(token, permission string) bool`

Returns `true` iff the JWT `permissions` claim contains `permission`.

```go
if client.HasPermission(accessToken, "docs.versions.read") {
    renderVersionHistory()
}
```

### `HasRole(token, role string) bool`

Returns `true` iff the JWT `roles` claim contains `role`. Useful for UI personalization and coarse-grained access.

```go
if client.HasRole(accessToken, "billing-admin") {
    renderBillingPanel()
}
```

### `InGroup(token, groupSlug string) bool`

Returns `true` iff the JWT `groups` claim contains the group slug.

```go
if client.InGroup(accessToken, "engineering") {
    renderInternalToolingLink()
}
```

### `InOrg(token, orgID string) bool`

Returns `true` iff the JWT `oid` claim equals the given org ID.

```go
if client.InOrg(accessToken, "org_acme") {
    renderAcmeContent()
}
```

### `Permissions(ctx, token) (*MePermissionsResponse, error)`

Calls `GET /v1/me/permissions` and returns the **freshly-resolved** RBAC claim set from the server. Unlike the synchronous helpers above, this reflects any role/group assignments made since the JWT was issued.

```go
perms, err := client.Permissions(ctx, accessToken)
if err != nil {
    return fmt.Errorf("permissions: %w", err)
}
// perms.Roles, perms.Groups, perms.Permissions
```

Use `Permissions` when you need post-issuance accuracy (e.g., after an admin operation). For every other check, prefer the synchronous local helpers — they're faster and don't touch the network.

---

## UserInfo endpoint

Returns OIDC claims filtered by the granted scopes. `Sub` is always present; `Name` requires `profile` scope; `Email` and `EmailVerified` require `email` scope.

```go
info, err := client.UserInfo(ctx, accessToken)
if err != nil {
    return fmt.Errorf("userinfo: %w", err)
}
// info.Sub            — stable user identifier
// info.Name           — display name (if profile scope granted)
// info.Email          — email address (if email scope granted)
// info.EmailVerified  — bool (if email scope granted)
```

---

## Admin API

`AdminClient` wraps the `/admin/*` endpoints. Obtain one from any `Client` instance using a bearer token that carries the `hearth.admin` permission.

```go
admin := client.Admin(accessToken)
```

### Users

```go
// Create a user
user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
    Email:       "alice@example.com",
    DisplayName: "Alice",
})

// Get a user by ID
user, err := admin.GetUser(ctx, "<user-id>")

// Update a user
name := "Alice Smith"
updated, err := admin.UpdateUser(ctx, "<user-id>", hearth.UpdateUserRequest{
    DisplayName: &name,
})

// List users (paginated, up to limit records per page)
page, err := admin.ListUsers(ctx, 50)
// page.Items: []User, page.NextCursor: *string (nil if last page)

// Delete a user
err = admin.DeleteUser(ctx, "<user-id>")
```

### Realms

```go
// Realms are provisioned via hearth.yaml, not the admin API — there is no
// CreateRealm client method (the server returns 405). Only read paths exist.

// Get a realm by ID
realm, err := admin.GetRealm(ctx, "<realm-id>")

// Update a realm
suspended := "suspended"
updated, err := admin.UpdateRealm(ctx, "<realm-id>", hearth.UpdateRealmRequest{
    Status: &suspended,
})

// Delete a realm (cascades users, sessions, clients, assignments)
err = admin.DeleteRealm(ctx, "<realm-id>")
```

---

## Error handling

Non-2xx responses return `*APIError`.

```go
import (
    "errors"
    "fmt"

    "github.com/hearth-auth/hearth/sdks/go/hearth"
)

tokens, err := client.ExchangeCode(ctx, req)
if err != nil {
    var apiErr *hearth.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("HTTP %d: %s\n", apiErr.StatusCode, apiErr.Message)
    } else {
        return fmt.Errorf("exchange code: %w", err)
    }
}
```

`APIError.StatusCode` is the HTTP status code. `APIError.Message` is the raw response body.

---

## Dev bootstrap (development only)

The bootstrap endpoint creates a realm, admin user, session, assigns the `realm.admin` role, and returns tokens. Available only when Hearth is running with `--dev`. In production, it returns 404.

```go
resp, err := hearth.Bootstrap(ctx, "http://localhost:8420")
if err != nil {
    panic(err)
}

// resp.RealmID      — UUID of the newly created realm
// resp.UserID       — UUID of the admin user
// resp.AccessToken  — short-lived JWT with hearth.admin permission
// resp.RefreshToken — opaque refresh token

client := hearth.NewClient("http://localhost:8420", resp.RealmID)
admin  := client.Admin(resp.AccessToken)
```

---

## Type reference

```go
// Client — created by NewClient(baseURL, realmID string)
// All methods are goroutine-safe.

// AuthorizeRequest — argument to Client.Authorize
type AuthorizeRequest struct {
    ClientID     string `json:"client_id"`
    RedirectURI  string `json:"redirect_uri"`
    Scope        string `json:"scope"`
    State        string `json:"state"`
    ResponseType string `json:"response_type"` // default: "code"
    UserID       string `json:"user_id"`
}

// AuthorizeResponse — returned by Client.Authorize
type AuthorizeResponse struct {
    Code  string `json:"code"`
    State string `json:"state"`
}

// TokenRequest — argument to Client.ExchangeCode and Client.RefreshTokens
type TokenRequest struct {
    ClientID     string `json:"client_id"`
    GrantType    string `json:"grant_type,omitempty"`    // default: "authorization_code"
    Code         string `json:"code,omitempty"`
    RedirectURI  string `json:"redirect_uri,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse — returned by token endpoints
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    IDToken      string `json:"id_token,omitempty"`
    TokenType    string `json:"token_type"`    // "Bearer"
    ExpiresIn    int    `json:"expires_in,omitempty"` // seconds
    RefreshToken string `json:"refresh_token"`
}

// UserInfoResponse — returned by Client.UserInfo
type UserInfoResponse struct {
    Sub           string `json:"sub"`
    Name          string `json:"name,omitempty"`
    Email         string `json:"email,omitempty"`
    EmailVerified bool   `json:"email_verified,omitempty"`
}

// MePermissionsResponse — returned by Client.Permissions
type MePermissionsResponse struct {
    Roles       []string `json:"roles"`
    Groups      []string `json:"groups"`
    Permissions []string `json:"permissions"`
    Scope       string   `json:"scope"`
}

// CreateUserRequest — argument to AdminClient.CreateUser
type CreateUserRequest struct {
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
}

// UpdateUserRequest — argument to AdminClient.UpdateUser (nil fields = no change)
type UpdateUserRequest struct {
    Email       *string `json:"email,omitempty"`
    DisplayName *string `json:"display_name,omitempty"`
    Status      *string `json:"status,omitempty"`
}

// User — user record from the API
type User struct {
    ID          string `json:"id"`
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
    Status      string `json:"status"`
    CreatedAt   int64  `json:"created_at,omitempty"` // Unix epoch seconds
    UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// UpdateRealmRequest — argument to AdminClient.UpdateRealm (nil fields = no change)
type UpdateRealmRequest struct {
    Name   *string `json:"name,omitempty"`
    Status *string `json:"status,omitempty"`
}

// Realm — realm record from the API
type Realm struct {
    ID        string `json:"id"`
    Name      string `json:"name"`
    Status    string `json:"status"`
    Config    any    `json:"config"`
    CreatedAt int64  `json:"created_at,omitempty"`
    UpdatedAt int64  `json:"updated_at,omitempty"`
}

// PageResponse[T] — paginated list response
type PageResponse[T any] struct {
    Items      []T     `json:"items"`
    NextCursor *string `json:"next_cursor"` // nil if last page
}

// RegisterClientRequest — argument to Client.RegisterClient
type RegisterClientRequest struct {
    ClientName   string   `json:"client_name"`
    RedirectURIs []string `json:"redirect_uris"`
}

// OAuthClient — returned by RegisterClient
type OAuthClient struct {
    ClientID     string   `json:"client_id"`
    ClientName   string   `json:"client_name"`
    RedirectURIs []string `json:"redirect_uris"`
    GrantTypes   []string `json:"grant_types"`
}

// APIError — returned for non-2xx responses
type APIError struct {
    StatusCode int
    Message    string // raw response body
}
```

## Authorization modes (HEA-921 / HEA-922)

Hearth supports three strategies for checking permissions on resource servers.
Each `OAuthClient` is configured with an `access_token_authorization` mode;
the SDK middleware must be configured with the **same** mode — mismatches are
always rejected, never silently downgraded.

### `ModeEmbedded` (default)

Permissions are baked into the JWT at issuance. The middleware decodes
claims locally with zero network overhead.

```go
mw := hearth.RequirePermission(client, "docs.edit", hearth.MiddlewareConfig{
    ExpectedMode: hearth.ModeEmbedded,
})
http.Handle("/docs", mw(docsHandler))
```

### `ModeDecision`

Each request calls `POST /oauth/authorize` for a live per-request decision.
Fail-closed: network errors deny the request.

```go
mw := hearth.RequirePermission(client, "docs.edit", hearth.MiddlewareConfig{
    ExpectedMode: hearth.ModeDecision,
})
http.Handle("/docs", mw(docsHandler))
```

You can also call the decision endpoint directly:

```go
resp, err := client.CheckPermission(ctx, accessToken, hearth.CheckPermissionRequest{
    Permission:     "docs.edit",
    OrganizationID: "org_123", // optional: scope to an org
})
if err == nil && resp.Allowed {
    // authorized
}
```

### `ModeIntrospection`

Each request calls `POST /introspect` (RFC 7662). The server re-resolves live
RBAC and echoes the configured mode back in the response. If the echoed mode
does not match `ExpectedMode` the middleware returns `403` without falling back
to a local check.

```go
mw := hearth.RequirePermission(client, "docs.edit", hearth.MiddlewareConfig{
    ExpectedMode: hearth.ModeIntrospection,
    ClientID:     "my-resource-server",
    ClientSecret: os.Getenv("RS_SECRET"),
})
http.Handle("/docs", mw(docsHandler))
```

Direct introspection call:

```go
resp, err := client.Introspect(ctx, hearth.IntrospectRequest{
    Token:        accessToken,
    ClientID:     "my-resource-server",
    ClientSecret: os.Getenv("RS_SECRET"),
})
if err == nil && resp.Active {
    fmt.Println("live permissions:", resp.Permissions)
}
```

### Custom token extraction and denial

```go
mw := hearth.RequirePermission(client, "api.write", hearth.MiddlewareConfig{
    ExpectedMode: hearth.ModeEmbedded,
    TokenExtractor: func(r *http.Request) string {
        return r.Header.Get("X-Api-Token") // custom header
    },
    OnDenied: func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusUnauthorized)
        _, _ = w.Write([]byte(`{"error":"unauthorized"}`))
    },
})
```

## Troubleshooting

**`DiscoveryError`** — verify `IssuerURL` is reachable and returns a valid `/.well-known/openid-configuration`.

**`JWKSFetchError`** — check network connectivity to the JWKS endpoint. The SDK retries once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — JWT signature does not match any key in the JWKS. If the server recently rotated keys the SDK will re-fetch once automatically; persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured audience. Verify `ClientID` matches the audience your authorization server issues.

See [docs/specs/SDK.md](../../docs/specs/SDK.md) Section 5 for the full error taxonomy.

---

## Agent Authentication (M5)

Enable in `hearth.yaml`:
```yaml
agent_auth:
  capabilities:
    identity: true   # /v1/agents, /.well-known/agent.json
    advanced: true   # /v1/aats, /v1/transaction-tokens, /v1/spiffe-mappings
```

### Agent CRUD + API keys

```go
// Create an agent
agentBody := map[string]interface{}{
    "realm_id":     realmID,
    "display_name": "my-agent",
    "capabilities": []string{"urn:hearth:capability:docs:read"},
}
// POST /v1/agents with admin bearer token
agent, err := hearthClient.Post(ctx, "/v1/agents", agentBody)

// Issue an API key
key, err := hearthClient.Post(ctx, fmt.Sprintf("/v1/agents/%s/credentials/keys", agentID),
    map[string]string{"description": "prod key"})
// key["api_key"] is the long-lived bearer credential
```

### DPoP-bound tokens (RFC 9449)

Go's `crypto/ecdsa` and `crypto/elliptic` packages support EC P-256:

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "math/big"
)

priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
pub := priv.Public().(*ecdsa.PublicKey)

x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32)))
y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32)))

// JWK thumbprint (RFC 7638): SHA-256 of canonical JSON with lex-sorted required members
canonical, _ := json.Marshal(map[string]string{"crv": "P-256", "kty": "EC", "x": x, "y": y})
sum := sha256.Sum256(canonical)
thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])

// Build and sign DPoP proof JWT — r||s raw signature (not DER)
func makeDPopProof(priv *ecdsa.PrivateKey, htm, htu, nonce string) string { ... }

// Use as:  req.Header.Set("DPoP", makeDPopProof(...))
// Issued AT will contain: cnf: { jkt: "<thumbprint>" }
```

### RFC 8693 Token Exchange

```go
vals := url.Values{
    "grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
    "subject_token":         {subjectToken},
    "subject_token_type":    {"urn:ietf:params:oauth:token-type:access_token"},
    "requested_token_type":  {"urn:ietf:params:oauth:token-type:access_token"},
    "scope":                 {"openid"},
}
resp, _ := http.PostForm(baseURL+"/token", vals)
// Exchanged token contains: act.sub = actorClientID (RFC 8693 §4.1)
```

### AATs and Transaction Tokens (Phase D)

```go
// Issue root AAT
rootAat, _ := hearthClient.Post(ctx, "/v1/aats", map[string]interface{}{
    "realm_id": realmID,
    "agent_id": agentID,
    "tools":    []map[string]interface{}{{"tool_name": "read_docs", "constraints": nil}},
    "expires_in_secs": 3600,
})

// Derive child AAT (narrowed scope)
childAat, _ := hearthClient.Post(ctx, "/v1/aats/derive", map[string]interface{}{
    "realm_id":      realmID,
    "parent_token":  rootAat["token"],
    "tools":         []map[string]interface{}{{"tool_name": "read_docs", "constraints": nil}},
    "expires_in_secs": 300,
})

// Issue transaction token (agent-a → agent-b, single-use, 60s TTL)
txn, _ := hearthClient.Post(ctx, "/v1/transaction-tokens", map[string]interface{}{
    "realm_id":             realmID,
    "requesting_agent_id":  agentAID,
    "target_agent_id":      agentBID,
    "txn_id":               "txn-" + uuid.New().String(),
})

// Consume (second call returns 409 — replay prevention)
_, _ = hearthClient.Post(ctx, "/v1/transaction-tokens/consume", map[string]interface{}{
    "realm_id": realmID,
    "token":    txn["token"],
})
```

### Draft-standard tracking

See the TypeScript SDK README for the full draft tracking table. Draft owner: **@therecluse26** (CTO). Open a follow-up on [HEA-1409](/HEA/issues/HEA-1409) when any draft advances.

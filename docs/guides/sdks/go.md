---
title: Go SDK quickstart
sidebar_label: Go
description: Add Hearth authentication and RBAC to a Go service in under 5 minutes.
---

# Go SDK quickstart

Get your first protected HTTP endpoint in under 5 minutes using the Hearth Go SDK.

## Install

```bash
go get github.com/hearth-auth/hearth/sdks/go
```

## Start Hearth locally

```bash
# from the hearth repo root
make dev
# → binds http://127.0.0.1:8420

curl -X POST http://127.0.0.1:8420/admin/bootstrap
# → { "realm_id": "…", "access_token": "…", "refresh_token": "…" }
```

## Initialize the client

```go
import "github.com/hearth-auth/hearth/sdks/go/hearth"

client := hearth.NewClient("http://127.0.0.1:8420", "<realm_id>")
```

`Client` is goroutine-safe and is designed to be created once and reused across
requests.

## Auth code flow with PKCE

Hearth implements standard OIDC authorization code flow with mandatory PKCE.
Generate a verifier and challenge, then exchange the authorization code for
tokens:

```go
package main

import (
    "context"
    "fmt"

    "github.com/hearth-auth/hearth/sdks/go/hearth"
)

func main() {
    ctx := context.Background()
    client := hearth.NewClient("http://127.0.0.1:8420", "<realm_id>")

    // 1. Generate PKCE pair — verifier + S256 challenge, no manual crypto needed
    pkce, err := hearth.GeneratePKCE()
    if err != nil {
        panic(err)
    }

    // 2. Start authorization — pass the PKCE challenge
    authResp, err := client.Authorize(ctx, hearth.AuthorizeRequest{
        ClientID:            "<client_id>",
        RedirectURI:         "http://localhost:8080/callback",
        Scope:               "openid profile email",
        State:               "random-csrf-token",
        UserID:              "<user_uuid>", // authenticated user on your backend
        CodeChallenge:       pkce.Challenge,
        CodeChallengeMethod: pkce.Method,
    })
    if err != nil {
        panic(err)
    }

    // 3. Exchange the code for tokens — pass the matching PKCE verifier
    tokens, err := client.ExchangeCode(ctx, hearth.TokenRequest{
        ClientID:     "<client_id>",
        Code:         authResp.Code,
        RedirectURI:  "http://localhost:8080/callback",
        CodeVerifier: pkce.Verifier,
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("access_token:", tokens.AccessToken)
    fmt.Println("expires_in:  ", tokens.ExpiresIn)

    // 4. Refresh before expiry
    refreshed, err := client.RefreshTokens(ctx, "<client_id>", tokens.RefreshToken)
    _ = refreshed
}
```

## Verify tokens

`VerifyToken` performs full Ed25519/EdDSA local signature verification with JWKS
caching and key-rotation recovery:

```go
package main

import (
    "context"
    "errors"
    "fmt"

    "github.com/hearth-auth/hearth/sdks/go/hearth"
)

func main() {
    ctx := context.Background()
    client := hearth.NewClient("http://127.0.0.1:8420", "<realm_id>",
        hearth.WithClientCredentials("<client_id>", ""),
    )

    claims, err := client.VerifyToken(ctx, accessToken)
    if err != nil {
        var tokenErr *hearth.TokenError
        if errors.As(err, &tokenErr) {
            fmt.Println("token rejected:", tokenErr.Code) // "expired", "invalid", "issuer_mismatch", etc.
        }
        return
    }

    fmt.Println("user:", claims.Subject)
    fmt.Println("roles:", claims.Roles)
    fmt.Println("permissions:", claims.Permissions)
}
```

`VerifyToken` validates signature, `exp`, `iss`, `aud` (when `client_id` is
set), and `iat` in that order. Keys are cached; a `kid` miss triggers one
re-fetch before failing (transparent key rotation). It never falls back to
introspection.

Pass additional audience values as variadic arguments:

```go
claims, err := client.VerifyToken(ctx, token, "other-service")
```

## Machine-to-machine (client credentials)

For daemon-to-daemon calls where the service authenticates as its own principal:

```go
client := hearth.NewClient("http://127.0.0.1:8420", "<realm_id>",
    hearth.WithClientCredentials("<service-client-id>", "<service-client-secret>"),
)

tokens, err := client.ClientCredentials(ctx)
if err != nil {
    panic(err)
}
fmt.Println("access_token:", tokens.AccessToken)
// tokens.ExpiresIn — seconds until expiry
```

Pass optional scopes as variadic strings:

```go
tokens, err := client.ClientCredentials(ctx, "read:users", "write:reports")
```

## Device authorization flow

For CLI tools or headless servers that need interactive user approval:

```go
resp, err := client.StartDeviceFlow(ctx)
if err != nil {
    panic(err)
}
fmt.Printf("Visit %s\nEnter code: %s\n", resp.VerificationURI, resp.UserCode)

// Poll until the user approves. PollDeviceToken manages the interval internally.
for {
    tokens, err := client.PollDeviceToken(ctx, resp.DeviceCode)
    if err != nil {
        var tokenErr *hearth.TokenError
        if errors.As(err, &tokenErr) && tokenErr.Code == "expired_token" {
            fmt.Println("device code expired")
            return
        }
        panic(err)
    }
    if tokens != nil {
        // Approved
        fmt.Println("access_token:", tokens.AccessToken)
        break
    }
    // nil means authorization_pending or slow_down — sleep and retry
    time.Sleep(time.Duration(resp.Interval) * time.Second)
}
```

`PollDeviceToken` handles `authorization_pending` and `slow_down` by returning
`nil` (the caller is responsible for the sleep loop). It raises a `TokenError`
with `Code == "expired_token"` when the device code expires.

## Magic-link (passwordless) initiation

```go
err := client.RequestMagicLink(ctx, "user@example.com")
// err is nil whether or not the email is registered (enumeration resistance)
```

HTTP 429 is surfaced as `*hearth.APIError` with `StatusCode == 429`.

## RBAC checks

### Synchronous (zero-network) helpers

These decode the JWT **locally** — no network call, no lock. They return
`false` for an empty or malformed token.

```go
// Returns true if the JWT permissions claim contains this permission.
if client.HasPermission(accessToken, "invoices.write") {
    renderInvoiceForm()
}

// Returns true if the JWT roles claim contains this role.
if client.HasRole(accessToken, "billing-admin") {
    renderBillingPanel()
}

// Returns true if the JWT groups claim contains this slug.
if client.InGroup(accessToken, "engineering") {
    renderInternalTooling()
}

// Returns true if the JWT oid claim equals this org ID.
if client.InOrg(accessToken, "org_acme") {
    renderAcmeContent()
}
```

### Live permission check (post-issuance)

Call `Permissions` when you need claims that reflect role/group changes made
after the JWT was issued (e.g., after an admin operation):

```go
perms, err := client.Permissions(ctx, accessToken)
if err != nil {
    return fmt.Errorf("permissions: %w", err)
}
// perms.Roles       []string
// perms.Groups      []string
// perms.Permissions []string
```

## HTTP middleware pattern

Use the synchronous helpers to build composable Gin (or `net/http`) middleware:

```go
func requirePermission(client *hearth.Client, perm string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := bearerToken(c)
        if !client.HasPermission(token, perm) {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "error":              "forbidden",
                "required_permission": perm,
            })
            return
        }
        c.Next()
    }
}

// Usage
r.GET("/admin", requirePermission(client, "hearth.admin"), handleAdmin)
```

## Error handling

Non-2xx responses return `*hearth.APIError`:

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
        return fmt.Errorf("exchange: %w", err)
    }
}
```

## UserInfo and Admin API

```go
// OIDC UserInfo — scope-filtered claims
info, err := client.UserInfo(ctx, accessToken)
// info.Sub, info.Name, info.Email, info.EmailVerified

// Admin operations — requires hearth.admin permission
admin := client.Admin(accessToken)

user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
    Email:       "alice@example.com",
    DisplayName: "Alice",
})

page, err := admin.ListUsers(ctx, 50)
// page.Items []hearth.User, page.NextCursor *string
```

## Runnable example

A complete Go/Gin server lives at
[`examples/go-gin/`](https://github.com/hearth-auth/hearth/tree/main/examples/go-gin).
It demonstrates JWT middleware, RBAC route guards, automatic JWKS refresh, and a
dev bootstrap flow — all runnable with `go run .`.

## Next steps

- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [Go type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/go/README.md) — full type list

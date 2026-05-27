---
id: go
title: Go SDK quickstart
sidebar_label: Go
description: Add Hearth authentication and RBAC to a Go service in under 5 minutes.
---

# Go SDK quickstart

Get your first protected HTTP endpoint in under 5 minutes using the Hearth Go SDK.

## Install

```bash
go get github.com/anthropics/hearth/sdks/go
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
import "github.com/anthropics/hearth/sdks/go/hearth"

client := hearth.NewClient("http://127.0.0.1:8420", "<realm_id>")
```

`Client` is goroutine-safe and is designed to be created once and reused across
requests.

## Verify tokens with JWKS

Hearth signs JWTs with Ed25519. Verify them using the realm's JWKS endpoint
and the [`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx) library:

```bash
go get github.com/lestrrat-go/jwx/v2
```

```go
package main

import (
    "context"
    "fmt"

    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
)

func main() {
    ctx := context.Background()

    // Fetch and cache the JWKS once at startup.
    jwksURL := "http://127.0.0.1:8420/realms/<realm_id>/jwks"
    keySet, err := jwk.Fetch(ctx, jwksURL)
    if err != nil {
        panic(err)
    }

    // Verify a token.
    accessToken := "<token>"
    tok, err := jwt.Parse([]byte(accessToken), jwt.WithKeySet(keySet))
    if err != nil {
        panic(fmt.Errorf("invalid token: %w", err))
    }

    fmt.Println("user:", tok.Subject())
}
```

The key set should be refreshed once on a verification failure (to handle
server key rotation). See `examples/go-gin/main.go` for a complete example.

## Auth code flow with PKCE

Hearth implements standard OIDC authorization code flow. To issue tokens for a
user your service has already authenticated:

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/anthropics/hearth/sdks/go/hearth"
)

func pkce() (verifier, challenge string) {
    raw := make([]byte, 32)
    rand.Read(raw)
    verifier = hex.EncodeToString(raw)
    sum := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(sum[:])
    return
}

func main() {
    ctx := context.Background()
    client := hearth.NewClient("http://127.0.0.1:8420", "<realm_id>")

    // 1. Generate PKCE verifier and challenge
    codeVerifier, _ := pkce()

    // 2. Start authorization — exchange code for this specific user
    authResp, err := client.Authorize(ctx, hearth.AuthorizeRequest{
        ClientID:    "<client_id>",
        RedirectURI: "http://localhost:8080/callback",
        Scope:       "openid profile email",
        State:       "random-csrf-token",
        UserID:      "<user_uuid>", // authenticated user on your backend
    })
    if err != nil {
        panic(err)
    }

    // 3. Exchange the code for tokens
    tokens, err := client.ExchangeCode(ctx, hearth.TokenRequest{
        ClientID:    "<client_id>",
        Code:        authResp.Code,
        RedirectURI: "http://localhost:8080/callback",
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("access_token:", tokens.AccessToken)
    fmt.Println("expires_in:  ", tokens.ExpiresIn)

    // 4. Refresh before expiry
    refreshed, err := client.RefreshTokens(ctx, "<client_id>", tokens.RefreshToken)
    _ = refreshed
    _ = codeVerifier
}
```

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

    "github.com/anthropics/hearth/sdks/go/hearth"
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
[`examples/go-gin/`](https://github.com/therecluse26/hearth/tree/main/examples/go-gin).
It demonstrates JWT middleware, RBAC route guards, automatic JWKS refresh, and a
dev bootstrap flow — all runnable with `go run .`.

## Next steps

- [RBAC guide](../rbac.md) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](../admin-api.md) — managing users and clients programmatically
- [Go type reference](https://github.com/therecluse26/hearth/blob/main/sdks/go/README.md) — full type list

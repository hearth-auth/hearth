---
title: Authenticate a Gin app with Hearth
sidebar_label: Gin
description: >
  Protect Gin routes with Hearth tokens using the dedicated hearthgin middleware adapter.
  Covers HearthMiddleware, RequirePermission, GetToken, and functional options.
---

# Authenticate a Gin app with Hearth

This guide is for **Gin developers** who want to protect routes with Hearth tokens. The Go SDK ships a dedicated Gin adapter in the `hearthgin` sub-package (`hearth/gin`) that extracts the bearer token from `Authorization: Bearer`, stores it in the Gin context, and provides a `RequirePermission` middleware for per-group permission gates.

:::note[Dedicated adapter vs generic net/http middleware]
This page covers the `hearthgin` adapter (`hearth/gin`), which works with Gin's `gin.HandlerFunc` type. For **net/http** `ServeMux`, Gorilla Mux, or any standard `http.Handler`-compatible router, use the generic [`hearth.RequirePermission`](./go.md#nethttp-middleware) from the base `hearth` package instead.
:::

## Install

```bash
go get github.com/hearth-auth/hearth/sdks/go
```

The Gin adapter lives inside the SDK module at `hearth/gin` — no separate `go get` is needed.

## Set up the middleware

Import both the base SDK and the `hearthgin` adapter:

```go
import (
    hearth    "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthgin "github.com/hearth-auth/hearth/sdks/go/hearth/gin"
    "github.com/gin-gonic/gin"
)

client := hearth.NewClient(
    "https://hearth.example.com",
    "<realm-id>",
)

r := gin.Default()
r.Use(hearthgin.HearthMiddleware(client))
```

`HearthMiddleware` reads `Authorization: Bearer <token>` and stores two values in the Gin context for downstream handlers and middleware to use:

| Context key | Constant | Value |
|-------------|----------|-------|
| `"hearth_token"` | `hearthgin.TokenContextKey` | Raw JWT string |
| `"hearth_client"` | `hearthgin.ClientContextKey` | `*hearth.Client` |

Requests with no `Authorization` header receive `HTTP 401 Unauthorized` by default. Requests that carry a token continue to the next handler; the token is not verified at this stage — verification is a local JWKS check that happens when you call `GetToken` + `HasPermission` or invoke `RequirePermission`.

## Read the token in a handler

Use `hearthgin.GetToken` to retrieve the JWT string stored in context, then call RBAC helpers on the client:

```go
r.GET("/profile", func(c *gin.Context) {
    token := hearthgin.GetToken(c)
    // HasPermission decodes claims locally — no network call
    if !client.HasPermission(token, "profile.read") {
        c.AbortWithStatus(http.StatusForbidden)
        return
    }
    c.JSON(http.StatusOK, gin.H{"sub": "..."})
})
```

`GetToken` returns an empty string when `HearthMiddleware` has not run or when the request carried no token.

## Per-group permission gate with RequirePermission

Use `hearthgin.RequirePermission` as group middleware to gate a set of routes on a single permission. Claims are decoded locally from the stored JWT — no network call on the request path.

```go
import (
    "net/http"

    hearth    "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthgin "github.com/hearth-auth/hearth/sdks/go/hearth/gin"
    "github.com/gin-gonic/gin"
)

func main() {
    client := hearth.NewClient("https://hearth.example.com", "<realm-id>")

    r := gin.Default()
    r.Use(hearthgin.HearthMiddleware(client)) // authenticate all routes

    // Any valid token passes through
    r.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "ok"})
    })

    // Admin group — requires admin.write permission
    admin := r.Group("/admin")
    admin.Use(hearthgin.RequirePermission("admin.write"))
    admin.GET("/users", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"users": []string{}})
    })

    r.Run(":8080")
}
```

`RequirePermission` response matrix:

| Condition | Response |
|-----------|----------|
| No token in context (HearthMiddleware not wired) | `401 Unauthorized` |
| Token lacks the required permission | `403 Forbidden` |
| Token passes the permission check | Calls `c.Next()` |

:::info[Middleware ordering]
`HearthMiddleware` must appear before `RequirePermission` in the chain. `HearthMiddleware` sets both `hearth_token` and `hearth_client` in the Gin context; `RequirePermission` reads both. If the client key is absent from context, `RequirePermission` aborts with `500 Internal Server Error` — the most common cause is mounting `RequirePermission` without `HearthMiddleware` at the parent level.
:::

## Functional options

Both `HearthMiddleware` accepts optional `MiddlewareOption` arguments to replace default behaviour.

### Custom token extractor

The default extractor strips `Bearer ` from the `Authorization` header. Replace it to read from a cookie or custom header:

```go
r.Use(hearthgin.HearthMiddleware(client,
    hearthgin.WithTokenExtractor(func(c *gin.Context) string {
        // Read from an httpOnly cookie instead of the Authorization header
        cookie, err := c.Cookie("access_token")
        if err != nil {
            return ""
        }
        return cookie
    }),
))
```

### Custom unauthorized handler

Replace the default `HTTP 401` abort when no token is found:

```go
r.Use(hearthgin.HearthMiddleware(client,
    hearthgin.WithOnUnauthorized(func(c *gin.Context) {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
            "error":     "unauthorized",
            "login_url": "https://hearth.example.com/authorize",
        })
    }),
))
```

## Full working example

```go
package main

import (
    "net/http"

    hearth    "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthgin "github.com/hearth-auth/hearth/sdks/go/hearth/gin"
    "github.com/gin-gonic/gin"
)

func main() {
    client := hearth.NewClient(
        "https://hearth.example.com",
        "<realm-id>",
    )

    r := gin.Default()

    // Authenticate every request
    r.Use(hearthgin.HearthMiddleware(client))

    r.GET("/profile", func(c *gin.Context) {
        token := hearthgin.GetToken(c)
        c.JSON(http.StatusOK, gin.H{
            "authenticated": true,
            "has_admin":     client.HasPermission(token, "admin.write"),
        })
    })

    // Admin routes — require admin.write permission
    admin := r.Group("/admin")
    admin.Use(hearthgin.RequirePermission("admin.write"))

    admin.GET("/users", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"users": []string{}})
    })
    admin.POST("/users", func(c *gin.Context) {
        c.JSON(http.StatusCreated, gin.H{"created": true})
    })

    r.Run(":8080")
}
```

Run against the Hearth dev server:

```bash
make dev &                         # start Hearth on http://127.0.0.1:8420
go run .                           # start Gin on :8080
curl -H "Authorization: Bearer <token>" http://localhost:8080/profile
```

A complete runnable example with dev bootstrap is at
[`examples/go-gin/`](https://github.com/hearth-auth/hearth/tree/main/examples/go-gin).

## Next steps

- [Go SDK quickstart](./go.md) — `NewClient`, PKCE login, RBAC helpers, and the `net/http` generic middleware
- [Echo adapter](./go-echo.md) — `hearthecho` for Echo v4 applications
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure

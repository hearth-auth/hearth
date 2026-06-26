---
title: Authenticate an Echo app with Hearth
sidebar_label: Echo
description: >
  Protect Echo v4 routes with Hearth tokens using the dedicated hearthecho middleware adapter.
  Covers HearthMiddleware, RequirePermission, GetToken, and functional options.
---

# Authenticate an Echo app with Hearth

This guide is for **Echo v4 developers** who want to protect routes with Hearth tokens. The Go SDK ships a dedicated Echo adapter in the `hearthecho` sub-package (`hearth/echo`) that extracts the bearer token from `Authorization: Bearer`, stores it in the Echo context, and provides a `RequirePermission` middleware for per-group permission gates.

:::note[Dedicated adapter vs generic net/http middleware]
This page covers the `hearthecho` adapter (`hearth/echo`), which works with Echo's `echo.MiddlewareFunc` type and returns `error` from handlers in the Echo style. For **net/http** `ServeMux`, Gorilla Mux, or any standard `http.Handler`-compatible router, use the generic [`hearth.RequirePermission`](./go.md#nethttp-middleware) from the base `hearth` package instead.
:::

## Install

```bash
go get github.com/hearth-auth/hearth/sdks/go
```

The Echo adapter lives inside the SDK module at `hearth/echo` — no separate `go get` is needed.

## Set up the middleware

Import both the base SDK and the `hearthecho` adapter:

```go
import (
    hearth      "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthecho  "github.com/hearth-auth/hearth/sdks/go/hearth/echo"
    "github.com/labstack/echo/v4"
)

client := hearth.NewClient(
    "https://hearth.example.com",
    "<realm-id>",
)

e := echo.New()
e.Use(hearthecho.HearthMiddleware(client))
```

`HearthMiddleware` reads `Authorization: Bearer <token>` and stores two values in the Echo context for downstream handlers and middleware to use:

| Context key | Constant | Value |
|-------------|----------|-------|
| `"hearth_token"` | `hearthecho.TokenContextKey` | Raw JWT string |
| `"hearth_client"` | `hearthecho.ClientContextKey` | `*hearth.Client` |

Requests with no `Authorization` header receive `HTTP 401 Unauthorized` (via `echo.ErrUnauthorized`) by default. Requests that carry a token continue to the next handler.

:::info[Echo middleware returns error]
Unlike Gin's void `gin.HandlerFunc`, Echo middleware returns `error`. When `HearthMiddleware` or `RequirePermission` rejects a request, they return an `*echo.HTTPError` — which Echo's default error handler converts to the appropriate JSON response. You do not call `c.Abort()`.
:::

## Read the token in a handler

Use `hearthecho.GetToken` to retrieve the JWT string stored in context, then call RBAC helpers on the client:

```go
e.GET("/profile", func(c echo.Context) error {
    token := hearthecho.GetToken(c)
    // HasPermission decodes claims locally — no network call
    if !client.HasPermission(token, "profile.read") {
        return echo.ErrForbidden
    }
    return c.JSON(http.StatusOK, map[string]any{"sub": "..."})
})
```

`GetToken` returns an empty string when `HearthMiddleware` has not run or when the request carried no token.

## Per-group permission gate with RequirePermission

Use `hearthecho.RequirePermission` as group middleware to gate a set of routes on a single permission. Claims are decoded locally from the stored JWT — no network call on the request path.

```go
import (
    "net/http"

    hearth     "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthecho "github.com/hearth-auth/hearth/sdks/go/hearth/echo"
    "github.com/labstack/echo/v4"
)

func main() {
    client := hearth.NewClient("https://hearth.example.com", "<realm-id>")

    e := echo.New()
    e.Use(hearthecho.HearthMiddleware(client)) // authenticate all routes

    // Any valid token passes through
    e.GET("/health", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
    })

    // Admin group — requires admin.write permission
    admin := e.Group("/admin")
    admin.Use(hearthecho.RequirePermission("admin.write"))
    admin.GET("/users", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]any{"users": []string{}})
    })

    e.Start(":8080")
}
```

`RequirePermission` response matrix:

| Condition | Response |
|-----------|----------|
| No token in context (HearthMiddleware not wired) | `401 Unauthorized` (`echo.ErrUnauthorized`) |
| Token lacks the required permission | `403 Forbidden` (`echo.ErrForbidden`) |
| Client missing from context (misconfigured chain) | `500 Internal Server Error` |
| Token passes the permission check | Calls `next(c)` |

:::info[Middleware ordering]
`HearthMiddleware` must appear before `RequirePermission` in the chain. `HearthMiddleware` sets both `hearth_token` and `hearth_client` in the Echo context; `RequirePermission` reads both. The most common misconfiguration is mounting `RequirePermission` on a group without applying `HearthMiddleware` at the parent level first.
:::

## Functional options

`HearthMiddleware` accepts optional `MiddlewareOption` arguments to replace default behaviour.

### Custom token extractor

The default extractor strips `Bearer ` from the `Authorization` header. Replace it to read from a cookie or custom header:

```go
e.Use(hearthecho.HearthMiddleware(client,
    hearthecho.WithTokenExtractor(func(c echo.Context) string {
        // Read from an httpOnly cookie instead of the Authorization header
        cookie, err := c.Cookie("access_token")
        if err != nil {
            return ""
        }
        return cookie.Value
    }),
))
```

### Custom unauthorized handler

Replace the default `echo.ErrUnauthorized` response when no token is found. The function must return an `error` — typically an `*echo.HTTPError`:

```go
e.Use(hearthecho.HearthMiddleware(client,
    hearthecho.WithOnUnauthorized(func(c echo.Context) error {
        return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
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

    hearth     "github.com/hearth-auth/hearth/sdks/go/hearth"
    hearthecho "github.com/hearth-auth/hearth/sdks/go/hearth/echo"
    "github.com/labstack/echo/v4"
)

func main() {
    client := hearth.NewClient(
        "https://hearth.example.com",
        "<realm-id>",
    )

    e := echo.New()

    // Authenticate every request
    e.Use(hearthecho.HearthMiddleware(client))

    e.GET("/profile", func(c echo.Context) error {
        token := hearthecho.GetToken(c)
        return c.JSON(http.StatusOK, map[string]any{
            "authenticated": true,
            "has_admin":     client.HasPermission(token, "admin.write"),
        })
    })

    // Admin routes — require admin.write permission
    admin := e.Group("/admin")
    admin.Use(hearthecho.RequirePermission("admin.write"))

    admin.GET("/users", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]any{"users": []string{}})
    })
    admin.POST("/users", func(c echo.Context) error {
        return c.JSON(http.StatusCreated, map[string]bool{"created": true})
    })

    e.Start(":8080")
}
```

Run against the Hearth dev server:

```bash
make dev &                         # start Hearth on http://127.0.0.1:8420
go run .                           # start Echo on :8080
curl -H "Authorization: Bearer <token>" http://localhost:8080/profile
```

## Next steps

- [Go SDK quickstart](./go.md) — `NewClient`, PKCE login, RBAC helpers, and the `net/http` generic middleware
- [Gin adapter](./go-gin.md) — `hearthgin` for Gin applications
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure

## Context

`createHearthAuth` keeps the refresh token in its store. `refreshAccessToken()` reads it, calls `client.refreshTokens`, and stores the rotated token. Nothing stops two calls from reading the same token before either stores the new one. Hearth's refresh grant compares the token with the family's current hash and, on a mismatch, revokes the family (theft detection, OAuth 2.0 Security BCP §4.14).

## Goals / Non-Goals

**Goals:**
- Concurrent calls in one `createHearthAuth` instance send one request.

**Non-Goals:**
- Coordination across tabs or across instances. The default store is `sessionStorage`, which a tab does not share.
- A server-side reuse grace period. Theft detection stays strict.

## Decisions

1. **A shared promise, cleared when it settles.** `refreshAccessToken` returns the in-flight promise while one exists, and clears it in `finally`. A failed refresh is not cached: the next call tries again.
2. **Both callers see the same outcome.** If the request fails, every caller that shared it gets the same rejection, so no caller falls back to a second request with the old token.

## Risks / Trade-offs

- [A caller that wanted a fresh request gets the result of one that started earlier] → The earlier request returns a token as new as the caller can get: its refresh token was the current one.

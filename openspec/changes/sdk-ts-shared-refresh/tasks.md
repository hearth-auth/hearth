## 1. Test first (red)

- [x] 1.1 `sdks/typescript/tests/browser-auth.test.ts`: two `refreshAccessToken()` calls before the first resolves send one `refreshTokens` request, both resolve, and the rotated refresh token is stored; a call after that sends a second request. A failed shared request rejects both callers, and the next call tries again.
- [x] 1.2 Run `npx vitest run tests/browser-auth.test.ts`: it fails (two requests).

## 2. Implementation

- [x] 2.1 `browser-auth.ts`: `refreshAccessToken` returns the in-flight promise while a refresh runs, and clears it when it settles.
- [x] 2.2 Run the SDK tests and `tsc` (green).

## 3. Close-out

- [x] 3.1 `CHANGELOG.md` `Fixed` entry.
- [ ] 3.2 Full-stack demo integration suite: flows 3, 5 and 6 pass (in the demo-repair PR).

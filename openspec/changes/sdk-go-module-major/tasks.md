## 1. Release guard

- [x] 1.1 Write `scripts/tests/check-go-module-major.test.sh` first: a matching `/v3` module passes; the current unsuffixed module with `3.5.9` fails; a `/v3` module with `4.0.0` fails; an unsuffixed module with `1.6.12` passes; a `/v2` module with `1.2.0` fails; a bad version fails. Run it red.
- [x] 1.2 Write `scripts/check-go-module-major.sh <version>` until the test passes.
- [x] 1.3 Run the guard on the repo with `3.5.9` before the rename: it fails.
- [x] 1.4 Add it to `sdks/go/.releaserc.json` as an `@semantic-release/exec` `verifyReleaseCmd`, and add the self-test to `.github/workflows/ci.yml`.

## 2. Module path

- [x] 2.1 Set `sdks/go/go.mod` to `github.com/hearth-auth/hearth/sdks/go/v3`, and update every import in `sdks/go`, `examples/go-gin` and `examples/full-stack-demo/backend` (including `replace` lines).
- [x] 2.2 `go build ./...`, `go vet ./...` and `go test ./...` in `sdks/go` and both examples. The demo backend's `handlers` tests (`TestAdminListUsers`) fail on `main` too; they are not part of CI.
- [x] 2.3 Run the guard on the repo with `3.5.9`: it passes.
- [x] 2.4 Update the docs, the README files and `.github/workflows/sdk-publish-go.yml`.

## 3. Close out

- [x] 3.1 `CHANGELOG.md` entry under `Fixed`, with the new import path.
- [ ] 3.2 `make ci-local-fast`.
- [ ] 3.3 After the release: `go get github.com/hearth-auth/hearth/sdks/go/v3@<tag>` resolves in a scratch module.

## Context

semantic-release computes each SDK's next version from the commit messages, and SDK versions move in step with the server. The Go SDK's tags are `sdks/go/vX.Y.Z`. Go resolves a tag `vN.x.y` with `N >= 2` only for a module path that ends in `/vN`.

## Decisions

### Check at release time, with the computed version

The guard runs as the Go SDK's `verifyReleaseCmd` with `${nextRelease.version}`. That is the first moment the next major is known, and it is before semantic-release creates the tag. A PR check cannot know whether the next release is a major bump, because the commits after the PR decide it. CI runs the guard's self-test only, which proves that the guard fails on a mismatch.

A release that fails the guard leaves `main` unreleased until a PR changes the module path. That is the intent: an uninstallable tag is worse than a late one.

### Move the proto `go_package` options with the next major

The proto `go_package` options name `github.com/hearthdb/hearth/sdks/go/generated/...`, a path that does not exist. They matter only for imports between generated packages, and no code imports the generated proto packages. `buf breaking` with the `FILE` category refuses a `go_package` change (`FILE_SAME_GO_PACKAGE`). The next major version changes the module path to `/v4` and breaks formats anyway, so it fixes `go_package` once, with the right path.

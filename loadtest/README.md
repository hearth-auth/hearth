# hearth-loadtest

Load-testing harness for the Hearth identity server, built on
[goose](https://book.goose.rs/). Tracks the load-test plan in
[HEA-1787](/HEA/issues/HEA-1787).

## Why this crate is excluded from the workspace

`hearth-loadtest` is **not** a workspace member — the root `Cargo.toml`
declares `exclude = ["loadtest"]`. goose pulls in a large transitive
dependency tree (an async HTTP client, reqwest, tooling for reports) that we
do not want compiled on every `cargo nextest run --workspace`, which would
slow the unit-test gate for no benefit. The crate is `publish = false` and is
built/run explicitly instead.

## Building and running

```bash
make loadtest              # cargo run --release -p hearth-loadtest -- ...
make loadtest-check        # cargo check -p hearth-loadtest (keeps it from rotting)
```

Or directly:

```bash
cargo run --release -p hearth-loadtest -- --help
```

## Status

Skeleton only. The binary currently registers no scenarios and exits
immediately. Auth-flow, token-validation, session-lookup, and RBAC-check
scenarios are added in follow-up issues under HEA-1787.

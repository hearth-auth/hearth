# scripts/tests

Tests for the pure-bash CI guards in `scripts/`.

These guards run in the `filter` job of `.github/workflows/ci.yml` before any Rust
build, so they are not covered by `cargo nextest`. Each guard that gates a release
should have a companion `*.test.sh` here proving it **fails** on the condition it
exists to catch — a guard that only ever exits 0 is indistinguishable from a stub.

| Test | Guard under test |
|------|------------------|
| `check-readme-version.test.sh` | `scripts/check-readme-version.sh` (HEA-2116) |

Run one locally:

```bash
bash scripts/tests/check-readme-version.test.sh
```

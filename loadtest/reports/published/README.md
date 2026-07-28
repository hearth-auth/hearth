# Published Load-Test Artifacts

`loadtest/reports/` is gitignored (bearer tokens in seed handles must never be
committed). This subdirectory is the exception: **any report JSON that backs a
figure cited in `docs/perf/PERFORMANCE_REPORT_1_0.md` MUST be committed here**
so the figure is re-auditable without re-running the test.

## Naming convention

```
loadtest/reports/published/<issue>/<run-label>.json
```

Example: `loadtest/reports/published/hea1871/steady-500u.json`

## What to include

- The `report.json` produced by `make loadtest` for the specific run.
- The run must have been produced with `--server-pid` so the `resources` block
  is populated and the ceiling attribution is trustworthy (HEA-1880).
- Strip the seed handle (`seed-handle.json`) before committing — it contains
  live bearer tokens.

## What NOT to include

- `*.html` reports (large, not machine-readable, not needed for re-audit).
- `seed-handle.json` or any file containing bearer tokens.
- Raw Goose log files (`curve-run.log`, `hea1812-run.log`, etc.).

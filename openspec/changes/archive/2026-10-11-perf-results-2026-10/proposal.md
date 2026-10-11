## Why

`docs/perf/` now holds the AWS load test of 2026-10-10, and the July 2026 figures (`PUBLISHED_FIGURES.md`, `PERFORMANCE_REPORT_2_1.md` and their artifacts) are removed. The `performance-budgets` spec cites `docs/perf/PUBLISHED_FIGURES.md` §2.1 for the retraction of the earlier session-creation peak. That path no longer exists.

## What Changes

- The requirement "Durable session creation throughput" cites the retraction through a permalink to the last commit that has `PUBLISHED_FIGURES.md`. The requirement itself does not change: the target, the ungraded status and the scenario stay the same.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `performance-budgets`: one citation in "Durable session creation throughput" becomes a permalink.

## Impact

Documentation only. No code, gate or budget changes.

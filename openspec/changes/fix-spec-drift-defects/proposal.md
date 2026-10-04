## Why

`adopt-openspec-specs` converted the prose specs into OpenSpec and checked every requirement against the code. In most places where the code and the doc disagreed, the code was right and the spec now states what the code does. In the places listed here, the code is wrong: a missing audit event, a wrong status code or wire format, a documented config key that does not exist, a bench that measures the wrong code. Security-relevant defects are tracked separately, in `security-hardening`. The baseline keeps the correct rule, so today the code fails it.

## What Changes

- Fix each defect in `tasks.md`. Each task names a regression scenario. That scenario is added to the baseline requirement by this change's delta, and a test for it is written first (red), then the fix (green).
- Each delta is a MODIFIED copy of the baseline requirement with one or more `Regression —` scenarios added. The requirement text does not change.
- Each user-visible fix needs a `CHANGELOG.md` entry when it ships.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
Every capability with a delta under `specs/`: each gains regression scenarios; no requirement text changes.

## Impact

- **Code:** `src/abuse/`, `src/identity/`, `src/rbac/`, `src/protocol/`, `src/config/`, `templates/`, `benches/`, `loadtest/`, and the Go, Python, PHP and TypeScript SDKs.
- **Config:** documented keys that do not exist today (A-24 `quotas`) are wired, so the documented YAML starts the server.
- **Order:** this change applies after `adopt-openspec-specs` is archived. No requirement here is also modified by `security-hardening`. It does not depend on the other active changes, but `sdk-standard-libraries` may replace some SDK fixes; check each SDK task against it first.

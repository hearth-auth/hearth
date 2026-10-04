## Why

`adopt-openspec-specs` checked every converted requirement against the code. For the security-relevant requirements listed here, the code needs work before it satisfies the baseline. Each one is tracked as a scenario that the code must pass, so none of them is missed.

The detail of each gap (where the code falls short, and how) is kept in the draft repository security advisory `GHSA-hxcr-696v-vqw3`, visible to maintainers only, not in this public repo. Read it before starting a task.

## What Changes

- Each delta is a MODIFIED copy of a baseline requirement with one or more added scenarios. The requirement text does not change; the scenarios make each rule testable.
- `tasks.md` has one task per scenario: write the test first (red), then the fix (green).
- Every fix ships with a `### Security` entry in `CHANGELOG.md`.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
Every capability with a delta under `specs/`: each gains scenarios; no requirement text changes.

## Impact

- **Code:** server (`src/`) and the Go, Python and TypeScript SDKs.
- **Order:** applies after `adopt-openspec-specs` (archived). No requirement here is also modified by `fix-spec-drift-defects`, so the two changes can archive in either order.
- **Disclosure:** keep exploit detail out of commits, PR text and public issues until the fix ships.

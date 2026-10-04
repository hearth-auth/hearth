## Why

The prose specs that `adopt-openspec-specs` converted described behaviour that was never built: agents as authenticated principals (an agent as token subject, `act.sub` naming the agent, agent roles, `max_delegation_depth` on agents), on-behalf-of `requested_actor`, intent claims, risk signals, cross-realm agent tokens, SPIFFE validation, and more. Keeping those rules in the baseline would make `openspec/specs/` claim features Hearth does not have. Deleting them would lose the design work.

## What Changes

- The unbuilt rules leave the baseline and live here as ADDED requirements, grouped by capability. Nothing in this change is implemented.
- This change is a backlog, not a plan. Under the trusted-core feature freeze (`scope-trim-trusted-core`), each requirement is either cut (delete it from this change) or promoted into its own change with a design and tasks before any work starts.
- `tasks.md` holds one triage task per capability.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
Every capability with a delta under `specs/`: each gains the unbuilt requirements as ADDED requirements.

## Impact

- **Code:** none until a requirement is promoted into its own change.
- **Docs:** `openspec/specs/` stays true to the code; this change records what the old docs promised.
- **Order:** applies after `adopt-openspec-specs` is archived. Do not archive this change; cut or promote its requirements instead.

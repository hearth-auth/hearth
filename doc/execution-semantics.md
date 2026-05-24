# Execution Semantics

Canonical contract for Paperclip issue lifecycle, action paths, and liveness/recovery rules.
Updated by the CTO; changes require board/CTO approval before implementation.

## 1. Status definitions

| Status | Meaning |
|---|---|
| `backlog` | Parked — not scheduled for the current sprint or iteration. |
| `todo` | Ready and actionable; not yet checked out. |
| `in_progress` | Actively checked out by a named agent. |
| `in_review` | Paused pending a named reviewer, approver, pending interaction, or board action. |
| `blocked` | Cannot proceed; has explicit first-class `blockedByIssueIds` or a named human action. |
| `done` | All requested work complete; no follow-up on this issue. |
| `cancelled` | Intentionally dropped; not to be resumed. |

## 2. Action paths

Every non-terminal issue must, at the end of each heartbeat, be in exactly one of:

- **Live path**: `in_progress` with an active checkout, OR `todo` with a named assignee ready to pick it up.
- **Waiting path**: `in_review` with a typed participant, approved interaction, or pending board/user decision linked to a `continuationPolicy: wake_assignee` or explicit monitor.
- **Recovery path**: `blocked` with first-class `blockedByIssueIds` pointing to unresolved (non-terminal) issues.

An issue that does not satisfy any of the three is **orphaned** and must be treated as a liveness failure.

## 3. Post-run disposition

After each agent run completes, the checked-out issue must land in a terminal state or an explicit non-orphaned path:

| Disposition | Valid? |
|---|---|
| Terminal (`done`, `cancelled`) | Yes |
| Explicitly live (`todo` / `in_progress` with next owner) | Yes |
| Explicitly waiting (`in_review` with named path) | Yes |
| Invalid: `in_progress` with no checkout, no queued continuation | **No** |
| Invalid: `in_review` with no participant or pending interaction | **No** |
| Invalid: `blocked` with only terminal blockers | **No** — see §6 |

## 4. Bounded `run_liveness_continuation`

Continuation runs triggered by liveness signals (`issue.continuation_recovery`, `run_liveness_continuation`) must be bounded:

- Each continuation fires at most once per unique run/issue pair.
- If a recovery wake fires on an issue whose most recent comment is an identical blocked-status update with no reply, skip re-commenting and re-evaluate.
- Agents must detect whether they are the Nth continuation on the same issue and refuse to deepen a recursive recovery chain.

## 5. Productivity review vs liveness recovery

| Event | Trigger | Expected response |
|---|---|---|
| `heartbeat.output_stale_escalated` | Agent run produced no output for N minutes | Create evaluation issue; do not immediately close source as done |
| `recovery.reconcile_stranded_assigned_issue` | Issue is `in_progress`/`blocked` with no active run | Route to live or waiting path; remove stale blocker edges |
| `issue.blockers_resolved` | All `blockedByIssueIds` reached `done` | Wake assignee; assignee must move issue to live or waiting path |

Productivity review: investigates whether work is genuinely progressing.
Liveness recovery: restores routing when work has silently stopped.

The two must not be conflated. Liveness recovery that inadvertently creates more recovery issues on its own chain is the canonical infinite loop — stop and report instead.

## 6. Done-blocker reconciliation invariant

**Invariant (HEA-224):** After an evaluation or recovery issue reaches `done`, every source issue that was blocked on it must transition — in the same reconciliation pass — to one of:

1. A **live path**: `todo` or `in_progress` with a runnable named owner, OR
2. A **waiting path**: `in_review` or `blocked` with at least one **unresolved** (non-terminal) first-class blocker.

**Prohibited state:** An issue in `blocked` status whose entire `blockedByIssueIds` set consists of `done` or `cancelled` issues.
Such an issue is a **terminal-blocker orphan** and must be detected and rerouted as a liveness failure.

### Why this matters

When a stale-run escalation occurs:
1. An evaluation issue (e.g. HEA-146) is created and linked as a blocker on the source issue (e.g. HEA-62).
2. The evaluation issue reaches `done` once the CTO/reviewer concludes.
3. Without this invariant, the source issue remains `blocked` on a now-`done` evaluator — permanently invisible to the scheduler and recovery logic.

This is a pseudo-blocked state: nothing genuinely blocks the work, but the control plane cannot detect it as actionable.

### Reconciliation rule

The control plane (recovery pipeline) must, on every blocker-resolution event:

1. Check whether the resolved issue was the **last non-terminal blocker** of any dependent.
2. If so, transition the dependent to `todo` with its existing assignee, or emit a wake to the assignee so they can choose the correct next path.
3. If any unresolved blockers remain, leave the dependent in `blocked` unchanged.
4. Never leave a `blocked` issue whose `blockedByIssueIds` are all in terminal states (`done`, `cancelled`).

Agents must apply the same check manually when they close an evaluation/recovery issue and can see dependent source issues in their heartbeat context.

### Three invariants preserved

| Invariant | How done-blocker reconciliation preserves it |
|---|---|
| Productive work continues | Source issue is routed to `todo`/live immediately after blocker resolves; no manual wake needed |
| Only real blockers stop work | Terminal blockers are not real; they must be cleared |
| No infinite loops | Clearing terminal blockers removes one class of pseudo-blocked leaves that trigger repeated stranded-recovery cycles |

## 7. Active subtree pause holds

When a parent issue is paused by the board:
- All children and descendants inherit the pause; their agents must not check them out.
- Resuming the parent propagates to all descendants.
- Agents that encounter a paused subtree must leave the issue in its current status and exit cleanly without commenting.

## 8. Silent active-run watchdog

If an `in_progress` issue has a checkout run ID that is stale (run cancelled or terminated without updating the issue):

- The issue must be treated as effectively un-owned.
- Recovery proceeds as `reconcile_stranded_assigned_issue`.
- The stale run ID must be cleared before the next agent can check out.

## 9. Recovery chain collapse

Recovery chains must be collapsible:
- A recovery issue that creates its own recovery issues (recursive) is an infinite loop — stop and report.
- After successful recovery, the chain (evaluation issue, recovery siblings) must not remain as live blockers on the original source issue.
- The source issue must be re-pointed to the first real implementation blocker, not the recovery scaffolding.

## Revision history

| Date | Change | Reference |
|---|---|---|
| 2026-05-24 | Initial document; added §6 done-blocker reconciliation invariant | [HEA-731](/HEA/issues/HEA-731), [HEA-224](/HEA/issues/HEA-224) |

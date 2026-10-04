## MODIFIED Requirements

### Requirement: An expired request counts as denied
An expired approval request MUST be treated as denied. To retry, the agent MUST create a new request.

#### Scenario: Approve after expiry
- **WHEN** an approver tries to approve a request after its `expires_at`
- **THEN** no capability token is issued

#### Scenario: Regression — an expired request still reads Pending
- **WHEN** a client reads or lists a request whose `expires_at` has passed without a decision
- **THEN** its status is `Expired`, and `GET /v1/approval-requests?status=expired` lists it

### Requirement: Signal-triggered actions are audited with their signal
Every action triggered by a risk signal MUST be recorded in the audit log, with the triggering signal as context.

#### Scenario: A signal-triggered action is recorded
- **WHEN** Hearth takes an action because of a risk signal
- **THEN** the action's audit event names that signal

#### Scenario: Regression — rate suspension is audited without its signal
- **WHEN** the rate monitor suspends an agent
- **THEN** the `AgentSuspended` event names the rate signal as its cause, and a failure to suspend or to write the event is reported rather than ignored

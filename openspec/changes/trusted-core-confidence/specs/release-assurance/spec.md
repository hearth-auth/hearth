## ADDED Requirements

### Requirement: Feature freeze until the confidence work is done
From v3.0.0 until this change is archived, the project SHALL accept no new server feature. Defect fixes, removals, tests, documentation, tooling and the `sdk-standard-libraries` change SHALL remain allowed. `CONTRIBUTING.md` SHALL state the rule and its end condition.

#### Scenario: A feature is proposed during the freeze
- **WHEN** a change proposes a new endpoint, config key, grant or login method during the freeze
- **THEN** the review refuses it, and the reason cites the freeze in `CONTRIBUTING.md`

#### Scenario: A defect fix during the freeze
- **WHEN** a change fixes a defect in an existing surface during the freeze
- **THEN** the freeze does not block it

### Requirement: External OIDC conformance passes
Before a release, the OpenID Foundation conformance suite SHALL run the Basic OP, Config OP and Dynamic OP plans against a production-mode Hearth (`serve -c`, TLS, a real KEK, not `--dev`). Every plan SHALL finish with zero failed conditions. Each warning SHALL have a recorded decision in the run report.

#### Scenario: A plan has a failed condition
- **WHEN** the scripted run finishes and any plan has a failed condition
- **THEN** the script exits non-zero, and the release is blocked

#### Scenario: A plan has a warning
- **WHEN** a plan has a warning
- **THEN** the run report names the warning and the decision (fixed, or kept with a reason)

#### Scenario: The run uses a production configuration
- **WHEN** the script starts Hearth for the run
- **THEN** it starts it with `serve -c`, TLS on and a real KEK, and refuses to run against `--dev`

### Requirement: Every entry point enforces every invariant
A registry SHALL list every entry point that creates a session or issues a token: HTTP routes and CLI commands. For each security invariant (realm status, organization status, user status, client status, the MFA policy, the pre-token webhook policy), a table-driven test SHALL check that each entry point refuses when the invariant is violated. A row that does not apply SHALL carry a written reason.

#### Scenario: An entry point skips an invariant
- **WHEN** an entry point issues a token while the user's organization is suspended
- **THEN** the invariant test for that entry point fails

#### Scenario: A new entry point is not registered
- **WHEN** a route that issues a token or creates a session is added to the router and not to the registry
- **THEN** the registry guard test fails and names the route

#### Scenario: An invariant does not apply
- **WHEN** an invariant cannot apply to an entry point (for example, the MFA policy on the client credentials grant)
- **THEN** the registry row marks it not applicable, with a reason, and the test skips only that pair

### Requirement: Mutation testing with a budget that only goes down
`cargo-mutants` SHALL run nightly on `src/identity/`, `src/rbac/` and `src/protocol/http/`. A committed budget SHALL hold the number of surviving mutants per module. CI SHALL fail when a module's count is higher than its budget. Each security invariant in the registry SHALL also have an entry in `ci/mutations.toml`.

#### Scenario: A change lets more mutants survive
- **WHEN** the nightly run finds more surviving mutants in a module than its budget
- **THEN** the job fails and lists the new survivors

#### Scenario: A survivor gets a test
- **WHEN** a test is added that kills a surviving mutant
- **THEN** the module's budget is lowered in the same change

#### Scenario: An invariant guard is removed
- **WHEN** the mutation spot-check removes the check behind a registered invariant
- **THEN** the named test fails

### Requirement: External pentest before the production-readiness claim
An external firm SHALL test a tagged build against a scope document that matches the shipped surface. Every Critical and High finding SHALL be fixed with a regression test and re-tested by the firm. Every Medium and Low finding SHALL have a tracked decision.

#### Scenario: The scope document is stale
- **WHEN** `docs/security-audit/pentest-scope.md` names a route or module path that does not exist
- **THEN** the scope is not ready, and the engagement does not start

#### Scenario: A High finding is open
- **WHEN** a Critical or High finding is not fixed and re-tested
- **THEN** the production-readiness claim is blocked

### Requirement: The production-readiness claim needs every gate
`README.md` and `docs/STATUS.md` SHALL NOT call Hearth production-ready until the conformance gate, the invariant registry, the mutation budget and the pentest gate all pass. The claim SHALL link to the evidence for each gate.

#### Scenario: A gate is open
- **WHEN** any gate in this capability has not passed
- **THEN** the README and `docs/STATUS.md` say Hearth is not yet production-ready, and name the open gate

#### Scenario: All gates pass
- **WHEN** every gate has passed
- **THEN** the claim links to the conformance report, the invariant test, the mutation budget and the pentest report

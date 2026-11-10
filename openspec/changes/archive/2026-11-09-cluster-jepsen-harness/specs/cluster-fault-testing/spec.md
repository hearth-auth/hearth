## ADDED Requirements

### Requirement: The harness tests a production-mode cluster
The Jepsen harness SHALL run five Hearth nodes, each in its own container, with one control container that drives them. Each node SHALL run `hearth serve` built without the `dev-endpoints` feature and started without `--dev`. Each node SHALL use the production storage sync mode, peer mTLS, HTTPS, and the same key-encryption key and `HEARTH_MASTER_KEY` as the other nodes. Each node configuration SHALL pass `hearth config validate` before the node starts.

#### Scenario: A configuration fails validation
- **WHEN** `hearth config validate` rejects a node's generated configuration
- **THEN** the run stops before any workload starts
- **AND** the run reports a setup error, not a consistency failure

#### Scenario: The harness is pointed at a dev binary
- **WHEN** the binary under test was built with the `dev-endpoints` feature
- **THEN** the harness refuses to start the run

### Requirement: The harness injects real faults
The harness SHALL be able to inject these faults: a network partition into a majority and a minority, a partition that isolates the current leader, `kill -9` of a minority of nodes, restart of a killed node from its data directory, and added delay on the peer links. Each test SHALL name the faults it uses.

#### Scenario: A killed node restarts from disk
- **WHEN** the harness kills a node with `kill -9` and then restarts it
- **THEN** the node starts from its existing data directory, not from an empty one

### Requirement: Client answers map to Jepsen outcomes
The harness client SHALL record each operation's outcome by this mapping:

| Hearth answer | Write | Read |
|---|---|---|
| `2xx` | `:ok` | `:ok` |
| `503` with `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN` | `:info` | not applicable |
| `503` with `HEARTH_CLUSTER_UNAVAILABLE` | `:fail` | `:fail` |
| Timeout or connection error | `:info` | `:fail` |
| Any other error | `:fail` | `:fail` |

The history SHALL keep the HTTP status and the Hearth error code of every failed or unknown operation.

#### Scenario: A write times out
- **WHEN** a write gets no answer before the client timeout
- **THEN** the history records it as `:info`
- **AND** the checker treats it as possibly applied

#### Scenario: An unavailable write is seen later
- **WHEN** a write recorded as `:fail` with `HEARTH_CLUSTER_UNAVAILABLE` is visible in a final read
- **THEN** the checker reports a W3 violation

### Requirement: Final reads follow a heal
After the last fault of a test, the harness SHALL remove every fault, restart every killed node, and wait until every node reports the same `last_applied_index` in `GET /admin/cluster/status`. Only then SHALL it run the test's final reads. If the nodes do not converge within the test's recovery timeout, the test result SHALL be invalid.

#### Scenario: The cluster does not converge
- **WHEN** one node's `last_applied_index` stays behind the others for longer than the recovery timeout
- **THEN** the test result is invalid
- **AND** the report names the node that did not converge

### Requirement: Every promise has a test or a stated reason
Each promise in the `cluster-consistency` capability SHALL have at least one harness test, or the test map in `docs/dev/CONSISTENCY.md` SHALL state why the harness cannot test it. Each open item (`G1`–`G9`) that Docker can exercise SHALL have a test expected to fail until the item is closed.

#### Scenario: A promise the harness cannot test
- **WHEN** a promise needs per-node clock skew, which containers on one kernel cannot produce
- **THEN** the test map names the promise and the reason
- **AND** no test claims to cover it

### Requirement: Results are classified as pass, fail, xfail or xpass
Each test SHALL have an expectation: `pass`, or `xfail` with exactly one G-id. A run SHALL classify each test result as follows:

| Expectation | Jepsen result | Run result |
|---|---|---|
| `pass` | valid | pass |
| `pass` | invalid or unknown | fail |
| `xfail` | invalid | xfail, with its G-id |
| `xfail` | valid | xpass, with its G-id, as a warning |

A run SHALL fail when any test result is fail. An xpass SHALL NOT fail the run.

#### Scenario: A required test fails
- **WHEN** a test expected to `pass` finds a lost acknowledged write
- **THEN** the run fails
- **AND** the run keeps the full history and the node logs of that test

#### Scenario: An expected failure fails
- **WHEN** the R2 test, expected `xfail` with `G1`, finds a stale read on a partitioned node
- **THEN** the run reports "xfail G1"
- **AND** the run does not fail because of it

#### Scenario: An expected failure passes
- **WHEN** a test expected `xfail` finds no violation
- **THEN** the run reports "xpass" with the G-id as a warning
- **AND** the run does not fail because of it

### Requirement: Closing a G-item promotes its test
A change that closes a G-item SHALL change the expectation of that item's tests from `xfail` to `pass`. The same change SHALL add the promise that the item unblocks to the `cluster-consistency` capability.

#### Scenario: G1 is closed
- **WHEN** a change makes partitioned nodes refuse reads
- **THEN** that change sets the R2 and V2 tests to `pass`
- **AND** it adds R2 and V2 to `cluster-consistency`

### Requirement: The checkers are proven before they are trusted
Each custom checker SHALL have a test on a hand-written history that contains a violation, and the checker SHALL report that violation. On the first full run against Hearth, each test expected `xfail` SHALL report xfail. An xfail test that passes on that first run SHALL be treated as a harness defect until it is explained.

#### Scenario: A checker misses a planted violation
- **WHEN** a checker's test history contains two successful redemptions of one artifact
- **AND** the checker reports the history as valid
- **THEN** the checker's test fails

### Requirement: When the harness runs
`make jepsen` SHALL build the binary and the containers and run every test. `make jepsen TEST=<name>` SHALL run one test. A CI workflow SHALL run all tests nightly and on manual dispatch. The workflow SHALL NOT be a required check for merging. It SHALL keep each run's histories, checker output and node logs as a CI artifact for 14 days.

#### Scenario: A nightly run fails
- **WHEN** a required test fails in the nightly workflow
- **THEN** the workflow run is marked failed
- **AND** the histories, checker output and node logs are downloadable from that run for 14 days

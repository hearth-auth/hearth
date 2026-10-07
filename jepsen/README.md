# Hearth Jepsen tests

These tests run [Jepsen](https://jepsen.io) against a 5-node, production-mode Hearth
cluster in Docker. They check the cluster-mode promises (W1–W5, R1, V1, …) in
[`docs/dev/CONSISTENCY.md`](../docs/dev/CONSISTENCY.md) under network partitions,
`kill -9`, restarts and peer-link delay.

The plan, the decisions and the open items are in the OpenSpec change
[`cluster-jepsen-harness`](../openspec/changes/cluster-jepsen-harness/).

> **Status:** in progress. The harness works end to end: setup, the four
> faults, heal-and-converge and result classification. The suite holds only
> the `noop` test so far; the consistency workloads (tasks 4 and 5) come next.

## Warning: privileged containers

The five node containers run with `privileged: true`. The partition and delay faults
change `iptables` and `tc` inside them, and that needs the privilege. A privileged
container can reach the host kernel. Run these tests only on your own machine or on
an ephemeral CI runner. **Never run them on a shared host.**

## What you need

- Docker with Compose v2 and BuildKit.
- About 8 GB of free memory: six containers and one JVM.
- The subnet `10.77.0.0/24` free on the host. The containers use fixed addresses
  in it, because `cluster.peer_address` must be an IP address. If it collides
  with a host network, change it in `docker/compose.yaml` and `node-ip-prefix`
  in `src/jepsen/hearth/db.clj`.
- Network access on the first run: the images, the cargo registry and the Jepsen
  libraries download once and are then cached.

## Run

From the repository root:

```bash
make jepsen                   # build, start the cluster, run every test in the suite
make jepsen TEST=noop         # one test (comma-separate several)
make jepsen TIME_LIMIT=60     # each test's fault phase in seconds (default 300)
make jepsen-down              # remove the containers and their volumes
```

`make jepsen` runs `make jepsen-binary` (build the shipped image, copy its hearth binary
to `jepsen/docker/.build/`) and `make jepsen-up` (start control and n1–n5, then
`ssh <node> true` on all five) first. It prints one line per test and exits 1 only when a
test FAILs. The format, with an illustrative xfail line:

```
PASS        noop
XFAIL G1    staleness
1 pass, 0 fail, 1 xfail, 0 xpass: run PASSED
```

The suite's tests, the promise each checks and its faults are listed in
`docs/dev/CONSISTENCY.md` section 9.

Each test's expectation is in `expectations.edn`: `:pass`, or `{:xfail "G<n>"}` for a
promise that an open item in `docs/dev/CONSISTENCY.md` breaks today. An xpass (an xfail
test that found no violation) is a warning, not a failure.

`make jepsen-binary` builds the root `Dockerfile`, so the tests run the binary the
published image ships: Debian bookworm, built without `dev-endpoints`. A run refuses
a binary that serves `/admin/bootstrap`.

To run a single test with your own faults, inside the control container:

```bash
docker compose -f jepsen/docker/compose.yaml exec control bash
jepsen-run test --workload noop --nemesis partition,kill --time-limit 60
ssh n1                                  # root on node n1
```

`jepsen-run test` takes only the options you give it. A suite test can add more: the
`snapshot` test raises `cluster.read_lag_threshold_ms`. To run a suite test as the suite
does, use `jepsen-run suite --only <name>`.

The faults are `partition` (majority/minority split), `partition-leader` (isolate the
current leader), `kill` (`kill -9` a minority, then restart) and `packet` (delay on the
node-to-node links). After the last fault, every test heals the cluster and waits until all
nodes report the same `last_applied_index`; a test whose nodes never agree is invalid.

## Layout

| Path | What it is |
|------|------------|
| `docker/` | Compose file, node image (bookworm, sshd, iptables, iproute2), control image (JDK 21, Leiningen) |
| `scripts/gen-material.sh` | Per-run secrets and certificates: KEK, master key, CA, peer and HTTPS leaves with `DNS:nX` |
| `scripts/gen-configs.sh` | One bundle per node for `/opt/hearth`: `hearth.yaml`, seed config, master key, TLS files |
| `scripts/seed-store.sh` | Seeds one store with an operator and mints a system-realm token into it |
| `scripts/spike-cold-cluster.sh` | The task 0.2 spike: the same seeding path on 3 host processes |
| `project.clj`, `src/`, `test/` | The Jepsen project; `lein test` runs its unit tests |
| `expectations.edn` | `:pass` or `{:xfail "G<n>"}` for each test in the suite |

## How a node is set up

Each node runs production mode: no `--dev`, no `dev-endpoints`, TLS on HTTPS and on
the peer link, fsync on. The control node:

1. generates fresh material for the run (`gen-material.sh`, `gen-configs.sh`);
2. seeds one store on `n1`: first-boot setup, email verification, then
   `hearth admin token` (`seed-store.sh`);
3. copies that store to every node and starts all five. The lowest-ID node forms the
   cluster.

## Reading results

Each run writes to `jepsen/store/<test-name>/<timestamp>/`. `store/latest` points at
the newest run.

| File | What it holds |
|------|---------------|
| `results.edn` | The checker verdict. `:valid? true` means the history is consistent. |
| `history.txt` | Every operation: `:invoke`, then `:ok`, `:fail` or `:info`. |
| `jepsen.log` | The control node's log, including every fault and when it happened. |
| `n1/` … `n5/` | Each node's `hearth.log`, downloaded at teardown. |
| `latency-raw.png`, `rate.png` | Latency and throughput, with fault periods shaded. |

Each Hearth answer maps to one outcome (design decision 6):

| Hearth answer | Write | Read |
|---|---|---|
| `2xx` | `:ok` | `:ok` |
| `503` `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN` | `:info` | — |
| `503` `HEARTH_CLUSTER_UNAVAILABLE` | `:fail` | `:fail` |
| Timeout, or connection broken during the request | `:info` | `:fail` |
| Connection refused (nothing sent) | `:fail` | `:fail` |
| Any other error | `:fail`, with the code in the history | `:fail` |

`:ok` means Hearth acknowledged the write. `:fail` means it did not happen. `:info`
means the outcome is unknown: the checkers allow the write to have happened or not.
A `:fail` write that later shows up breaks W3.

Some tests check a promise that Hearth does not keep yet. They are marked `xfail` with
a gap ID (`G1`, `G2`, …) from `docs/dev/CONSISTENCY.md`. Such a test reports `xfail`
when it finds the expected violation, and `xpass` when it does not.

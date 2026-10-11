# Artifacts: load test on AWS c7i.large, 2026-10-10

These files back every figure in [`../../2026-10-10-aws-c7i-large.md`](../../2026-10-10-aws-c7i-large.md).

## Folders

| Folder | Run |
|---|---|
| `environment/` | Instance inventory, disk sync test, user import, store size |
| `soak/` | 60-minute mix soak at 120 journeys/s, `main` `11960149` |
| `ramp-<feature>/` | One ramp per feature, `main` `11960149` |
| `soak-20261009-main-48378b06/` | 60-minute mix soak of 2026-10-09, `main` `48378b06` (comparison) |
| `soak-20261009-pr461-4a5bf893/` | 60-minute mix soak of 2026-10-09, PR #461 at `4a5bf893` (comparison) |
| `tables/` | The per-step and memory tables, as the scripts in [`../../scripts/`](../../scripts/) print them |

## Files in each run folder

| File | Content |
|---|---|
| `params.env` | Journey, offered start rate, step, number of steps, hold time per step, start time |
| `variant.txt` | Binary, commit, environment, restart time, `POST /admin/bootstrap` status |
| `report.md`, `report.json` | Per-step summary from the driver (all journeys together) |
| `summary-g1.json`, `summary-g2.json` | k6 end-of-test summary, one per generator |
| `sampler.csv.gz` | Server, one row per second: Hearth CPU ticks, RSS, threads, file descriptors, MemAvailable, disk writes, load |
| `gen-sampler-g1.csv.gz`, `gen-sampler-g2.csv.gz` | The same for the k6 process on each generator |
| `vmstat-gen1-*.txt.gz`, `vmstat-gen2-*.txt.gz` | `vmstat -n -t 5` on each generator (ramps of 2026-10-10 only) |
| `metrics-storage.txt.gz` | Hearth `/metrics`, every 5 s: hot-tier entries and evictions, memtable bytes and entries, SST files, KDF gate gauges and `hearth_kdf_compute_seconds`. Lines are `<unix ts> <metric> <value>`. |

## Not committed

- The k6 raw CSVs (`raw-g1.csv.gz`, `raw-g2.csv.gz`, about 500 MB for this round). `tables/ramps.txt` is the output of `scripts/ramps.py` on them.
- The Hearth logs.
- The k6 script and the AWS driver. They are not in this repository yet.

## How to read the Argon2id time per hash

Take two lines of `hearth_kdf_compute_seconds_sum` and `hearth_kdf_compute_seconds_count` from `metrics-storage.txt.gz`. The time per hash is (sum₂ − sum₁) ÷ (count₂ − count₁).

# Performance results

This folder is the source of record for every performance figure that Hearth publishes. The figures in the README and in the guides come from a report here.

## Reports

| Date | Report | Build | Server | Plane |
|---|---|---|---|---|
| 2026-10-10 | [Load test on AWS c7i.large](2026-10-10-aws-c7i-large.md): the limit of each feature, and a 60-minute soak | `11960149` (v3.4.0) | AWS c7i.large, 2 vCPU, 3.8 GB | Network |

## Rules for a report

The rules in [`docs/dev/perf-framing-rule.md`](../dev/perf-framing-rule.md) and in [`loadtest/README.md`](../../loadtest/README.md) § "Artifact contract and admissibility rules" apply. In short:

1. Name each report `<date>-<server>.md`.
2. Give the build commit. It must be on `main`.
3. Give the measurement plane: engine, HTTP or network (see the framing rule).
4. Give the hardware and the configuration that change the result, for example the Argon2id parameters.
5. Put the files that back each figure in `artifacts/<date>-<server>/`, with a `README.md` that says what each file is.
6. Put the analysis scripts in `scripts/`, so that a reader can recompute each table.
7. Do not edit an old report to show new numbers. Add a new report, and update this table.

## Earlier results

The engine-plane and loopback figures of July 2026 (`PUBLISHED_FIGURES.md`, `PERFORMANCE_REPORT_2_1.md` and their artifacts) were removed on 2026-10-10. They predate many changes to the read and write paths. They are in the git history at [`3981837a`](https://github.com/hearth-auth/hearth/tree/3981837a75422969959d23b4324c81a61e0efc2f/docs/perf).

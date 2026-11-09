#!/usr/bin/env python3
"""Fail when a module has more surviving mutants than its budget.

Usage:
    python3 scripts/check-mutants-budget.py [--budget FILE] [--summary FILE] RESULTS_DIR
    python3 scripts/check-mutants-budget.py [--budget FILE] --check-config

The scheduled mutation run (#641, OpenSpec trusted-core-confidence task 4.1)
runs `cargo mutants` on each module of `ci/mutants-budget.toml`, in shards.
Each shard job writes one directory with two files:

- `shard.txt`: one line, `<module> <k> <n>` (shard k of n, k from 0).
- `outcomes.json`: the `mutants.out/outcomes.json` of that shard.

RESULTS_DIR holds these directories, at any depth. This script adds the
missed mutants (the survivors) of all shards of each module and compares the
sum with the module's `survivors` budget:

- More survivors than the budget: FAIL. A change made the tests miss more.
- Fewer survivors than the budget: pass, and the message tells you to lower
  the budget to the new count. The budget only goes down.
- No `survivors` key for a module: FAIL. A budget that is not recorded can
  never pass. The message gives the count to record (design Open Question 3:
  the budget starts at the first-run count).

The check also FAILS when a result cannot be trusted: a module has no
result, a shard is missing or reported twice, the shards of a module disagree
on the shard count, a shard did not finish, a shard's baseline (the unmutated
tree) failed, or a mutant is in a file that no module names. A missing shard
must not look like fewer survivors.

`--check-config` reads only the budget file: it must parse, and the `files`
globs of each module must match at least one file in this repository. This
is the cheap half that runs on every PR; it needs no mutation run.

Timeouts are not survivors. They are counted and shown, but no budget
applies to them.
"""

import argparse
import fnmatch
import json
import os
import sys
import tomllib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BUDGET = os.path.join(REPO_ROOT, "ci", "mutants-budget.toml")


def load_budget(path):
    """Read the budget file and return {module: config}; exit 1 when it is bad."""
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        sys.exit(f"FAIL: cannot read the budget file {path}: {exc}")
    modules = data.get("modules")
    if not isinstance(modules, dict) or not modules:
        sys.exit(f"FAIL: {path} has no [modules.<name>] tables")
    for name, cfg in modules.items():
        files = cfg.get("files")
        if not isinstance(files, list) or not files or not all(isinstance(f, str) for f in files):
            sys.exit(f"FAIL: module {name}: `files` must be a non-empty list of globs")
        if "survivors" in cfg:
            s = cfg["survivors"]
            if not isinstance(s, int) or isinstance(s, bool) or s < 0:
                sys.exit(f"FAIL: module {name}: `survivors` must be a non-negative integer")
    return modules


def module_of(path, modules):
    """Return the module whose `files` globs match path, or None."""
    for name, cfg in modules.items():
        for pattern in cfg["files"]:
            prefix = pattern[:-3] if pattern.endswith("/**") else None
            if (prefix and path.startswith(prefix + "/")) or fnmatch.fnmatchcase(path, pattern):
                return name
    return None


def check_config(modules):
    """Fail when a module's `files` globs match no file in the repository."""
    sources = []
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "src")):
        dirs.sort()
        rel = os.path.relpath(root, REPO_ROOT)
        sources.extend(os.path.join(rel, f).replace(os.sep, "/") for f in files)
    bad = [n for n in modules if not any(module_of(p, {n: modules[n]}) for p in sources)]
    for name in bad:
        print(f"FAIL: module {name}: `files` matches no file under src/")
    if bad:
        return 1
    print(f"PASS: {len(modules)} modules, each `files` glob matches a source file")
    return 0


def find_shards(results_dir):
    """Yield (dir, module, k, n) for every shard.txt under results_dir."""
    for root, _dirs, files in os.walk(results_dir):
        if "shard.txt" not in files:
            continue
        with open(os.path.join(root, "shard.txt"), encoding="utf-8") as fh:
            parts = fh.read().split()
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            yield root, None, None, None
            continue
        yield root, parts[0], int(parts[1]), int(parts[2])


def main():
    """Run the check and return the process exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--budget", default=DEFAULT_BUDGET)
    parser.add_argument("--summary", help="append a Markdown table to this file")
    parser.add_argument("--check-config", action="store_true", help="check the budget file only")
    parser.add_argument("results_dir", nargs="?")
    args = parser.parse_args()

    modules = load_budget(args.budget)
    if args.check_config:
        return check_config(modules)
    if args.results_dir is None:
        parser.error("RESULTS_DIR is required without --check-config")
    errors = []
    seen = {name: {} for name in modules}
    shard_counts = {name: set() for name in modules}
    missed = {name: [] for name in modules}
    timeouts = {name: 0 for name in modules}
    tested = {name: 0 for name in modules}

    for shard_dir, module, k, n in find_shards(args.results_dir):
        if module is None:
            errors.append(f"{shard_dir}/shard.txt is not `<module> <k> <n>`")
            continue
        if module not in modules:
            errors.append(f"{shard_dir}: module {module} is not in the budget file")
            continue
        if k >= n:
            errors.append(f"{shard_dir}: shard {k}/{n} of {module} is out of range")
            continue
        shard_counts[module].add(n)
        if k in seen[module]:
            errors.append(f"{module}: shard {k}/{n} is reported twice")
            continue
        seen[module][k] = shard_dir
        try:
            with open(os.path.join(shard_dir, "outcomes.json"), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{module}: shard {k}/{n} has no readable outcomes.json: {exc}")
            continue
        if not data.get("end_time"):
            errors.append(f"{module}: shard {k}/{n} did not finish (no end_time)")
            continue
        for outcome in data.get("outcomes", []):
            scenario = outcome.get("scenario")
            summary = outcome.get("summary")
            if scenario == "Baseline":
                if summary != "Success":
                    errors.append(f"{module}: shard {k}/{n}: the unmutated tree failed ({summary})")
                continue
            mutant = scenario.get("Mutant", {}) if isinstance(scenario, dict) else {}
            path = mutant.get("file", "")
            owner = module_of(path, modules)
            if owner != module:
                errors.append(f"{module}: shard {k}/{n}: mutant in {path!r}, not in this module")
                continue
            tested[module] += 1
            if summary == "MissedMutant":
                missed[module].append(mutant.get("name", path))
            elif summary == "Timeout":
                timeouts[module] += 1

    for name in modules:
        counts = shard_counts[name]
        if not counts:
            errors.append(f"{name}: no shard reported a result")
            continue
        if len(counts) > 1:
            errors.append(f"{name}: shards disagree on the shard count: {sorted(counts)}")
            continue
        n = counts.pop()
        absent = sorted(set(range(n)) - set(seen[name]))
        if absent:
            errors.append(
                f"{name}: no result for shard(s) {', '.join(str(k) for k in absent)} of {n}"
            )

    rows = []
    for name, cfg in modules.items():
        count = len(missed[name])
        budget = cfg.get("survivors")
        if budget is None:
            verdict = "FAIL"
            errors.append(
                f"{name}: no budget is recorded. This run has {count} survivors. "
                f"Record `survivors = {count}` under [modules.{name}] in ci/mutants-budget.toml"
            )
        elif count > budget:
            verdict = "FAIL"
            errors.append(
                f"{name}: {count} survivors, budget {budget} (+{count - budget}). "
                f"Add tests that catch the new survivors (see missed.txt in the artifacts)"
            )
        elif count < budget:
            verdict = "ok, lower the budget"
            print(
                f"note: {name}: {count} survivors, budget {budget}. "
                f"Lower the budget to {count} in ci/mutants-budget.toml"
            )
        else:
            verdict = "ok"
        rows.append((name, tested[name], count, "-" if budget is None else budget, timeouts[name], verdict))

    for name, tested_n, count, budget, timeout_n, verdict in rows:
        print(f"{name}: tested {tested_n}, survivors {count}, budget {budget}, "
              f"timeouts {timeout_n}: {verdict}")

    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write("| module | mutants tested | survivors | budget | timeouts | verdict |\n")
            fh.write("| --- | --- | --- | --- | --- | --- |\n")
            for row in rows:
                fh.write("| " + " | ".join(str(c) for c in row) + " |\n")
            for err in errors:
                fh.write(f"\n- FAIL: {err}")
            fh.write("\n")

    if errors:
        for err in errors:
            print(f"FAIL: {err}")
        return 1
    print("PASS: no module has more survivors than its budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())

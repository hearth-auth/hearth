#!/usr/bin/env python3
"""Fail when a module has more surviving mutants than its budget.

Usage:
    python3 scripts/check-mutants-budget.py [--budget FILE] [--summary FILE] RESULTS_DIR
    python3 scripts/check-mutants-budget.py [--budget FILE] --check-config
    python3 scripts/check-mutants-budget.py [--budget FILE] --matrix
    python3 scripts/check-mutants-budget.py [--budget FILE] --mutants-args MODULE

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
result, a shard is missing or reported twice, a shard count is not the one
in the budget file, a shard did not finish, a shard's baseline (the unmutated
tree) failed, or a mutant is not in its module or is in two modules. A missing shard
must not look like fewer survivors.

A module in the budget file has these keys:

- `files`: cargo-mutants `--file` globs.
- `re` (optional): cargo-mutants `--re` regexes. A mutant is in the module
  only when its name (`<file>:<line>:<col>: <change>`) matches one of them.
  Use plain regex syntax that Rust and Python read the same way.
- `tests` (optional): integration test binaries (`tests/<name>.rs`). Each
  mutant runs the lib tests and these binaries.
- `shards`: the number of parallel jobs for the module.
- `survivors`: the budget. Absent until the first run.

`--check-config` reads only the budget file: it must parse, the `files` globs
of each module must match a file in this repository, each `re` must compile,
and each `tests` binary must exist. This is the cheap half that runs on every
PR; it needs no mutation run.

`--matrix` prints the GitHub Actions matrix (`{"include": [...]}`, one entry
for each shard). `--mutants-args MODULE` prints the cargo-mutants arguments
for the module, one on each line. The workflow uses both, so the budget file
is the only place that defines a module.

cargo-mutants 27.1.0 does not apply `--re` to "delete field" mutants. A
mutant in a module's files that matches no `re` of any module is not in the
module: it is counted apart and not checked against the budget. The same
applies to a "delete field" mutant (genre StructField) that is in another
module: only that module counts it.

Timeouts are not survivors. They are counted and shown, but no budget
applies to them.
"""

import argparse
import fnmatch
import json
import os
import re
import sys
import tomllib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BUDGET = os.path.join(REPO_ROOT, "ci", "mutants-budget.toml")
# A nextest filterset: the tests that each mutant runs.
#
# Not in it:
# - The storage and cluster lib tests (see mutants_args).
# - verify_nonexistent_user_takes_comparable_time. It compares two password
#   checks by wall-clock time, and under the load of a mutants run it fails
#   for about 1 mutant in 30 that it cannot catch (#641). Each such failure
#   counts as caught, so it hides survivors at random.
LIB_TEST_FILTER = (
    "not (kind(lib) and (test(/^(storage|cluster)::/)"
    " or test(=identity::engine::tests::verify_nonexistent_user_takes_comparable_time)))"
)


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
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            sys.exit(f"FAIL: module {name}: the name must be lower-case letters, digits and -")
        for key, required in (("files", True), ("re", False), ("tests", False)):
            value = cfg.get(key)
            if value is None and not required:
                continue
            if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
                sys.exit(f"FAIL: module {name}: `{key}` must be a non-empty list of strings")
        try:
            cfg["_re"] = [re.compile(r) for r in cfg.get("re", [])]
        except re.error as exc:
            sys.exit(f"FAIL: module {name}: a `re` does not compile: {exc}")
        shards = cfg.get("shards")
        if not isinstance(shards, int) or isinstance(shards, bool) or shards < 1:
            sys.exit(f"FAIL: module {name}: `shards` must be a positive integer")
        if "survivors" in cfg:
            s = cfg["survivors"]
            if not isinstance(s, int) or isinstance(s, bool) or s < 0:
                sys.exit(f"FAIL: module {name}: `survivors` must be a non-negative integer")
    return modules


def file_in(path, cfg):
    """True when path matches one of the module's `files` globs."""
    for pattern in cfg["files"]:
        prefix = pattern[:-3] if pattern.endswith("/**") else None
        if (prefix and path.startswith(prefix + "/")) or fnmatch.fnmatchcase(path, pattern):
            return True
    return False


def modules_of(path, mutant_name, modules):
    """Return the names of the modules that hold this mutant."""
    return [
        name
        for name, cfg in modules.items()
        if file_in(path, cfg) and (not cfg["_re"] or any(r.search(mutant_name) for r in cfg["_re"]))
    ]


def check_config(modules):
    """Fail when a module names a source file or a test binary that does not exist."""
    sources = []
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "src")):
        dirs.sort()
        rel = os.path.relpath(root, REPO_ROOT)
        sources.extend(os.path.join(rel, f).replace(os.sep, "/") for f in files)
    bad = 0
    for name, cfg in modules.items():
        if not any(file_in(p, cfg) for p in sources):
            print(f"FAIL: module {name}: `files` matches no file under src/")
            bad += 1
        for test in cfg.get("tests", []):
            if not os.path.isfile(os.path.join(REPO_ROOT, "tests", f"{test}.rs")):
                print(f"FAIL: module {name}: test binary tests/{test}.rs does not exist")
                bad += 1
    if bad:
        return 1
    print(f"PASS: {len(modules)} modules; every `files` glob and `tests` binary exists")
    return 0


def matrix(modules):
    """Print the GitHub Actions matrix: one entry for each shard of each module."""
    include = [
        {"module": name, "shard": k, "shards": cfg["shards"]}
        for name, cfg in modules.items()
        for k in range(cfg["shards"])
    ]
    print(json.dumps({"include": include}, separators=(",", ":")))
    return 0


def mutants_args(modules, name):
    """Print the cargo-mutants arguments for one module, one on each line."""
    if name not in modules:
        print(f"FAIL: module {name} is not in the budget file")
        return 1
    cfg = modules[name]
    args = []
    for pattern in cfg["files"]:
        args += ["--file", pattern]
    for regex in cfg.get("re", []):
        args += ["--re", regex]
    args += ["--cargo-arg=--lib"]
    for test in cfg.get("tests", []):
        args += ["--cargo-arg=--test", f"--cargo-arg={test}"]
    # The storage and cluster layers sit below identity and rbac and must not
    # import them (docs/dev/ARCHITECTURE.md), so their lib tests cannot catch
    # a mutant in these modules. Skipping them saves about a third of the
    # test time of each mutant.
    args += ["--", "-E", LIB_TEST_FILTER]
    print("\n".join(args))
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
    parser.add_argument("--matrix", action="store_true", help="print the shard matrix")
    parser.add_argument("--mutants-args", metavar="MODULE", help="print cargo-mutants arguments")
    parser.add_argument("results_dir", nargs="?")
    args = parser.parse_args()

    modules = load_budget(args.budget)
    if args.check_config:
        return check_config(modules)
    if args.matrix:
        return matrix(modules)
    if args.mutants_args:
        return mutants_args(modules, args.mutants_args)
    if args.results_dir is None:
        parser.error("RESULTS_DIR is required without --check-config, --matrix or --mutants-args")
    errors = []
    seen = {name: {} for name in modules}
    missed = {name: [] for name in modules}
    timeouts = {name: 0 for name in modules}
    tested = {name: 0 for name in modules}
    outside_re = {name: 0 for name in modules}

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
        if n != modules[module]["shards"]:
            errors.append(
                f"{module}: shard {k}/{n}, but the budget file says {modules[module]['shards']} shards"
            )
            continue
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
            mutant_name = mutant.get("name", "")
            owners = modules_of(path, mutant_name, modules)
            delete_field = mutant.get("genre") == "StructField"
            if (
                module not in owners
                and file_in(path, modules[module])
                and (not owners or delete_field)
            ):
                # cargo-mutants 27.1.0 does not apply `--re` to "delete field"
                # mutants, so the run tests some mutants outside the module's
                # `re`, also some of another module's functions. They are not
                # in this module: count them apart. The other module's run
                # tests and counts its own.
                outside_re[module] += 1
                continue
            if owners != [module]:
                where = " and ".join(owners) if owners else "no module"
                errors.append(f"{module}: shard {k}/{n}: mutant {mutant_name!r} is in {where}")
                continue
            tested[module] += 1
            if summary == "MissedMutant":
                missed[module].append(mutant_name)
            elif summary == "Timeout":
                timeouts[module] += 1

    for name, cfg in modules.items():
        if not seen[name]:
            errors.append(f"{name}: no shard reported a result")
            continue
        n = cfg["shards"]
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
        if outside_re[name]:
            print(f"note: {name}: {outside_re[name]} mutants outside `re` are not counted")
        for mutant_name in missed[name]:
            print(f"  survivor: {mutant_name}")

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

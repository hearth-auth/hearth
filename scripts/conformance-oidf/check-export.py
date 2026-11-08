"""Summarise and check the suite's export for scripts/conformance-oidf.sh.

The suite's runner exports one zip for each plan. This script reads the test
logs in each zip and:

  * prints, for each plan, the number of test modules for each result and the
    number of conditions for each result (the numbers for the run report);
  * prints each WARNING and FAILURE condition (module, block, condition);
  * checks each warning that expected-warnings.json lists with an
    "unknown-properties" key: the warning must name only those properties.
    The runner matches an expected warning by condition name only, so without
    this check a new unregistered metadata field would hide behind the
    recorded decision for an old one.

Exit 0 when the checks pass, 1 when they do not. Run with `python3 -I`.
Standard library only.
"""

import argparse
import collections
import fnmatch
import json
import pathlib
import sys
import zipfile


def logs_in(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        for name in sorted(z.namelist()):
            if name.endswith(".json") and "test-log-" in name:
                yield json.loads(z.read(name))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", required=True, help="the runner's export dir")
    ap.add_argument("--expected", required=True, help="the run's expected-warnings.json")
    args = ap.parse_args()

    expected = json.loads(pathlib.Path(args.expected).read_text())
    zips = sorted(pathlib.Path(args.export).glob("*.zip"))
    if not zips:
        print("check-export: no exported plan results")
        return 1

    bad = 0
    for zip_path in zips:
        plan = zip_path.name.split("--")[0]
        modules = collections.Counter()
        conditions = collections.Counter()
        findings = []
        for log in logs_in(zip_path):
            info = log["testInfo"]
            modules[info.get("result") or info.get("status")] += 1
            for entry in log.get("results", []):
                result = entry.get("result")
                if result in ("SUCCESS", "FAILURE", "WARNING"):
                    conditions[result] += 1
                if result not in ("FAILURE", "WARNING"):
                    continue
                findings.append((result, info["testName"], entry.get("src"),
                                 entry.get("msg", "")[:160]))
                props = sorted(p.get("property") for p in entry.get("unknown_properties") or [])
                for e in expected:
                    allowed = e.get("unknown-properties")
                    if (allowed is not None and result == "WARNING"
                            and e["condition"] == entry.get("src")
                            and fnmatch.fnmatch(info["testName"], e["test-name"])):
                        extra = [p for p in props if p not in allowed]
                        if extra:
                            print(f"check-export: FAIL {info['testName']}: "
                                  f"{entry.get('src')} names {extra}, which have no recorded decision")
                            bad = 1

        print(f"plan {plan}")
        print("  modules:    " + ", ".join(f"{k} {v}" for k, v in sorted(modules.items())))
        print("  conditions: " + ", ".join(f"{k} {conditions[k]}"
                                           for k in ("SUCCESS", "FAILURE", "WARNING")))
        for result, module, src, msg in findings:
            print(f"  {result:7} {module}: {src}: {msg}")
    return bad


if __name__ == "__main__":
    sys.exit(main())

"""Render the OIDF plan configs for one run of scripts/conformance-oidf.sh.

Reads plans/<plan>.json from the config dir, replaces each ${NAME} with a
value from the run's env file (or a derived value below), puts the shared
browser steps (plans/browser.json) where a plan says "@browser.json", and
writes the result to the output dir. It also writes expected-warnings.json
with only the entries for the plans of this run: the suite's runner fails a
run when an entry matches no test, and that check must stay on for the plans
that run.

Run with `python3 -I`. Standard library only.
"""

import argparse
import fnmatch
import json
import pathlib
import re
import sys
import uuid

# src/identity/reconcile.rs APP_NAMESPACE: a YAML application's client_id is
# UUIDv5(APP_NAMESPACE, "<realm>/<slug>").
APP_NAMESPACE = uuid.UUID(bytes=bytes([
    0x8B, 0x07, 0x4E, 0x8C, 0x3E, 0x6A, 0x5A, 0x8E,
    0x96, 0x1D, 0x8F, 0x2B, 0xAA, 0xE7, 0x1B, 0xF4,
]))
REALM = "conformance"
PLACEHOLDER = re.compile(r"\$\{([A-Z0-9_]+)\}")


def read_env(path):
    values = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value
    return values


def substitute(node, values):
    if isinstance(node, str):
        def repl(m):
            if m.group(1) not in values:
                sys.exit(f"render-plans: no value for ${{{m.group(1)}}}")
            return values[m.group(1)]
        return PLACEHOLDER.sub(repl, node)
    if isinstance(node, list):
        return [substitute(x, values) for x in node]
    if isinstance(node, dict):
        return {k: substitute(v, values) for k, v in node.items()}
    return node


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config-dir", required=True)
    ap.add_argument("--env-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--plans", nargs="+", required=True)
    args = ap.parse_args()

    cfg = pathlib.Path(args.config_dir)
    out = pathlib.Path(args.out)
    values = read_env(args.env_file)
    values["OIDF_CLIENT_ID"] = str(uuid.uuid5(APP_NAMESPACE, f"{REALM}/oidf-client"))
    values["OIDF_CLIENT2_ID"] = str(uuid.uuid5(APP_NAMESPACE, f"{REALM}/oidf-client2"))
    browser = json.loads((cfg / "plans" / "browser.json").read_text())

    for plan in args.plans:
        doc = json.loads((cfg / "plans" / f"{plan}.json").read_text())
        if doc.get("browser") == "@browser.json":
            doc["browser"] = browser
        doc = substitute(doc, values)
        (out / f"{plan}.json").write_text(json.dumps(doc, indent=2) + "\n")

    # The runner matches "configuration-filename" against the path it was given.
    names = [f"/run-dir/plans/{plan}.json" for plan in args.plans]
    expected = json.loads((cfg / "expected-warnings.json").read_text())
    for entry in expected:
        if entry.get("expected-result") != "warning":
            sys.exit("render-plans: expected-warnings.json may list warnings only; "
                     "a failed condition always fails the run")
        if not entry.get("decision"):
            sys.exit(f"render-plans: entry for {entry.get('condition')} has no decision")
    kept = [e for e in expected
            if any(fnmatch.fnmatch(n, e["configuration-filename"]) for n in names)]
    (out / "expected-warnings.json").write_text(json.dumps(kept, indent=2) + "\n")


if __name__ == "__main__":
    main()

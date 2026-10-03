#!/usr/bin/env python3
"""Write the admin subset of docs/api/openapi.json for the SDK generators.

Usage:
    python3 scripts/admin_openapi.py OUT.json

Keeps every `/admin/...` path and only the component schemas those paths
reach, so each SDK's generated admin client carries no OAuth, SCIM or OIDC
surface. The output is sorted, so the generators see the same input on every
machine.
"""

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(REPO_ROOT, "docs", "api", "openapi.json")
REF_PREFIX = "#/components/schemas/"


def refs(node, out: set) -> None:
    """Collect every component-schema name referenced under `node`."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith(REF_PREFIX):
            out.add(ref[len(REF_PREFIX):])
        for value in node.values():
            refs(value, out)
    elif isinstance(node, list):
        for value in node:
            refs(value, out)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(SPEC) as f:
        spec = json.load(f)

    paths = {p: item for p, item in spec["paths"].items() if p.startswith("/admin/")}
    schemas = spec.get("components", {}).get("schemas", {})

    keep: set = set()
    refs(paths, keep)
    pending = list(keep)
    while pending:
        found: set = set()
        refs(schemas[pending.pop()], found)
        pending.extend(found - keep)
        keep |= found

    components = dict(spec.get("components", {}))
    components["schemas"] = {name: schemas[name] for name in sorted(keep)}
    out = {
        "openapi": spec["openapi"],
        "info": {**spec["info"], "title": "Hearth Admin API"},
        "paths": dict(sorted(paths.items())),
        "components": components,
    }
    if "security" in spec:
        out["security"] = spec["security"]

    with open(sys.argv[1], "w") as f:
        json.dump(out, f, indent=2, sort_keys=False)
        f.write("\n")


if __name__ == "__main__":
    main()

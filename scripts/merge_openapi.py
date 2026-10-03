#!/usr/bin/env python3
"""Merge Swagger 2.0 (proto-derived) + OpenAPI 3.0 (supplement) → openapi.json.

Usage:
    python3 scripts/merge_openapi.py [--out docs/api/openapi.json]

The proto-derived Swagger 2.0 paths are converted to OpenAPI 3.0 format and
merged with the hand-written supplement.  Supplement paths take precedence
when both files define the same path.  The output is a single OpenAPI 3.0
document committed at docs/api/openapi.json and embedded by the binary.
"""

import argparse
import copy
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(REPO_ROOT, "docs", "api", "openapi.json")
PROTO_DERIVED = os.path.join(REPO_ROOT, "docs", "api", "openapi_proto_derived.swagger.json")
SUPPLEMENT = os.path.join(REPO_ROOT, "docs", "api", "openapi.supplement.yaml")


def upgrade_ref(ref: str) -> str:
    """Convert Swagger 2.0 $ref to OpenAPI 3.0."""
    return ref.replace("#/definitions/", "#/components/schemas/")


def upgrade_schema(schema: dict) -> dict:
    """Recursively rewrite $ref in a schema object.

    The proto3 JSON mapping writes 64-bit integers as strings, and the Swagger
    says so. The REST handlers send numbers (`proto_to_rest_json` turns every
    integer-like string into a JSON number), so 64-bit fields become integers.
    """
    if not isinstance(schema, dict):
        return schema
    if schema.get("type") == "string" and schema.get("format") in ("int64", "uint64"):
        schema = {**schema, "type": "integer", "format": "int64"}
    out = {}
    for k, v in schema.items():
        if k == "$ref" and isinstance(v, str):
            out[k] = upgrade_ref(v)
        elif isinstance(v, dict):
            out[k] = upgrade_schema(v)
        elif isinstance(v, list):
            out[k] = [upgrade_schema(i) if isinstance(i, dict) else i for i in v]
        else:
            out[k] = v
    return out


def upgrade_response(resp: dict) -> dict:
    """Convert a Swagger 2.0 response object to OpenAPI 3.0."""
    out = {"description": resp.get("description", "")}
    if "schema" in resp:
        out["content"] = {
            "application/json": {"schema": upgrade_schema(resp["schema"])}
        }
    return out


# Swagger 2.0 keeps a non-body parameter's type inline; OpenAPI 3.0 moves it
# under `schema`. Generators reject the inline form.
PARAM_SCHEMA_KEYS = (
    "type", "format", "items", "enum", "default", "minimum", "maximum",
    "pattern", "minLength", "maxLength",
)


def upgrade_parameter(param: dict) -> dict:
    """Convert a Swagger 2.0 non-body parameter to OpenAPI 3.0."""
    out = {k: v for k, v in param.items() if k not in PARAM_SCHEMA_KEYS}
    out.pop("collectionFormat", None)
    if "schema" in param:
        out["schema"] = upgrade_schema(param["schema"])
    else:
        out["schema"] = {
            k: upgrade_schema(v) if isinstance(v, dict) else v
            for k, v in param.items()
            if k in PARAM_SCHEMA_KEYS
        }
    if param.get("collectionFormat") == "multi":
        out["explode"] = True
    return out


def upgrade_operation(op: dict) -> dict:
    """Convert a Swagger 2.0 operation to OpenAPI 3.0."""
    out: dict = {}
    for key in ("operationId", "summary", "description", "tags", "deprecated"):
        if key in op:
            out[key] = op[key]

    # Parameters: split body vs non-body
    body_param = None
    params = []
    for p in op.get("parameters", []):
        if p.get("in") == "body":
            body_param = p
        else:
            params.append(upgrade_parameter(p))
    if params:
        out["parameters"] = params

    # Body parameter → requestBody
    if body_param and "schema" in body_param:
        out["requestBody"] = {
            "required": body_param.get("required", True),
            "content": {
                "application/json": {
                    "schema": upgrade_schema(body_param["schema"])
                }
            },
        }

    # Responses
    if "responses" in op:
        out["responses"] = {
            code: upgrade_response(r) for code, r in op["responses"].items()
        }

    return out


def upgrade_path_item(item: dict) -> dict:
    """Convert all HTTP method operations in a path item to OpenAPI 3.0."""
    methods = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
    out = {}
    for key, val in item.items():
        if key in methods:
            out[key] = upgrade_operation(val)
        else:
            out[key] = val
    return out


def convert_swagger2_to_openapi3(swagger: dict) -> dict:
    """Minimal Swagger 2.0 → OpenAPI 3.0 conversion (paths + schemas only)."""
    out: dict = {
        "openapi": "3.0.3",
        "info": swagger.get("info", {"title": "Hearth API", "version": "0.1.0"}),
    }

    # Servers block from Swagger 2.0 host/basePath
    base_path = swagger.get("basePath", "/")
    if base_path and base_path != "/":
        out["servers"] = [{"url": base_path}]

    # Upgrade paths
    paths = {}
    for path, item in swagger.get("paths", {}).items():
        paths[path] = upgrade_path_item(item)
    out["paths"] = paths

    # Move definitions → components/schemas (rewrite $refs inside)
    if "definitions" in swagger:
        out["components"] = {
            "schemas": {
                name: upgrade_schema(schema)
                for name, schema in swagger["definitions"].items()
            }
        }

    return out


def merge_paths(base: dict, overlay: dict) -> dict:
    """Overlay paths over base; overlay wins on conflict."""
    merged = dict(base)
    merged.update(overlay)
    return dict(sorted(merged.items()))


def omit_operations(paths: dict, operation_ids: list) -> dict:
    """Drop the operations whose operationId is listed; drop emptied paths.

    Fails when a listed operationId matches nothing, so the supplement's
    `x-hearth-omit-operations` list cannot silently go stale.
    """
    methods = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
    wanted = set(operation_ids)
    found = set()
    out = {}
    for path, item in paths.items():
        kept = {}
        for key, val in item.items():
            op_id = val.get("operationId") if key in methods and isinstance(val, dict) else None
            if op_id in wanted:
                found.add(op_id)
                continue
            kept[key] = val
        if any(k in methods for k in kept):
            out[path] = kept
    missing = wanted - found
    if missing:
        sys.exit(f"x-hearth-omit-operations: no operation matches {sorted(missing)}")
    return out


def rename_success(paths: dict, operation_ids: list, status: str, key: str) -> dict:
    """Rename the `200` response of each listed operation to `status`.

    protoc-gen-openapiv2 documents every success as `200`; these operations
    answer `201 Created` or `204 No Content`. A `204` keeps no body. Fails
    when a listed operationId has no `200`, so the supplement list cannot go
    stale (`key` names the list in the error).
    """
    wanted = set(operation_ids)
    found = set()
    for item in paths.values():
        for op in item.values():
            if isinstance(op, dict) and op.get("operationId") in wanted:
                responses = op.get("responses", {})
                if "200" in responses:
                    found.add(op["operationId"])
                    ok = dict(responses.pop("200"))
                    if status == "204":
                        ok.pop("content", None)
                        ok["description"] = ok.get("description") or "No Content"
                    responses[status] = ok
                    op["responses"] = dict(sorted(responses.items()))
    missing = wanted - found
    if missing:
        sys.exit(f"{key}: no `200` operation matches {sorted(missing)}")
    return paths


def patch_schemas(schemas: dict, patches: dict) -> dict:
    """Merge each property patch into the named proto-derived schema.

    For facts the proto cannot express (a string enum on a plain `string`
    field). Fails when a patch names a schema or property that does not exist.
    """
    for name, patch in patches.items():
        if name not in schemas:
            sys.exit(f"x-hearth-schema-patches: no schema {name}")
        props = schemas[name].get("properties", {})
        for prop, fields in patch.get("properties", {}).items():
            if prop not in props:
                sys.exit(f"x-hearth-schema-patches: no property {name}.{prop}")
            props[prop].update(fields)
    return schemas


def merge_components(base: dict | None, overlay: dict | None) -> dict:
    """Merge components sections (schemas, securitySchemes, etc.)."""
    out: dict = {}
    for section in ("schemas", "securitySchemes", "parameters", "responses", "examples"):
        b = (base or {}).get(section, {})
        o = (overlay or {}).get(section, {})
        if b or o:
            merged = dict(b)
            merged.update(o)
            out[section] = merged
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=DEFAULT_OUT, help="Output path")
    parser.add_argument(
        "--proto-derived", default=PROTO_DERIVED, help="Swagger 2.0 input"
    )
    parser.add_argument(
        "--supplement", default=SUPPLEMENT, help="OpenAPI 3.0 supplement YAML"
    )
    args = parser.parse_args()

    with open(args.proto_derived) as f:
        swagger2 = json.load(f)

    with open(args.supplement) as f:
        supplement = yaml.safe_load(f)

    # Convert proto-derived Swagger 2.0 → OpenAPI 3.0
    proto_oas3 = convert_swagger2_to_openapi3(swagger2)
    for status, key in (
        ("201", "x-hearth-created-operations"),
        ("204", "x-hearth-no-content-operations"),
    ):
        proto_oas3["paths"] = rename_success(
            proto_oas3.get("paths", {}), supplement.get(key) or [], status, key
        )
    patch_schemas(
        proto_oas3.get("components", {}).get("schemas", {}),
        supplement.get("x-hearth-schema-patches") or {},
    )

    # Merge: supplement paths win over proto paths
    merged_paths = merge_paths(proto_oas3.get("paths", {}), supplement.get("paths", {}))
    # Drop proto-derived operations the REST surface does not serve.
    merged_paths = omit_operations(
        merged_paths, supplement.get("x-hearth-omit-operations") or []
    )

    # Build the final document using supplement as the skeleton.
    # Override the title so the merged output doesn't say "supplement".
    merged_info = dict(supplement.get("info", proto_oas3.get("info", {})))
    merged_info["title"] = "Hearth API"
    result: dict = {
        "openapi": "3.0.3",
        "info": merged_info,
        "paths": merged_paths,
    }

    # Merge servers
    servers = supplement.get("servers") or proto_oas3.get("servers")
    if servers:
        result["servers"] = servers

    # Merge tags (supplement first, then proto)
    supp_tags = supplement.get("tags") or []
    proto_tags = proto_oas3.get("tags") or []
    all_tags = list({t["name"]: t for t in (proto_tags + supp_tags)}.values())
    if all_tags:
        result["tags"] = sorted(all_tags, key=lambda t: t.get("name", ""))

    # Merge components
    merged_components = merge_components(
        proto_oas3.get("components"), supplement.get("components")
    )
    if merged_components:
        result["components"] = merged_components

    # Security schemes from supplement
    if "security" in supplement:
        result["security"] = supplement["security"]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")

    path_count = len(merged_paths)
    print(f"Wrote {args.out} ({path_count} paths)")


if __name__ == "__main__":
    main()

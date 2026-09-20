"""openapi.yml completeness + validity guard.

The control plane generates types from this spec; a stale or schema-less spec
is how hand-copied shapes reached production. This asserts the spec parses,
every $ref resolves, the routes the API actually serves are documented (with
rule_kind=list), and every success response carries a schema (not a bare
"200: OK").
"""

from __future__ import annotations

from pathlib import Path

import yaml

_SPEC_PATH = Path(__file__).resolve().parents[1] / "openapi.yml"


def _spec() -> dict:
    return yaml.safe_load(_SPEC_PATH.read_text())


def _resolve(spec: dict, ref: str):
    assert ref.startswith("#/"), f"unexpected external $ref: {ref}"
    node = spec
    for part in ref[2:].split("/"):
        assert isinstance(node, dict) and part in node, f"unresolved $ref: {ref}"
        node = node[part]
    return node


def _walk_refs(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str):
                yield v
            else:
                yield from _walk_refs(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_refs(v)


def test_spec_parses():
    spec = _spec()
    assert spec["openapi"].startswith("3.")
    assert "paths" in spec and "components" in spec


def test_all_refs_resolve():
    spec = _spec()
    for ref in _walk_refs(spec):
        _resolve(spec, ref)


def test_documented_paths_cover_served_routes():
    paths = set(_spec()["paths"])
    expected = {
        "/status",
        "/help",
        "/signals",
        "/signals/stats",
        "/logs",
        "/rules",
        "/rules/{rule_id}",
        "/settings",
        "/settings/{setting_id}",
        "/ir-roles",
        "/ir-roles/{aws_account_id}",
        "/ir-actions",
        "/ir-actions/{detection_id}",
        "/ir-actions/{detection_id}/rollback",
    }
    missing = expected - paths
    assert not missing, f"openapi.yml missing served routes: {sorted(missing)}"


def test_no_phantom_routes_documented():
    # Routes that no handler serves must not be advertised.
    paths = set(_spec()["paths"])
    assert "/swagger.json" not in paths
    assert "/docs" not in paths


def test_rule_kind_enum_includes_list():
    spec = _spec()
    # GET /rules query param
    get_params = spec["paths"]["/rules"]["get"]["parameters"]
    rk = next(p for p in get_params if p.get("name") == "rule_kind")
    assert "list" in rk["schema"]["enum"]
    # GET /rules/{rule_id} query param
    get_one = spec["paths"]["/rules/{rule_id}"]["get"]["parameters"]
    rk1 = next(p for p in get_one if p.get("name") == "rule_kind")
    assert "list" in rk1["schema"]["enum"]


def test_success_responses_have_schemas():
    spec = _spec()
    offenders = []
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method == "parameters" or not isinstance(op, dict):
                continue
            for code, resp in op.get("responses", {}).items():
                if not str(code).startswith("2"):
                    continue
                # Either an inline content schema or a $ref response with one.
                content = resp.get("content") if isinstance(resp, dict) else None
                if isinstance(resp, dict) and "$ref" in resp:
                    content = _resolve(spec, resp["$ref"]).get("content")
                has_schema = bool(content) and any("schema" in c for c in content.values())
                if not has_schema:
                    offenders.append(f"{method.upper()} {path} -> {code}")
    assert not offenders, f"success responses without a schema: {offenders}"


def test_ir_scopes_and_optimistic_concurrency_documented():
    spec = _spec()
    schemas = spec["components"]["schemas"]
    # expected_rev is part of the write contract
    assert "expected_rev" in schemas["RuleWrite"]["properties"]
    assert "expected_rev" in schemas["SettingsWrite"]["properties"]
    # IR action + role schemas exist
    assert "IRAction" in schemas and "IRRole" in schemas

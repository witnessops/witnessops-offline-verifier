#!/usr/bin/env python3
"""Structure-only validator for API authorization fixture examples.

Validates committed synthetic/local JSON examples only. It does not access live
APIs, use credentials, create runtime evidence packages, send requests, fuzz,
or contact external targets.
"""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
VALID_ROOT = ROOT / "fixtures" / "api-authz" / "valid"
INVALID_ROOT = ROOT / "fixtures" / "api-authz" / "invalid"

EXPECTED_PROOF_RUN_ID = "API-AUTHZ-FIXTURE-SPEC-V1"
EXPECTED_PARENT = "PRC-API-AUTHZ"
EXPECTED_GATE_ID = "API-AUTHZ-GATE-001"
EXPECTED_VERIFIER = "api-authz-fixture-structure-checker"
EXPECTED_MODE = "structure_only"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

EXPECTED_VALID_FILES = {
    "FIXTURE.json",
    "AUTHORIZATION_MATRIX.json",
    "OBSERVED_DECISIONS.json",
    "EVIDENCE_MANIFEST.json",
    "RECEIPT.json",
    "VERIFICATION.json",
}
EXPECTED_INVALID_FILES = {
    "fixture-real-boundary.json",
    "fixture-real-actor.json",
    "observed-decision-mismatch.json",
    "receipt-hash-mismatch.json",
    "receipt-live-api-claim.json",
}
EXPECTED_REQUIRED_ARTIFACTS = {
    "FIXTURE.json",
    "AUTHORIZATION_MATRIX.json",
    "OBSERVED_DECISIONS.json",
    "VERIFICATION.json",
    "RECEIPT.json",
    "NOTES.md",
}
EXPECTED_LIMITATIONS = {
    "synthetic fixture only",
    "no live API tested",
    "no customer data",
    "no external targets",
    "no production security claim",
}

# Positive unsafe markers only. Negative limitation language such as
# "no live API tested" is intentionally allowed in valid artifacts.
PROHIBITED_TEXT_MARKERS = (
    "http://",
    "https://",
    "authorization:",
    "bearer ",
    "api_key",
    "apikey",
    "cookie",
    "session",
    "token",
    "production api authorization verified",
    "customer data used",
)


class ValidationError(Exception):
    pass


def fail(msg: str) -> None:
    raise ValidationError(msg)


def load_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()
    for marker in PROHIBITED_TEXT_MARKERS:
        if marker in lowered:
            fail(f"prohibited marker {marker!r} found in {path.relative_to(ROOT)}")
    data = json.loads(text)
    if not isinstance(data, dict):
        fail("top-level JSON value must be object")
    return data


def require(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        fail(f"missing required key: {key}")
    return data[key]


def require_const(data: dict[str, Any], key: str, expected: Any) -> None:
    actual = require(data, key)
    if actual != expected:
        fail(f"{key} expected {expected!r}, got {actual!r}")


def assert_inventory(directory: Path, expected: set[str]) -> None:
    actual = {path.name for path in directory.glob("*.json") if path.is_file()}
    if actual != expected:
        fail(f"inventory mismatch for {directory}: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")


def validate_hashes(value: Any, base_dir: Path | None = None) -> None:
    if not isinstance(value, list):
        fail("artifact_hashes must be list")
    for item in value:
        if not isinstance(item, dict):
            fail("artifact hash entries must be objects")
        if not isinstance(item.get("path"), str) or not item["path"]:
            fail("artifact hash path must be non-empty string")
        if not isinstance(item.get("sha256"), str) or not SHA256_RE.match(item["sha256"]):
            fail(f"invalid sha256 for {item.get('path')!r}")
        if base_dir is None:
            continue
        artifact_path = Path(item["path"])
        if artifact_path.is_absolute():
            fail(f"artifact hash path must be relative: {item['path']!r}")
        base = base_dir.resolve()
        resolved = (base / artifact_path).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            fail(f"artifact hash path escapes fixture directory: {item['path']!r}")
        if not resolved.is_file():
            fail(f"artifact hash path not found: {item['path']!r}")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != item["sha256"]:
            fail(f"sha256 mismatch for {item['path']!r}")


def fixture_ids() -> tuple[set[str], set[str]]:
    fixture = load_json(VALID_ROOT / "FIXTURE.json")
    actors = fixture.get("actors", [])
    objects = fixture.get("objects", [])
    return {a["id"] for a in actors if isinstance(a, dict) and "id" in a}, {o["id"] for o in objects if isinstance(o, dict) and "id" in o}


def validate_fixture(path: Path) -> None:
    data = load_json(path)
    require_const(data, "fixture_id", "api_authz_fixture_v1")
    require_const(data, "classification", "INTERNAL_ONLY")
    require_const(data, "target_boundary", "synthetic_local_fixture_only")
    actors = require(data, "actors")
    objects = require(data, "objects")
    if not isinstance(actors, list) or not actors:
        fail("actors must be non-empty list")
    if not isinstance(objects, list) or not objects:
        fail("objects must be non-empty list")
    actor_ids: set[str] = set()
    for actor in actors:
        if not isinstance(actor, dict):
            fail("actor entries must be objects")
        actor_id = actor.get("id")
        if not isinstance(actor_id, str) or not actor_id.startswith("actor_"):
            fail("actor.id must start with actor_")
        if actor_id in actor_ids:
            fail(f"duplicate actor id: {actor_id}")
        actor_ids.add(actor_id)
        if actor.get("synthetic") is not True:
            fail("all actors must be synthetic")
    object_ids: set[str] = set()
    for obj in objects:
        if not isinstance(obj, dict):
            fail("object entries must be objects")
        object_id = obj.get("id")
        if not isinstance(object_id, str) or not object_id.startswith("object_"):
            fail("object.id must start with object_")
        if object_id in object_ids:
            fail(f"duplicate object id: {object_id}")
        object_ids.add(object_id)
        if obj.get("synthetic") is not True:
            fail("all objects must be synthetic")
        if obj.get("owner_actor_id") not in actor_ids:
            fail("object owner_actor_id must reference a fixture actor")


def validate_matrix(path: Path) -> None:
    data = load_json(path)
    actor_ids, object_ids = fixture_ids()
    require_const(data, "matrix_id", "api_authz_matrix_v1")
    seen: set[tuple[str, str, str]] = set()
    for row in require(data, "decisions"):
        key = (row.get("actor_id"), row.get("object_id"), row.get("action"))
        if key[0] not in actor_ids:
            fail(f"decision.actor_id not found in fixture actors: {key[0]!r}")
        if key[1] not in object_ids:
            fail(f"decision.object_id not found in fixture objects: {key[1]!r}")
        if key[2] not in {"read", "write", "delete"}:
            fail("decision.action not allowed")
        if row.get("expected_decision") not in {"allow", "deny"}:
            fail("decision.expected_decision not allowed")
        if key in seen:
            fail(f"duplicate matrix decision: {key}")
        seen.add(key)


def matrix_lookup() -> dict[tuple[str, str, str], str]:
    return {(row["actor_id"], row["object_id"], row["action"]): row["expected_decision"] for row in load_json(VALID_ROOT / "AUTHORIZATION_MATRIX.json")["decisions"]}


def validate_observed(path: Path) -> None:
    data = load_json(path)
    lookup = matrix_lookup()
    seen_requests: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()
    for row in require(data, "observed_decisions"):
        request_id = row.get("request_id")
        if not isinstance(request_id, str) or not request_id.startswith("req_"):
            fail("request_id must start with req_")
        if request_id in seen_requests:
            fail(f"duplicate request_id: {request_id}")
        seen_requests.add(request_id)
        key = (row.get("actor_id"), row.get("object_id"), row.get("action"))
        if key in seen_keys:
            fail(f"duplicate observed decision for matrix key: {key}")
        seen_keys.add(key)
        if key not in lookup:
            fail(f"observed decision does not map to matrix row: {key}")
        if row.get("expected_decision") != lookup[key]:
            fail(f"expected decision disagrees with matrix for {key}")
        if row.get("observed_decision") != lookup[key]:
            fail(f"observed decision mismatch for {key}")
    if set(lookup) != seen_keys:
        fail(f"observed decision coverage mismatch: missing={sorted(set(lookup) - seen_keys)}, extra={sorted(seen_keys - set(lookup))}")


def validate_manifest(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "parent_candidate", EXPECTED_PARENT)
    require_const(data, "classification", "INTERNAL_ONLY")
    require_const(data, "target_boundary", "synthetic_local_fixture_only")
    if set(require(data, "required_artifacts")) != EXPECTED_REQUIRED_ARTIFACTS:
        fail("required_artifacts mismatch")
    if require(data, "stop_conditions_checked") is not True:
        fail("stop_conditions_checked must be true")
    validate_hashes(require(data, "artifact_hashes"))


def validate_receipt(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "parent_candidate", EXPECTED_PARENT)
    require_const(data, "authority_gate_id", EXPECTED_GATE_ID)
    require_const(data, "classification", "INTERNAL_ONLY")
    require_const(data, "execution_scope", "synthetic_local_fixture_only")
    closure_state = require(data, "closure_state")
    if closure_state not in {"drafted", "ready_for_fixture_run", "blocked_no_authority", "blocked_bad_fixture", "blocked_decision_mismatch", "blocked_invalid_artifact", "closed_verified"}:
        fail("closure_state not allowed")
    require_const(data, "evidence_manifest_path", "EVIDENCE_MANIFEST.json")
    require_const(data, "verification_path", "VERIFICATION.json")
    if not isinstance(require(data, "stop_condition_triggered"), bool):
        fail("stop_condition_triggered must be boolean")
    validate_hashes(require(data, "artifact_hashes"), path.parent if closure_state == "closed_verified" else None)
    limitations = require(data, "limitations")
    if set(limitations) != EXPECTED_LIMITATIONS:
        fail(f"limitations mismatch: expected={sorted(EXPECTED_LIMITATIONS)}, got={sorted(set(limitations))}")


def validate_verification(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "classification", "INTERNAL_ONLY")
    verifier = require(data, "verifier")
    if verifier.get("name") != EXPECTED_VERIFIER or verifier.get("mode") != EXPECTED_MODE:
        fail("verifier name/mode not allowed")
    if require(data, "result") not in {"passed", "failed"}:
        fail("result not allowed")
    check_ids: set[str] = set()
    for check in require(data, "checks"):
        check_id = check.get("id")
        if not isinstance(check_id, str) or not check_id:
            fail("check.id must be non-empty string")
        if check_id in check_ids:
            fail(f"duplicate check.id: {check_id}")
        check_ids.add(check_id)
        if check.get("result") not in {"passed", "failed", "skipped"}:
            fail("check.result not allowed")
    if "structure-only verification" not in require(data, "limitations"):
        fail("limitations must include structure-only verification")


VALID_CASES: dict[str, Callable[[Path], None]] = {
    "FIXTURE.json": validate_fixture,
    "AUTHORIZATION_MATRIX.json": validate_matrix,
    "OBSERVED_DECISIONS.json": validate_observed,
    "EVIDENCE_MANIFEST.json": validate_manifest,
    "RECEIPT.json": validate_receipt,
    "VERIFICATION.json": validate_verification,
}
INVALID_CASES: dict[str, Callable[[Path], None]] = {
    "fixture-real-boundary.json": validate_fixture,
    "fixture-real-actor.json": validate_fixture,
    "observed-decision-mismatch.json": validate_observed,
    "receipt-hash-mismatch.json": validate_receipt,
    "receipt-live-api-claim.json": validate_receipt,
}


def main() -> int:
    failures: list[str] = []
    try:
        assert_inventory(VALID_ROOT, set(VALID_CASES))
        assert_inventory(INVALID_ROOT, set(INVALID_CASES))
    except ValidationError as exc:
        failures.append(str(exc))
    for filename, validator in VALID_CASES.items():
        try:
            validator(VALID_ROOT / filename)
        except Exception as exc:
            failures.append(f"valid fixture failed {(VALID_ROOT / filename).relative_to(ROOT)}: {exc}")
    for filename, validator in INVALID_CASES.items():
        path = INVALID_ROOT / filename
        try:
            validator(path)
        except Exception as exc:
            print(json.dumps({"expected_invalid_rejected": str(path.relative_to(ROOT)), "reason": str(exc)}))
            continue
        failures.append(f"invalid fixture unexpectedly passed {path.relative_to(ROOT)}")
    if failures:
        print(json.dumps({"ok": False, "failures": failures}, indent=2))
        return 1
    print(json.dumps({"ok": True, "mode": "structure_only", "valid_checked": len(VALID_CASES), "invalid_checked": len(INVALID_CASES), "inventory_checked": True, "matrix_coverage_checked": True, "live_api_testing": False, "runtime_evidence_created": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

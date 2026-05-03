#!/usr/bin/env python3
"""Structure-only validator for SBOM supply-chain fixture examples.

Validates committed synthetic/local JSON examples only. It does not scan
dependencies, inspect repositories, query registries, perform vulnerability
analysis, analyze licenses, create runtime evidence packages, or contact
external targets.
"""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
VALID_ROOT = ROOT / "fixtures" / "sbom-supply-chain" / "valid"
INVALID_ROOT = ROOT / "fixtures" / "sbom-supply-chain" / "invalid"

EXPECTED_PROOF_RUN_ID = "SBOM-SUPPLY-CHAIN-FIXTURE-SPEC-V1"
EXPECTED_PARENT = "PRC-SUPPLY-CHAIN"
EXPECTED_GATE_ID = "SBOM-SUPPLY-CHAIN-GATE-001"
EXPECTED_VERIFIER = "sbom-supply-chain-fixture-structure-checker"
EXPECTED_MODE = "structure_only"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

EXPECTED_VALID_FILES = {
    "SOURCE_DECLARATION.json",
    "COMPONENT_INVENTORY.json",
    "EVIDENCE_MANIFEST.json",
    "RECEIPT.json",
    "VERIFICATION.json",
}
EXPECTED_INVALID_FILES = {
    "source-external-network.json",
    "inventory-non-synthetic-component.json",
    "receipt-hash-mismatch.json",
    "receipt-production-claim.json",
}
EXPECTED_REQUIRED_ARTIFACTS = {
    "ARTIFACTS/SOURCE_DECLARATION.json",
    "ARTIFACTS/COMPONENT_INVENTORY.json",
    "ARTIFACTS/NOTES.md",
    "HASHES.sha256",
    "VERIFICATION.json",
    "RECEIPT.json",
}
EXPECTED_RECEIPT_LIMITATIONS = {
    "synthetic fixture only",
    "no live repository analyzed",
    "no package registry queried",
    "no vulnerability scan performed",
    "no completeness claim",
    "no production supply-chain claim",
}

# Positive unsafe markers only. Negative limitation language such as
# "no live repository analyzed" is intentionally allowed in valid artifacts.
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
    "npmjs",
    "pypi",
    "maven",
    "ghcr.io",
    "docker.io",
    "github.com",
    "osv",
    "cve-",
    "ghsa-",
    "production supply-chain posture verified",
    "production supply-chain posture",
    "license compliance verified",
    "standards conformant",
    "complete sbom",
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


def validate_source(path: Path) -> None:
    data = load_json(path)
    require_const(data, "source_declaration_id", "sbom_fixture_source_v1")
    require_const(data, "classification", "INTERNAL_ONLY")
    require_const(data, "target_boundary", "synthetic_local_fixture_only")
    require_const(data, "source_type", "synthetic_fixture")
    for flag in ("contains_customer_data", "contains_secrets", "external_network_required"):
        if require(data, flag) is not False:
            fail(f"{flag} must be false")


def validate_inventory(path: Path) -> None:
    data = load_json(path)
    require_const(data, "inventory_id", "sbom_fixture_inventory_v1")
    require_const(data, "format", "internal_fixture")
    components = require(data, "components")
    if not isinstance(components, list) or not components:
        fail("components must be non-empty list")
    names: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            fail("component entries must be objects")
        name = component.get("name")
        if not isinstance(name, str) or not name.startswith("synthetic-"):
            fail("component.name must start with synthetic-")
        if name in names:
            fail(f"duplicate component name: {name}")
        names.add(name)
        if not isinstance(component.get("version"), str) or not component["version"]:
            fail("component.version must be non-empty string")
        if component.get("type") not in {"library", "application", "container", "service"}:
            fail("component.type not allowed")
        if component.get("synthetic") is not True:
            fail("all components must be synthetic")


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
    if closure_state not in {"drafted", "ready_for_fixture_run", "blocked_no_authority", "blocked_bad_fixture", "blocked_external_dependency", "blocked_invalid_artifact", "closed_verified"}:
        fail("closure_state not allowed")
    require_const(data, "evidence_manifest_path", "EVIDENCE_MANIFEST.json")
    require_const(data, "verification_path", "VERIFICATION.json")
    if not isinstance(require(data, "stop_condition_triggered"), bool):
        fail("stop_condition_triggered must be boolean")
    validate_hashes(require(data, "artifact_hashes"), path.parent if closure_state == "closed_verified" else None)
    limitations = require(data, "limitations")
    if set(limitations) != EXPECTED_RECEIPT_LIMITATIONS:
        fail(f"limitations mismatch: expected={sorted(EXPECTED_RECEIPT_LIMITATIONS)}, got={sorted(set(limitations))}")


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
    "SOURCE_DECLARATION.json": validate_source,
    "COMPONENT_INVENTORY.json": validate_inventory,
    "EVIDENCE_MANIFEST.json": validate_manifest,
    "RECEIPT.json": validate_receipt,
    "VERIFICATION.json": validate_verification,
}
INVALID_CASES: dict[str, Callable[[Path], None]] = {
    "source-external-network.json": validate_source,
    "inventory-non-synthetic-component.json": validate_inventory,
    "receipt-hash-mismatch.json": validate_receipt,
    "receipt-production-claim.json": validate_receipt,
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
    print(json.dumps({"ok": True, "mode": "structure_only", "valid_checked": len(VALID_CASES), "invalid_checked": len(INVALID_CASES), "inventory_checked": True, "overclaim_markers_checked": True, "dependency_scan": False, "live_repo_package_analysis": False, "registry_queries": False, "runtime_evidence_created": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

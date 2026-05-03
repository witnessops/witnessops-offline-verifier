#!/usr/bin/env python3
"""Structure-only validator for DFIR fixture examples.

This script validates committed JSON examples against a deliberately small
schema subset and policy checks. It does not create runtime evidence packages,
hash live systems, inspect endpoints, execute binaries, or access networks.
"""

from __future__ import annotations

import json
import hashlib
import re
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "fixtures" / "dfir-fixture"
VALID_ROOT = FIXTURE_ROOT / "valid"
INVALID_ROOT = FIXTURE_ROOT / "invalid"

EXPECTED_PROOF_RUN_ID = "DFIR-FIXTURE-CUSTODY-DRY-RUN-V1"
EXPECTED_GATE_ID = "DFIR-FIXTURE-CUSTODY-GATE-001"
EXPECTED_CLASSIFICATION = "INTERNAL_ONLY"
EXPECTED_BOUNDARY = "harmless_internal_fixture_file_only"
EXPECTED_SCOPE = "harmless_fixture_only"
EXPECTED_VERIFIER = "dfir-fixture-structure-checker"
EXPECTED_MODE = "structure_only"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

EXPECTED_VALID_FILES = {
    "EVIDENCE_MANIFEST.json",
    "RECEIPT.json",
    "VERIFICATION.json",
}

EXPECTED_INVALID_FILES = {
    "manifest-wrong-boundary.json",
    "manifest-secret-flagged.json",
    "receipt-invalid-closure.json",
    "receipt-hash-mismatch.json",
    "verification-wrong-mode.json",
}


class ValidationError(Exception):
    """Raised when fixture validation fails."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError("top-level JSON value must be an object")
    return data


def require(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise ValidationError(f"missing required key: {key}")
    return data[key]


def require_const(data: dict[str, Any], key: str, expected: Any) -> None:
    actual = require(data, key)
    if actual != expected:
        raise ValidationError(f"{key} expected {expected!r}, got {actual!r}")


def validate_hashes(value: Any, base_dir: Path | None = None) -> None:
    if not isinstance(value, list):
        raise ValidationError("artifact_hashes must be a list")
    for item in value:
        if not isinstance(item, dict):
            raise ValidationError("artifact_hashes entries must be objects")
        path = item.get("path")
        digest = item.get("sha256")
        if not isinstance(path, str) or not path:
            raise ValidationError("artifact hash path must be a non-empty string")
        if not isinstance(digest, str) or not SHA256_RE.match(digest):
            raise ValidationError(f"invalid sha256 for {path!r}")
        if base_dir is None:
            continue
        artifact_path = Path(path)
        if artifact_path.is_absolute():
            raise ValidationError(f"artifact hash path must be relative: {path!r}")
        base = base_dir.resolve()
        resolved = (base / artifact_path).resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise ValidationError(f"artifact hash path escapes fixture directory: {path!r}") from exc
        if not resolved.is_file():
            raise ValidationError(f"artifact hash path not found: {path!r}")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != digest:
            raise ValidationError(f"sha256 mismatch for {path!r}")


def assert_fixture_inventory(directory: Path, expected_files: set[str]) -> None:
    if not directory.exists():
        raise ValidationError(f"fixture directory missing: {directory}")
    actual_files = {path.name for path in directory.glob("*.json") if path.is_file()}
    missing = sorted(expected_files - actual_files)
    extra = sorted(actual_files - expected_files)
    if missing or extra:
        raise ValidationError(
            f"fixture inventory mismatch for {directory}: missing={missing}, extra={extra}"
        )


def validate_manifest(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "authority_gate_id", EXPECTED_GATE_ID)
    require_const(data, "classification", EXPECTED_CLASSIFICATION)
    require_const(data, "fixture_boundary", EXPECTED_BOUNDARY)
    if require(data, "stop_conditions_checked") is not True:
        raise ValidationError("stop_conditions_checked must be true")

    source = require(data, "source_object")
    if not isinstance(source, dict):
        raise ValidationError("source_object must be an object")
    if source.get("name") != "sample-evidence.txt":
        raise ValidationError("source_object.name must be sample-evidence.txt")
    if source.get("type") != "harmless_text_file":
        raise ValidationError("source_object.type must be harmless_text_file")
    for flag in ("contains_secrets", "contains_personal_data", "contains_customer_data", "contains_malware"):
        if source.get(flag) is not False:
            raise ValidationError(f"source_object.{flag} must be false")

    required_artifacts = require(data, "required_artifacts")
    if not isinstance(required_artifacts, list):
        raise ValidationError("required_artifacts must be a list")
    required_set = set(required_artifacts)
    expected_artifacts = {
        "ARTIFACTS/sample-evidence.txt",
        "ARTIFACTS/NOTES.md",
        "HASHES.sha256",
        "ACTIONS.log",
        "VERIFICATION.json",
        "RECEIPT.json",
    }
    if required_set != expected_artifacts:
        raise ValidationError(
            f"required_artifacts mismatch: expected={sorted(expected_artifacts)}, got={sorted(required_set)}"
        )
    validate_hashes(require(data, "artifact_hashes"))


def validate_receipt(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "parent_candidate", "PRC-DFIR-CUSTODY")
    require_const(data, "authority_gate_id", EXPECTED_GATE_ID)
    require_const(data, "classification", EXPECTED_CLASSIFICATION)
    require_const(data, "execution_scope", EXPECTED_SCOPE)
    closure_state = require(data, "closure_state")
    if closure_state not in {
        "drafted",
        "ready_for_fixture_run",
        "blocked_no_authority",
        "blocked_no_evidence",
        "blocked_hash_mismatch",
        "closed_verified",
    }:
        raise ValidationError("closure_state is not allowed")
    require_const(data, "evidence_manifest_path", "EVIDENCE_MANIFEST.json")
    require_const(data, "hashes_path", "HASHES.sha256")
    require_const(data, "verification_path", "VERIFICATION.json")
    if not isinstance(require(data, "stop_condition_triggered"), bool):
        raise ValidationError("stop_condition_triggered must be boolean")
    validate_hashes(require(data, "artifact_hashes"), path.parent if closure_state == "closed_verified" else None)
    limitations = require(data, "limitations")
    if not isinstance(limitations, list) or "fixture-only dry run" not in limitations:
        raise ValidationError("limitations must include fixture-only dry run")
    prohibited_limitations = {"real incident response", "legal admissibility", "production readiness"}
    if prohibited_limitations.intersection(set(limitations)):
        raise ValidationError("limitations contain prohibited capability claim")


def validate_verification(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "classification", EXPECTED_CLASSIFICATION)
    verifier = require(data, "verifier")
    if not isinstance(verifier, dict):
        raise ValidationError("verifier must be an object")
    if verifier.get("name") != EXPECTED_VERIFIER:
        raise ValidationError("verifier.name is not allowed")
    if verifier.get("mode") != EXPECTED_MODE:
        raise ValidationError("verifier.mode must be structure_only")
    if not isinstance(verifier.get("version"), str) or not verifier["version"]:
        raise ValidationError("verifier.version must be a non-empty string")
    if require(data, "result") not in {"passed", "failed"}:
        raise ValidationError("result must be passed or failed")
    checks = require(data, "checks")
    if not isinstance(checks, list) or not checks:
        raise ValidationError("checks must be a non-empty list")
    check_ids: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ValidationError("check entries must be objects")
        check_id = check.get("id")
        if not isinstance(check_id, str) or not check_id:
            raise ValidationError("check.id must be a non-empty string")
        if check_id in check_ids:
            raise ValidationError(f"duplicate check.id: {check_id}")
        check_ids.add(check_id)
        if check.get("result") not in {"passed", "failed", "skipped"}:
            raise ValidationError("check.result is not allowed")
        if not isinstance(check.get("detail"), str):
            raise ValidationError("check.detail must be a string")
    limitations = require(data, "limitations")
    if not isinstance(limitations, list) or "structure-only verification" not in limitations:
        raise ValidationError("limitations must include structure-only verification")


VALID_CASES: dict[str, Callable[[Path], None]] = {
    "EVIDENCE_MANIFEST.json": validate_manifest,
    "RECEIPT.json": validate_receipt,
    "VERIFICATION.json": validate_verification,
}

INVALID_CASES: dict[str, Callable[[Path], None]] = {
    "manifest-wrong-boundary.json": validate_manifest,
    "manifest-secret-flagged.json": validate_manifest,
    "receipt-invalid-closure.json": validate_receipt,
    "receipt-hash-mismatch.json": validate_receipt,
    "verification-wrong-mode.json": validate_verification,
}


def main() -> int:
    failures: list[str] = []

    try:
        assert_fixture_inventory(VALID_ROOT, EXPECTED_VALID_FILES)
        assert_fixture_inventory(INVALID_ROOT, EXPECTED_INVALID_FILES)
    except ValidationError as exc:
        failures.append(str(exc))

    for filename, validator in VALID_CASES.items():
        path = VALID_ROOT / filename
        try:
            validator(path)
        except ValidationError as exc:
            failures.append(f"valid fixture failed {path.relative_to(ROOT)}: {exc}")

    for filename, validator in INVALID_CASES.items():
        path = INVALID_ROOT / filename
        try:
            validator(path)
        except ValidationError as exc:
            print(json.dumps({"expected_invalid_rejected": str(path.relative_to(ROOT)), "reason": str(exc)}))
            continue
        failures.append(f"invalid fixture unexpectedly passed {path.relative_to(ROOT)}")

    if failures:
        print(json.dumps({"ok": False, "failures": failures}, indent=2))
        return 1

    print(
        json.dumps(
            {
                "ok": True,
                "valid_checked": len(VALID_CASES),
                "invalid_checked": len(INVALID_CASES),
                "inventory_checked": True,
                "mode": "structure_only",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

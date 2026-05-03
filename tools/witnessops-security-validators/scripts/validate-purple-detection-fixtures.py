#!/usr/bin/env python3
"""Structure-only validator for purple detection fixture examples.

Validates committed synthetic/local JSON examples only. It does not execute
adversary emulation, BAS tooling, attack commands, telemetry collection,
runtime evidence generation, or contact external targets.
"""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
VALID_ROOT = ROOT / "fixtures" / "purple-detection" / "valid"
INVALID_ROOT = ROOT / "fixtures" / "purple-detection" / "invalid"

EXPECTED_PROOF_RUN_ID = "PURPLE-DETECTION-FIXTURE-SPEC-V1"
EXPECTED_PARENT = "PRC-PURPLE-DETECTION"
EXPECTED_GATE_ID = "PURPLE-DETECTION-GATE-001"
EXPECTED_VERIFIER = "purple-detection-fixture-structure-checker"
EXPECTED_MODE = "structure_only"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

EXPECTED_VALID_FILES = {
    "SCENARIO_DECLARATION.json",
    "DETECTION_EXPECTATION.json",
    "OBSERVED_RESULT.json",
    "EVIDENCE_MANIFEST.json",
    "RECEIPT.json",
    "VERIFICATION.json",
}
EXPECTED_INVALID_FILES = {
    "scenario-attack-commands.json",
    "observed-live-telemetry.json",
    "receipt-hash-mismatch.json",
    "receipt-production-detection-claim.json",
}
EXPECTED_REQUIRED_ARTIFACTS = {
    "ARTIFACTS/SCENARIO_DECLARATION.json",
    "ARTIFACTS/DETECTION_EXPECTATION.json",
    "ARTIFACTS/OBSERVED_RESULT.json",
    "ARTIFACTS/NOTES.md",
    "HASHES.sha256",
    "VERIFICATION.json",
    "RECEIPT.json",
}
EXPECTED_RECEIPT_LIMITATIONS = {
    "synthetic fixture only",
    "no adversary emulation executed",
    "no BAS tooling executed",
    "no live telemetry used",
    "no production detection claim",
    "no customer environment tested",
}

# Positive unsafe markers only. Negative limitation language such as
# "no adversary emulation executed" is intentionally allowed in valid artifacts.
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
    "malware",
    "attack payload",
    "breach and attack simulation executed",
    "production telemetry used",
    "production detection coverage verified",
    "production detection claim verified",
    "endpoint tested",
    "cloud tenant tested",
    "identity system tested",
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


def validate_scenario(path: Path) -> None:
    data = load_json(path)
    require_const(data, "scenario_id", "purple_detection_fixture_scenario_v1")
    require_const(data, "classification", "INTERNAL_ONLY")
    require_const(data, "target_boundary", "synthetic_fixture_only")
    require_const(data, "scenario_type", "synthetic_detection_validation")
    for flag in ("contains_attack_commands", "contains_live_target_details", "contains_customer_data", "external_network_required"):
        if require(data, flag) is not False:
            fail(f"{flag} must be false")


def validate_expectation(path: Path) -> None:
    data = load_json(path)
    require_const(data, "expectation_id", "purple_detection_fixture_expectation_v1")
    require_const(data, "scenario_id", "purple_detection_fixture_scenario_v1")
    if require(data, "expected_result") not in {"detect", "not_detect"}:
        fail("expected_result must be detect or not_detect")
    require_const(data, "control_claim", "fixture_only")
    if require(data, "production_detection_claim") is not False:
        fail("production_detection_claim must be false")


def validate_observed(path: Path) -> None:
    data = load_json(path)
    require_const(data, "observed_result_id", "purple_detection_fixture_observed_v1")
    require_const(data, "scenario_id", "purple_detection_fixture_scenario_v1")
    if require(data, "observed_result") not in {"detect", "not_detect"}:
        fail("observed_result must be detect or not_detect")
    require_const(data, "source", "synthetic_fixture")
    if require(data, "production_telemetry_used") is not False:
        fail("production_telemetry_used must be false")


def validate_manifest(path: Path) -> None:
    data = load_json(path)
    require_const(data, "proof_run_id", EXPECTED_PROOF_RUN_ID)
    require_const(data, "parent_candidate", EXPECTED_PARENT)
    require_const(data, "classification", "INTERNAL_ONLY")
    require_const(data, "target_boundary", "synthetic_fixture_only")
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
    require_const(data, "execution_scope", "synthetic_fixture_only")
    closure_state = require(data, "closure_state")
    if closure_state not in {"drafted", "ready_for_fixture_run", "blocked_no_authority", "blocked_bad_fixture", "blocked_live_execution", "blocked_invalid_artifact", "closed_verified"}:
        fail("closure_state not allowed")
    require_const(data, "evidence_manifest_path", "EVIDENCE_MANIFEST.json")
    require_const(data, "verification_path", "VERIFICATION.json")
    if not isinstance(require(data, "stop_condition_triggered"), bool):
        fail("stop_condition_triggered must be boolean")
    validate_hashes(require(data, "artifact_hashes"), path.parent if closure_state == "closed_verified" else None)
    if set(require(data, "limitations")) != EXPECTED_RECEIPT_LIMITATIONS:
        fail("limitations mismatch")


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
    "SCENARIO_DECLARATION.json": validate_scenario,
    "DETECTION_EXPECTATION.json": validate_expectation,
    "OBSERVED_RESULT.json": validate_observed,
    "EVIDENCE_MANIFEST.json": validate_manifest,
    "RECEIPT.json": validate_receipt,
    "VERIFICATION.json": validate_verification,
}
INVALID_CASES: dict[str, Callable[[Path], None]] = {
    "scenario-attack-commands.json": validate_scenario,
    "observed-live-telemetry.json": validate_observed,
    "receipt-hash-mismatch.json": validate_receipt,
    "receipt-production-detection-claim.json": validate_receipt,
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
    print(json.dumps({"ok": True, "mode": "structure_only", "valid_checked": len(VALID_CASES), "invalid_checked": len(INVALID_CASES), "inventory_checked": True, "overclaim_markers_checked": True, "adversary_emulation": False, "bas_tooling": False, "attack_commands_payloads": False, "live_telemetry": False, "runtime_evidence_created": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

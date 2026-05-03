#!/usr/bin/env python3
"""Validate source-refresh records.

Structure-only validator. It does not retrieve sources, verify claims,
upgrade claim statuses, authorize publication, or create runtime evidence.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "source-refresh" / "record.schema.json"
RECORD_DIR = ROOT / "source-index" / "source-refresh-records"
EXPECTED_RECORDS = {
    "SOURCE_REFRESH_RECORD_VM_CLAIM_001.json": "VM-CLAIM-001",
    "SOURCE_REFRESH_RECORD_VM_CLAIM_002.json": "VM-CLAIM-002",
    "SOURCE_REFRESH_RECORD_VM_CLAIM_003.json": "VM-CLAIM-003",
    "SOURCE_REFRESH_RECORD_VM_CLAIM_004.json": "VM-CLAIM-004",
    "SOURCE_REFRESH_RECORD_VM_CLAIM_005.json": "VM-CLAIM-005",
    "SOURCE_REFRESH_RECORD_VM_CLAIM_011.json": "VM-CLAIM-011",
    "SOURCE_REFRESH_RECORD_VM_CLAIM_016.json": "VM-CLAIM-016",
}

REQUIRED_FIELDS = {
    "record_id",
    "classification",
    "publication_status",
    "execution_status",
    "record_status",
    "claim_id",
    "exact_claim_text",
    "source_family",
    "source_url_or_citation",
    "source_artifact_location",
    "retrieval_date",
    "custody_status",
    "evidence_mechanism",
    "reviewer",
    "decision",
    "remaining_limits",
    "claim_upgrade_authorized",
    "public_claim_authorized",
}

ALLOWED_SOURCE_FAMILIES = {
    "market_statistic",
    "regulatory_framework",
    "vendor_tool_capability",
    "api_security_reference",
    "sbom_supply_chain_reference",
    "purple_detection_reference",
    "dfir_custody_reference",
    "other",
}

STUB_ONLY_DECISIONS = {"stub_only_no_decision"}
REVIEWED_DECISIONS = {
    "confirmed_source_backed",
    "corrected_source_backed",
    "contradicted_do_not_use",
    "source_not_found",
    "source_inadequate",
    "stale_requires_newer_source",
    "retired",
}
EVIDENCE_MECHANISMS_WITH_REVIEW = {
    "source_snapshot",
    "source_url_and_retrieval_note",
    "hash_manifest",
    "archived_copy",
    "official_document_reference",
    "other_named_mechanism",
}

PROHIBITED_MARKERS = (
    "source retrieved",
    "source verified",
    "claim verified",
    "approved for publication",
    "public claim authorized",
    "external source checked",
    "evidence captured",
    "custody preserved",
)


def fail(message: str) -> None:
    print(json.dumps({"ok": False, "error": message}, sort_keys=True))
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - diagnostic path
        fail(f"failed to parse {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name}: expected JSON object")
    return value


def validate_schema_contract(schema: dict) -> None:
    if schema.get("title") != "Source Refresh Record":
        fail("unexpected source-refresh schema title")
    schema_required = set(schema.get("required", []))
    if not REQUIRED_FIELDS.issuperset(schema_required):
        fail(f"validator required fields missing schema required fields: {sorted(schema_required - REQUIRED_FIELDS)}")
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        fail("schema properties must be an object")
    for field in REQUIRED_FIELDS:
        if field not in props:
            fail(f"schema missing property used by validator: {field}")


def validate_record(path: Path, expected_claim_id: str) -> str:
    data = load_json(path)
    missing = sorted(REQUIRED_FIELDS - set(data))
    extra = sorted(set(data) - REQUIRED_FIELDS)
    if missing:
        fail(f"{path.name}: missing fields: {missing}")
    if extra:
        fail(f"{path.name}: unexpected fields: {extra}")
    if data["record_id"] != path.stem:
        fail(f"{path.name}: record_id must match filename stem")
    if data["claim_id"] != expected_claim_id:
        fail(f"{path.name}: claim_id must be {expected_claim_id}")
    if not re.fullmatch(r"VM-CLAIM-\d{3}", data["claim_id"]):
        fail(f"{path.name}: invalid claim_id format")
    if data["classification"] != "INTERNAL_ONLY":
        fail(f"{path.name}: classification must be INTERNAL_ONLY")
    if data["publication_status"] != "do_not_publish":
        fail(f"{path.name}: publication_status must be do_not_publish")
    if data["execution_status"] != "not_authorized":
        fail(f"{path.name}: execution_status must be not_authorized")
    if data["record_status"] == "stub_only":
        if data["decision"] not in STUB_ONLY_DECISIONS:
            fail(f"{path.name}: stub records must use stub_only_no_decision")
        if data["source_artifact_location"] != "not_retrieved":
            fail(f"{path.name}: source_artifact_location must remain not_retrieved for stub-only")
        if data["custody_status"] != "not_retrieved":
            fail(f"{path.name}: custody_status must remain not_retrieved for stub-only")
        if data["evidence_mechanism"] != "none_stub_only":
            fail(f"{path.name}: evidence_mechanism must remain none_stub_only")
        if data["reviewer"] != "not_assigned":
            fail(f"{path.name}: reviewer must remain not_assigned for stub-only")
    elif data["record_status"] in {
        "source_retrieved_pending_review",
        "reviewed_no_claim_upgrade",
        "reviewed_claim_update_proposed",
        "retired",
    }:
        if data["decision"] not in REVIEWED_DECISIONS:
            fail(f"{path.name}: decision {data['decision']} not valid for reviewed status {data['record_status']}")
        if data["reviewer"] in {"", "not_assigned"}:
            fail(f"{path.name}: reviewer must be assigned for reviewed records")
        if data["evidence_mechanism"] not in EVIDENCE_MECHANISMS_WITH_REVIEW:
            fail(f"{path.name}: evidence_mechanism must use a review mechanism for reviewed records")
        if data["source_artifact_location"] != "not_retrieved" and not data["source_artifact_location"].startswith("http"):
            fail(f"{path.name}: source_artifact_location for reviewed records must be source url/reference or not_retrieved")
        if data["decision"] == "source_not_found" and data["custody_status"] != "source_unavailable":
            fail(f"{path.name}: source_not_found requires custody_status source_unavailable")
    else:
        fail(f"{path.name}: unsupported record_status {data['record_status']}")
    if data["claim_upgrade_authorized"] is not False:
        fail(f"{path.name}: claim_upgrade_authorized must be false")
    if data["public_claim_authorized"] is not False:
        fail(f"{path.name}: public_claim_authorized must be false")
    if data["source_family"] not in ALLOWED_SOURCE_FAMILIES:
        fail(f"{path.name}: invalid source_family")
    if not isinstance(data["exact_claim_text"], str) or not data["exact_claim_text"].strip():
        fail(f"{path.name}: exact_claim_text must be non-empty")
    if not isinstance(data["source_url_or_citation"], str) or not data["source_url_or_citation"].strip():
        fail(f"{path.name}: source_url_or_citation must be non-empty")
    if not isinstance(data["remaining_limits"], list) or not data["remaining_limits"]:
        fail(f"{path.name}: remaining_limits must be a non-empty list")
    if data["record_status"] == "stub_only" and not any("not verified" in item.lower() or "not retrieved" in item.lower() for item in data["remaining_limits"]):
        fail(f"{path.name}: remaining_limits must preserve unverified/not-retrieved boundary")
    lowered = json.dumps(data, sort_keys=True).lower()
    for marker in PROHIBITED_MARKERS:
        if marker in lowered:
            fail(f"{path.name}: prohibited non-stub marker present: {marker}")
    return data["claim_id"]


def main() -> int:
    if not SCHEMA_PATH.exists():
        fail("schema missing")
    schema = load_json(SCHEMA_PATH)
    validate_schema_contract(schema)
    files = {p.name for p in RECORD_DIR.glob("SOURCE_REFRESH_RECORD_*.json")}
    if files != set(EXPECTED_RECORDS):
        fail(f"record inventory mismatch: expected={sorted(EXPECTED_RECORDS)} observed={sorted(files)}")
    seen_claim_ids: set[str] = set()
    for name, claim_id in sorted(EXPECTED_RECORDS.items()):
        observed_claim_id = validate_record(RECORD_DIR / name, claim_id)
        if observed_claim_id in seen_claim_ids:
            fail(f"duplicate claim_id observed: {observed_claim_id}")
        seen_claim_ids.add(observed_claim_id)
    print(json.dumps({
        "ok": True,
        "mode": "structure_only",
        "records_checked": len(EXPECTED_RECORDS),
        "inventory_checked": True,
        "schema_contract_checked": True,
        "unique_claim_ids_checked": True,
        "source_refresh_performed": False,
        "claim_verification_performed": False,
        "claim_upgrade_added": False,
        "runtime_evidence_created": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

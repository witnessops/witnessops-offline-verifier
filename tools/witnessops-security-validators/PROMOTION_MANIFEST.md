# Promotion Manifest

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
manifest_status: promotion_candidate
created_at_utc: 2026-05-03T19:59:09Z
structure_only: true
runtime_runners_included: false
live_testing_allowed: false
security_posture_claim_allowed: false
```

## Purpose

This manifest records the contents and boundary of the `witnessops-security-validators` promotion package.

The package is intended for controlled reuse in other WitnessOps repositories as CI or local structure-validation guardrails only.

## Included

| Path | Role |
| --- | --- |
| `README.md` | Package boundary, run instructions, and non-goals. |
| `ci/github-actions-security-validators.yml` | Copyable GitHub Actions example. |
| `scripts/validate-dfir-fixtures.py` | Structure-only DFIR fixture validator. |
| `scripts/validate-api-authz-fixtures.py` | Structure-only API authorization fixture validator. |
| `scripts/validate-sbom-supply-chain-fixtures.py` | Structure-only SBOM supply-chain fixture validator. |
| `scripts/validate-purple-detection-fixtures.py` | Structure-only purple detection fixture validator. |
| `scripts/validate-source-refresh-records.py` | Structure-only source-refresh record validator. |
| `schemas/` | Schema contracts used by validators or reviewed with fixtures. |
| `fixtures/` | Valid and invalid committed example fixtures used by validators. |
| `source-index/source-refresh-records/` | Source-refresh record examples required by `validate-source-refresh-records.py`. |

## Excluded

| Excluded Item | Reason |
| --- | --- |
| `scripts/run-dfir-fixture-runtime-proof.py` | Runtime package generation remains authority-gated. |
| `scripts/run-api-authz-fixture-runtime-proof.py` | Runtime package generation remains authority-gated. |
| `scripts/run-sbom-supply-chain-fixture-runtime-proof.py` | Runtime package generation remains authority-gated. |
| `scripts/run-purple-detection-fixture-runtime-proof.py` | Runtime package generation remains authority-gated. |
| Generated `receipts/` packages | Ignored local runtime artifacts are not portable repo evidence. |
| Publication, release, or claim-ledger update records | Promotion package does not authorize public or claim-status use. |

## Required Promotion Review

Before adopting this package into another repo, record:

```yaml
promotion_review:
  target_repo: required
  package_path: required
  validators_selected: required
  reviewer: required
  reviewed_at: required
  source_paths_reviewed: required
  forbidden_runtime_behavior_confirmed: required
  claim_language_boundary_confirmed: required
  ci_path: required_if_enabled
```

## Status

```yaml
witnessops_security_validators_package:
  package_created: true
  validators_included: 5
  schemas_included: true
  fixtures_included: true
  source_refresh_records_included: true
  ci_example_included: true
  runtime_runners_included: false
  live_testing_authorized: false
  security_posture_claim_authorized: false
```

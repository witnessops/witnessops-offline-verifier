# WitnessOps Security Validators Promotion Package

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
package_status: promotion_candidate
created_at_utc: 2026-05-03T19:59:09Z
structure_only: true
live_testing_allowed: false
security_posture_claim_allowed: false
runtime_evidence_created: false
```

## Boundary

This package contains structure-only validators and their local examples for promotion into other WitnessOps repositories.

It is structure-only; no live testing; no security posture claim.

The validators inspect committed JSON fixtures, schemas, and source-refresh records. They do not access live systems, contact external targets, use credentials, scan dependencies, inspect repositories, collect telemetry, run adversary emulation, create runtime evidence, authorize publication, or prove production security posture.

## Included Validators

| Validator | Scope | Not A Claim Of |
| --- | --- | --- |
| `scripts/validate-dfir-fixtures.py` | Harmless DFIR fixture manifest, receipt, verification, and hash-shape checks. | Real incident response, forensic acquisition, legal admissibility, malware handling, or customer evidence readiness. |
| `scripts/validate-api-authz-fixtures.py` | Synthetic/local API authorization fixture, matrix, observed-decision, receipt, and overclaim checks. | Live API authorization posture, endpoint testing, credential use, fuzzing, or production API security. |
| `scripts/validate-sbom-supply-chain-fixtures.py` | Synthetic/local SBOM supply-chain fixture, inventory, receipt, and overclaim checks. | SBOM completeness, standards conformance, dependency scanning, vulnerability status, registry checks, or production supply-chain posture. |
| `scripts/validate-purple-detection-fixtures.py` | Synthetic/local purple detection scenario, expectation, observed-result, receipt, and overclaim checks. | Adversary emulation, BAS execution, live telemetry validation, or production detection coverage. |
| `scripts/validate-source-refresh-records.py` | Source-refresh record schema, inventory, status, claim-upgrade, and public-claim boundary checks. | Source retrieval, claim verification, publication approval, or claim-ledger upgrade. |

## Package Layout

```text
witnessops-security-validators/
  README.md
  PROMOTION_MANIFEST.md
  ci/
    github-actions-security-validators.yml
  scripts/
    validate-dfir-fixtures.py
    validate-api-authz-fixtures.py
    validate-sbom-supply-chain-fixtures.py
    validate-purple-detection-fixtures.py
    validate-source-refresh-records.py
  schemas/
    dfir-fixture/
    api-authz/
    sbom-supply-chain/
    purple-detection/
    source-refresh/
  fixtures/
    dfir-fixture/
    api-authz/
    sbom-supply-chain/
    purple-detection/
  source-index/
    source-refresh-records/
```

## Run Locally

Run from this package root:

```bash
python3 scripts/validate-dfir-fixtures.py
python3 scripts/validate-api-authz-fixtures.py
python3 scripts/validate-sbom-supply-chain-fixtures.py
python3 scripts/validate-purple-detection-fixtures.py
python3 scripts/validate-source-refresh-records.py
```

Expected successful runs print JSON with `"ok": true` and explicit false flags for live/runtime behavior where applicable.

## Promotion Use

Recommended promotion pattern:

1. Copy `witnessops-security-validators/` into the target repo.
2. Keep the package as a review-only CI guardrail first.
3. Run the five validators from the package root.
4. Adopt one validator at a time into the target repo's native paths only after its fixtures and limits are reviewed.
5. Keep runtime proof runners out of scope unless a separate authority-gated lane defines output path, preservation decision, stop conditions, and closure criteria.

## CI Example

Use `ci/github-actions-security-validators.yml` as a copyable GitHub Actions example. It assumes the package is committed under:

```text
witnessops-security-validators/
```

If the package is placed somewhere else, update the workflow `working-directory` value.

## Non-Goals

- No live API testing.
- No endpoint, cloud, identity, email, or network testing.
- No dependency, package, registry, vulnerability, or license scanning.
- No adversary emulation, BAS tooling, attack commands, or telemetry collection.
- No incident response, forensic acquisition, malware handling, or customer evidence work.
- No source retrieval, source verification, claim upgrade, publication approval, or customer-facing proof claim.

## Closure Language

Allowed:

```text
The promoted validators passed structure-only checks against committed examples.
```

Not allowed:

```text
The target repo is secure, verified, production-ready, customer-ready, or covered by security proof.
```

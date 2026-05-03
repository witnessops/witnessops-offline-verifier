# Purple Detection Schemas

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
schema_status: seed
checker_mode: structure_only
```

## Purpose

These schemas define the structure-only artifact contract for a future synthetic/local purple-team detection validation fixture.

They do not authorize adversary emulation, BAS tooling, attack commands, live telemetry collection, endpoint/cloud/identity/email/network testing, malware handling, customer work, or production detection claims.

## Schemas

| Schema | Purpose |
| --- | --- |
| `scenario-declaration.schema.json` | Synthetic scenario declaration and no-live/no-command flags. |
| `detection-expectation.schema.json` | Expected synthetic detection result. |
| `observed-result.schema.json` | Observed synthetic fixture result. |
| `evidence-manifest.schema.json` | Required artifact list and hash records. |
| `receipt.schema.json` | Receipt and closure-state contract. |
| `verification.schema.json` | Structure-only verification result. |

## Boundary

All schemas require or assume:

- `classification: INTERNAL_ONLY`
- `target_boundary: synthetic_fixture_only`
- no adversary emulation execution
- no BAS tooling execution
- no attack commands or payloads
- no live telemetry
- no credentials, tokens, cookies, sessions, or secrets
- no customer, third-party, or personal data
- no production detection claim

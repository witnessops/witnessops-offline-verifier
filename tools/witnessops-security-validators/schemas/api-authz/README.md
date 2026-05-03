# API Authorization Schemas

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
schema_status: seed
checker_mode: structure_only
```

## Purpose

These schemas define the structure-only artifact contract for a future synthetic/local API authorization fixture.

They do not authorize live API testing, customer testing, external target testing, credential use, fuzzing, rate-limit testing, or exploitation.

## Schemas

| Schema | Purpose |
| --- | --- |
| `fixture.schema.json` | Synthetic actors and objects. |
| `authorization-matrix.schema.json` | Expected allow/deny decisions. |
| `observed-decisions.schema.json` | Observed decisions produced by a future local fixture run. |
| `evidence-manifest.schema.json` | Required artifact list and hash records. |
| `receipt.schema.json` | Receipt and closure-state contract. |
| `verification.schema.json` | Structure-only verification result. |

## Boundary

All schemas require or assume:

- `classification: INTERNAL_ONLY`
- `target_boundary: synthetic_local_fixture_only`
- no live API target
- no credentials, tokens, cookies, sessions, or API keys
- no customer, third-party, or personal data
- no public proof claim

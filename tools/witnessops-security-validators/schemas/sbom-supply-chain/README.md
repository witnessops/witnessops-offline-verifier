# SBOM Supply Chain Schemas

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
schema_status: seed
checker_mode: structure_only
```

## Purpose

These schemas define the structure-only artifact contract for a future synthetic/local SBOM supply-chain fixture.

They do not authorize dependency scanning, live repository analysis, package registry queries, vulnerability scanning, malware analysis, license/legal determinations, or production supply-chain claims.

## Schemas

| Schema | Purpose |
| --- | --- |
| `source-declaration.schema.json` | Synthetic/local source declaration and no-network/no-secret flags. |
| `component-inventory.schema.json` | Synthetic component inventory shape. |
| `evidence-manifest.schema.json` | Required artifact list and hash records. |
| `receipt.schema.json` | Receipt and closure-state contract. |
| `verification.schema.json` | Structure-only verification result. |

## Boundary

All schemas require or assume:

- `classification: INTERNAL_ONLY`
- `target_boundary: synthetic_local_fixture_only`
- no live repository or package analysis
- no registry queries
- no credentials, tokens, cookies, sessions, or API keys
- no customer, third-party, or personal data
- no completeness, vulnerability, license, or production security claim

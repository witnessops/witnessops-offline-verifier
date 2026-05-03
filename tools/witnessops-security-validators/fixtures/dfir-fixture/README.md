# DFIR Fixture Examples

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
fixture_status: schema_examples_only
runtime_evidence_package: false
```

## Purpose

These fixtures exercise the DFIR fixture schemas. They are examples only.

They do not prove that a custody dry run occurred. They do not represent real evidence, real incident response, forensic acquisition, malware handling, or customer work.

## Directories

| Directory | Purpose |
| --- | --- |
| `valid/` | Examples expected to satisfy their corresponding schema. |
| `invalid/` | Examples expected to fail schema validation or checker policy. |

## Boundary

- No generated runtime evidence package is committed here.
- No live system data is represented here.
- No malware, customer data, personal data, secrets, tokens, credentials, or forensic captures are represented here.
- These examples exist only to support future structure-only checker validation.

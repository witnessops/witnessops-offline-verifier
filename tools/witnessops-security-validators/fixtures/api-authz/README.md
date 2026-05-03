# API Authorization Fixture Examples

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
fixture_status: schema_examples_only
runtime_evidence_package: false
live_api_testing: false
```

## Purpose

These fixtures exercise the API authorization schemas using synthetic local data only.

They do not prove any production authorization posture and do not test a live API.

## Directories

| Directory | Purpose |
| --- | --- |
| `valid/` | Examples expected to satisfy the API authorization schema set. |
| `invalid/` | Examples expected to fail schema or policy validation. |

## Boundary

- No live API endpoint is represented here.
- No credential, token, cookie, session, header, or API key is represented here.
- No customer, third-party, or personal data is represented here.
- No fuzzing, exploit, rate-limit, or denial-of-service material is represented here.
- These examples exist only to support future structure-only validation.

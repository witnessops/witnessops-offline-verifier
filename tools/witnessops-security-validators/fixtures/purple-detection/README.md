# Purple Detection Fixture Examples

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
fixture_status: schema_examples_only
runtime_evidence_package: false
```

## Purpose

These fixtures exercise the purple detection schemas using synthetic local data only.

They do not prove production detection coverage and do not execute adversary emulation, BAS tooling, attack commands, or telemetry collection.

## Directories

| Directory | Purpose |
| --- | --- |
| `valid/` | Examples expected to satisfy the purple detection schema set. |
| `invalid/` | Examples expected to fail schema or policy validation. |

## Boundary

- No adversary emulation is represented here.
- No BAS tooling is represented here.
- No attack command or payload is represented here.
- No live telemetry is represented here.
- No endpoint, cloud, identity, email, or network target is represented here.
- No credential, token, cookie, session, secret, customer, third-party, or personal data is represented here.
- No production detection claim is represented here.

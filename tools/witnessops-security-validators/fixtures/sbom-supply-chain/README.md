# SBOM Supply Chain Fixture Examples

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
fixture_status: schema_examples_only
runtime_evidence_package: false
```

## Purpose

These fixtures exercise the SBOM supply-chain schemas using synthetic local data only.

They do not prove any production supply-chain posture and do not analyze a live repository, package, registry, vulnerability, license, or dependency graph.

## Directories

| Directory | Purpose |
| --- | --- |
| `valid/` | Examples expected to satisfy the SBOM supply-chain schema set. |
| `invalid/` | Examples expected to fail schema or policy validation. |

## Boundary

- No dependency scan is represented here.
- No live repository or package analysis is represented here.
- No package registry query is represented here.
- No vulnerability, license, malware, or completeness claim is represented here.
- No credential, token, cookie, session, header, or API key is represented here.
- No customer, third-party, or personal data is represented here.

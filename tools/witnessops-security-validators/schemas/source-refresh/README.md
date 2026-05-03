# Source Refresh Schemas

```yaml
classification: INTERNAL_ONLY
publication_status: do_not_publish
execution_status: not_authorized
schema_status: structure_only
source_refresh_performed: false
claim_upgrade_added: false
runtime_evidence_created: false
```

## Purpose

This directory defines structure-only contracts for future source-refresh records.

The schemas do not retrieve sources, verify claims, upgrade claim statuses, authorize publication, or create runtime evidence.

## Schemas

| Schema | Purpose |
| --- | --- |
| `record.schema.json` | Defines the required shape for a future source-refresh record. |

## Boundary

A schema-valid source-refresh record proves only that a record has the expected shape. It does not prove the source is authoritative, current, complete, or correctly interpreted.

Claim upgrade remains blocked unless a separate reviewer decision and claim-ledger update lane names the evidence path.

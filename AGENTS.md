# AGENTS.md

## Scope

This repository governs offline package verification tooling and verifier execution behavior.
It is not a proof signer, key-custody authority, schema authority, deployment target,
or evidence-collection surface by default.

## Non-negotiable rules

- Do not weaken verifier acceptance semantics to make a package pass.
- Do not treat skipped checks as passed checks.
- Do not infer source-system integrity, deployment trust, execution truth, or customer assurance from local package consistency alone.
- Do not add network dependencies to default offline verification paths.
- Do not include private keys, credentials, customer records, cloud secrets, or live operational evidence bundles in commits.
- Evidence and replayability requirements are required for verification behavior changes.
- Report and preserve exact command intent before claiming completion.

## Required commands

- Install dev dependencies: `pip install -r requirements-dev.txt`
- Run verifier baseline tests: `pytest -q`
- Run the repo's pinned schema checks before merging schema-affecting changes.

## Repo-specific governance

- Schema source and key-registry source must be deterministic and explicitly reported.
- A failing schema/source check or key-registry mismatch is a hard blocker for accepting packages.
- Do not change verifier acceptance policy without updating corresponding fixtures and negative tests.


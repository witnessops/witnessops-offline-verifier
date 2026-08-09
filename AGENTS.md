# AGENTS.md

## Scope

This repository is an **EXPERIMENTAL** public verifier prototype, demonstration
surface, and possible future distribution candidate.

It is not the canonical WitnessOps verifier implementation and is not currently
a supported public verifier distribution. Canonical internal verifier
implementation authority belongs to `witnessops-verifier`; canonical schema
authority belongs to `witnessops-contracts`. Promotion requires an explicit
conformance and distribution decision.

It is not a proof signer, key-custody authority, schema authority, deployment
target, or evidence-collection surface by default.

## Non-negotiable rules

- Do not describe this repository as canonical, production, or a supported public verifier distribution.
- Do not weaken verifier acceptance semantics to make a package pass.
- Do not treat skipped checks as passed checks.
- Do not infer source-system integrity, deployment trust, execution truth, signer authorization, production custody, or customer assurance from local package consistency alone.
- Do not add network dependencies to default offline verification paths.
- Do not include private keys, credentials, customer records, cloud secrets, production trust roots, or live operational evidence bundles in commits.
- Treat the checked-in certificates and timestamp token as demo fixtures only.
- Preserve exact command intent and test output before claiming completion.

## Required commands

This is a Node.js/Next.js repository. Do not use Python verifier commands such
as `pip install -r requirements-dev.txt` or `pytest -q` for the application
and CLI.

Use Node.js 22.

Run the zero-dependency functional sample suite:

```bash
npm test
```

For application or dependency changes, install the locked dependency graph and
build the Next.js application:

```bash
npm ci
npm run build
```

Run the development UI only when interactive behavior needs inspection:

```bash
npm run dev
```

The separate structure-only security-validator package under
`tools/witnessops-security-validators/` has its own Python workflow. Its checks
do not establish functional verifier conformance.

## Repo-specific governance

- Trust source must be deterministic and explicitly reported.
- A failing signature, payload, chain, or local-policy check must remain failure-visible.
- Do not change the prototype's acceptance or disposition policy without updating corresponding fixtures and functional tests.
- A passing sample test proves this implementation matches its checked-in experimental fixtures only; it does not prove parity with `witnessops-verifier` or production readiness.

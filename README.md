# WitnessOps Offline Verifier

> **Status: EXPERIMENTAL**
>
> This public repository is a verifier prototype, demonstration surface, and
> possible future distribution candidate. It is not the canonical WitnessOps
> verifier implementation and is not currently a supported public verifier
> distribution.

The canonical internal verifier implementation is
`witnessops/witnessops-verifier`. Canonical contract schemas are owned by
`witnessops/witnessops-contracts`. A later conformance and distribution
decision is required before this repository can be promoted beyond
experimental status.

This repository contains a small local verifier for WitnessOps-style
certificate/JWS demo bundles. Its verification vocabulary and bundle shape are
specific to this experiment; they must not be assumed to match the canonical
internal verifier's acceptance contract.

It includes:

- `verify-bundle.mjs` — a single-file, zero-runtime-dependency Node CLI.
- `app/page.tsx` — a minimal Next.js dropzone UI.
- `app/api/verify/route.ts` — a local `/api/verify` bridge that writes uploaded files to a temp directory and calls the CLI.
- `samples/` — four demonstration bundles covering `verified`, `inferred`, `declared`, and `not-proven`.
- `trust/roots/` — local demo trust policy used by this prototype.

## Evidentiary boundary

A result establishes only the checks performed by this implementation over the
supplied files and local trust roots. It does not establish production signer
authorization, production key custody, source-system truth, evidence
completeness, or conformance with the canonical internal verifier.

The optional `timestamp.jws` is a deliberately simplified demo token. It is
not RFC 3161 validation and must not be represented as production timestamp
verification.

## Bundle layout

```text
receipt.json
receipt.jws
signer/00-leaf.pem
signer/01-root.pem
timestamp.jws        # optional demo timestamp token
tsa/00-tsa.pem       # optional timestamp authority cert chain
tsa/01-root.pem
```

`receipt.jws` is compact JWS. Its payload bytes must exactly match
`receipt.json`.

`timestamp.jws` is a demo JWS timestamp token over the `receipt.jws`
artifact hash. It is intentionally simple so the experiment stays
dependency-light. A deliberately reviewed implementation would need to replace
`verifyTimestampToken()` in `verify-bundle.mjs` with the selected production
timestamp contract before promotion.

## Run the CLI

Requires Node.js 22.

```bash
node verify-bundle.mjs samples/bundle-good
node verify-bundle.mjs samples/bundle-good --json
node verify-bundle.mjs samples/bundle-inferred --strict
node verify-bundle.mjs samples/bundle-declared --no-default-trust
```

Exit codes:

- `0` for `verified`, `inferred`, or `declared` by default.
- `2` for `not_proven`.
- `3` for non-`verified` when `--strict` is set.

## Run the functional sample tests

The functional tests exercise all four sample dispositions through the same
`verifyBundle` implementation exported by the CLI.

```bash
npm test
```

## Run the dropzone

```bash
npm ci
npm run dev
```

Open `/verify` on the local Next.js URL, then use the sample buttons or drop
one of the `samples/bundle-*` folders.

The UI and CLI use the same experimental phrasing:

- **Verified** — signature, chain, local demo policy, and trusted demo issuance time check out.
- **Inferred** — signature and chain check out, but issuance time is declared only.
- **Declared only** — signature is valid, but the signer is not anchored in local demo trust policy.
- **Not proven** — cryptographic proof failed, is missing, or does not match the bundle.

These are dispositions of this prototype, not organization-wide WitnessOps
receipt or verifier semantics.

## Sample bundles

| Bundle | Expected disposition | Why |
|---|---:|---|
| `samples/bundle-good` | `verified` | Trusted demo signer chain + trusted demo timestamp chain + receipt match. |
| `samples/bundle-inferred` | `inferred` | Trusted demo signer chain, no trusted timestamp. |
| `samples/bundle-declared` | `declared` | Signature is valid, but signer root is not in local demo trust policy. |
| `samples/bundle-tampered` | `not_proven` | `receipt.json` was changed after signing. |

## Trust policy

The verifier does not call out to the network. Trust is whatever is present in
`trust/roots/` or passed with `--trust-dir`. The checked-in roots are demo
fixtures, not production WitnessOps trust or custody authority.

To try another local issuer:

```bash
cp your-root.pem trust/roots/
node verify-bundle.mjs path/to/bundle --json
```

Do not commit private keys, credentials, customer material, or production trust
roots. To make every signed-but-unanchored bundle show as `declared`, remove
local roots from `trust/roots` or pass `--no-default-trust`.

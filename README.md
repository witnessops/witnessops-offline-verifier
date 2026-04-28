# WitnessOps Offline Verifier

A tiny local verifier for WitnessOps-style proof bundles.

It includes:

- `verify-bundle.mjs` — a single-file, zero-runtime-dependency Node CLI.
- `app/page.tsx` — a minimal Next.js dropzone UI.
- `app/api/verify/route.ts` — a local `/api/verify` bridge that writes uploaded files to a temp directory and calls the CLI.
- `samples/` — four bundles covering `verified`, `inferred`, `declared`, and `not-proven`.
- `trust/roots/` — the local trust policy. Add or remove root certificates here.

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

`receipt.jws` is compact JWS. Its payload bytes must exactly match `receipt.json`.

`timestamp.jws` is a demo JWS timestamp token over the `receipt.jws` artifact hash. It is intentionally simple so the whole PoC stays dependency-light. Replace `verifyTimestampToken()` in `verify-bundle.mjs` with RFC 3161 `.tsr` validation when you wire a real TSA.

## Run the CLI

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

## Run the dropzone

```bash
npm install
npm run dev
```

Open `/verify` on the local Next.js URL, then use the sample buttons or drop one of the `samples/bundle-*` folders.

The UI and CLI use the same phrasing:

- **Verified** — signature, chain, policy, and trusted issuance time check out.
- **Inferred** — signature and chain check out, but issuance time is declared only.
- **Declared only** — signature is valid, but the signer is not anchored in local trust policy.
- **Not proven** — cryptographic proof failed, is missing, or does not match the bundle.

## Sample bundles

| Bundle | Expected disposition | Why |
|---|---:|---|
| `samples/bundle-good` | `verified` | Trusted signer chain + trusted timestamp chain + receipt match. |
| `samples/bundle-inferred` | `inferred` | Trusted signer chain, no trusted timestamp. |
| `samples/bundle-declared` | `declared` | Signature is valid, but signer root is not in `trust/roots`. |
| `samples/bundle-tampered` | `not_proven` | `receipt.json` was changed after signing. |

## Trust policy

The verifier does not call out to the network. Trust is whatever is present in `trust/roots/` or passed with `--trust-dir`.

To trust another issuer:

```bash
cp your-root.pem trust/roots/
node verify-bundle.mjs path/to/bundle --json
```

To make every signed-but-unanchored bundle show as `declared`, remove roots from `trust/roots` or pass `--no-default-trust`.

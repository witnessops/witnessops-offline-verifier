#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto, { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const VERIFY_PHRASES = {
  verified: 'Verified — signature, chain, policy, and trusted issuance time check out.',
  inferred: 'Inferred — signature and chain check out, but issuance time is declared only.',
  declared: 'Declared only — signature is valid, but the signer is not anchored in local trust policy.',
  not_proven: 'Not proven — cryptographic proof failed, is missing, or does not match the bundle.'
};

function usage() {
  console.log(`Usage: node verify-bundle.mjs <bundle-dir> [--json] [--strict] [--trust-dir <dir>] [--no-default-trust]

Offline verifier for a WitnessOps-style proof bundle.

Bundle layout:
  receipt.json
  receipt.jws            # compact JWS, payload bytes must equal receipt.json
  signer/00-leaf.pem     # leaf first, then intermediates/root
  timestamp.jws          # optional demo timestamp token over receipt.jws
  tsa/00-tsa.pem         # optional TSA chain for timestamp.jws

Dispositions:
  verified    signature + trusted chain + trusted issuance time
  inferred    signature + trusted chain, but no trusted timestamp
  declared    signature OK, but signer is not in local trust store
  not_proven  missing proof, bad signature, tamper, bad chain, or policy failure

Examples:
  node verify-bundle.mjs samples/bundle-good
  node verify-bundle.mjs samples/bundle-good --json
  node verify-bundle.mjs samples/bundle-inferred --strict
`);
}

function parseArgs(argv) {
  const opts = {
    json: false,
    strict: false,
    noDefaultTrust: false,
    trustDirs: [],
    bundleDir: null
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') opts.json = true;
    else if (arg === '--strict') opts.strict = true;
    else if (arg === '--no-default-trust') opts.noDefaultTrust = true;
    else if (arg === '--trust-dir') {
      const val = argv[++i];
      if (!val) throw new Error('--trust-dir requires a directory');
      opts.trustDirs.push(path.resolve(val));
    } else if (arg === '-h' || arg === '--help') {
      opts.help = true;
    } else if (!opts.bundleDir) {
      opts.bundleDir = path.resolve(arg);
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }
  if (!opts.noDefaultTrust) {
    opts.trustDirs.push(path.resolve(process.cwd(), 'trust', 'roots'));
    opts.trustDirs.push(path.resolve(__dirname, 'trust', 'roots'));
  }
  opts.trustDirs = [...new Set(opts.trustDirs)];
  return opts;
}

function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

function readText(p) {
  return fs.readFileSync(p, 'utf8').trim();
}

function b64urlDecode(input) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function b64urlJson(input) {
  return JSON.parse(b64urlDecode(input).toString('utf8'));
}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function parseCompactJws(jwsText) {
  const compact = jwsText.trim();
  const parts = compact.split('.');
  if (parts.length !== 3) throw new Error('JWS must use compact serialization with three dot-separated parts');
  const [protectedPart, payloadPart, signaturePart] = parts;
  return {
    compact,
    protectedPart,
    payloadPart,
    signaturePart,
    header: b64urlJson(protectedPart),
    payloadBytes: b64urlDecode(payloadPart),
    signatureBytes: b64urlDecode(signaturePart),
    signingInput: Buffer.from(`${protectedPart}.${payloadPart}`, 'ascii')
  };
}

function verifyCompactJwsWithCert(jwsText, cert) {
  const parsed = parseCompactJws(jwsText);
  const alg = parsed.header.alg;
  let ok = false;

  if (alg === 'RS256') {
    ok = crypto.verify('RSA-SHA256', parsed.signingInput, cert.publicKey, parsed.signatureBytes);
  } else if (alg === 'PS256') {
    ok = crypto.verify('sha256', parsed.signingInput, {
      key: cert.publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32
    }, parsed.signatureBytes);
  } else if (alg === 'ES256') {
    ok = crypto.verify('sha256', parsed.signingInput, {
      key: cert.publicKey,
      dsaEncoding: 'ieee-p1363'
    }, parsed.signatureBytes);
  } else if (alg === 'EdDSA') {
    ok = crypto.verify(null, parsed.signingInput, cert.publicKey, parsed.signatureBytes);
  } else {
    throw new Error(`Unsupported JWS alg: ${alg}`);
  }

  return { ok, parsed, alg };
}

function certDate(cert, field) {
  if (field === 'from' && cert.validFromDate) return cert.validFromDate;
  if (field === 'to' && cert.validToDate) return cert.validToDate;
  return new Date(field === 'from' ? cert.validFrom : cert.validTo);
}

function certIsTimeValid(cert, when) {
  const from = certDate(cert, 'from');
  const to = certDate(cert, 'to');
  return when >= from && when <= to;
}

function loadCertFilesFromDir(dir) {
  if (!exists(dir)) return [];
  return fs.readdirSync(dir)
    .filter((name) => /\.(pem|crt|cer)$/i.test(name))
    .sort((a, b) => a.localeCompare(b))
    .map((name) => path.join(dir, name));
}

function loadCertChain(dir) {
  const files = loadCertFilesFromDir(dir);
  return files.map((file) => {
    const pem = fs.readFileSync(file);
    const cert = new X509Certificate(pem);
    return { file, cert };
  });
}

function loadTrustRoots(trustDirs) {
  const roots = [];
  for (const dir of trustDirs) {
    for (const file of loadCertFilesFromDir(dir)) {
      try {
        const cert = new X509Certificate(fs.readFileSync(file));
        roots.push({ file, cert, fingerprint256: cert.fingerprint256 });
      } catch (err) {
        roots.push({ file, error: err.message });
      }
    }
  }
  return roots;
}

function formatCert(cert) {
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    ca: cert.ca
  };
}

function validateCertChain(chainEntries, trustRoots, validationTime) {
  const errors = [];
  const chain = chainEntries.map((x) => x.cert);

  if (chain.length === 0) {
    return { ok: false, anchored: false, errors: ['No signer certificate chain found'], trustAnchor: null };
  }

  for (let i = 0; i < chain.length; i += 1) {
    if (!certIsTimeValid(chain[i], validationTime)) {
      errors.push(`Certificate ${i} is not valid at ${validationTime.toISOString()}`);
    }
  }

  for (let i = 0; i < chain.length - 1; i += 1) {
    const child = chain[i];
    const issuer = chain[i + 1];
    if (!child.checkIssued(issuer)) {
      errors.push(`Certificate ${i} issuer does not match certificate ${i + 1} subject`);
    }
    if (!child.verify(issuer.publicKey)) {
      errors.push(`Certificate ${i} signature does not verify against certificate ${i + 1}`);
    }
  }

  const usableTrustRoots = trustRoots.filter((r) => r.cert);
  let trustAnchor = null;
  const terminal = chain[chain.length - 1];

  for (const root of usableTrustRoots) {
    if (terminal.fingerprint256 === root.cert.fingerprint256) {
      trustAnchor = root;
      break;
    }
    if (terminal.checkIssued(root.cert) && terminal.verify(root.cert.publicKey)) {
      trustAnchor = root;
      break;
    }
  }

  if (!trustAnchor) {
    errors.push('No local trust root anchors the signer chain');
  } else if (!certIsTimeValid(trustAnchor.cert, validationTime)) {
    errors.push(`Trust root is not valid at ${validationTime.toISOString()}`);
  }

  return {
    ok: errors.length === 0 && Boolean(trustAnchor),
    anchored: Boolean(trustAnchor),
    errors,
    trustAnchor: trustAnchor ? { file: trustAnchor.file, ...formatCert(trustAnchor.cert) } : null
  };
}

function timingSafeStringEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function findJwsFile(bundleDir) {
  const candidates = ['receipt.jws', 'signature.jws', 'signature'];
  for (const name of candidates) {
    const p = path.join(bundleDir, name);
    if (exists(p)) return p;
  }
  throw new Error('Missing receipt.jws or signature.jws');
}

function parseJsonBytes(bytes) {
  return JSON.parse(Buffer.from(bytes).toString('utf8'));
}

function verifyTimestampToken(bundleDir, trustRoots, artifactBytes) {
  const timestampPath = path.join(bundleDir, 'timestamp.jws');
  if (!exists(timestampPath)) {
    return {
      present: false,
      trusted: false,
      source: 'none',
      time: null,
      errors: ['No timestamp.jws found']
    };
  }

  const errors = [];
  try {
    const tsaChain = loadCertChain(path.join(bundleDir, 'tsa'));
    if (tsaChain.length === 0) throw new Error('timestamp.jws exists, but tsa/ chain is missing');

    const tokenText = readText(timestampPath);
    const sig = verifyCompactJwsWithCert(tokenText, tsaChain[0].cert);
    if (!sig.ok) errors.push('Timestamp token signature failed');

    const payload = parseJsonBytes(sig.parsed.payloadBytes);
    const genTime = payload.genTime || payload.time;
    if (!genTime) errors.push('Timestamp token payload missing genTime');

    const expected = sha256Hex(artifactBytes);
    const actual = String(payload.artifact_hash_sha256 || payload.message_hash || '').toLowerCase();
    if (!actual || !timingSafeStringEqual(expected, actual)) {
      errors.push('Timestamp token hash does not match receipt.jws');
    }

    const validationTime = genTime ? new Date(genTime) : new Date();
    if (Number.isNaN(validationTime.getTime())) errors.push(`Invalid timestamp genTime: ${genTime}`);

    const chainCheck = validateCertChain(tsaChain, trustRoots, validationTime);
    if (!chainCheck.ok) errors.push(...chainCheck.errors.map((e) => `TSA chain: ${e}`));

    return {
      present: true,
      trusted: errors.length === 0,
      source: 'timestamp.jws',
      time: genTime || null,
      signer: formatCert(tsaChain[0].cert),
      trustAnchor: chainCheck.trustAnchor,
      payload,
      errors
    };
  } catch (err) {
    return {
      present: true,
      trusted: false,
      source: 'timestamp.jws',
      time: null,
      errors: [err.message]
    };
  }
}

async function verifyBundle(bundleDir, opts = {}) {
  const trustDirs = opts.trustDirs || [];
  const trustRoots = loadTrustRoots(trustDirs);
  const receiptPath = path.join(bundleDir, 'receipt.json');
  const signerDir = path.join(bundleDir, 'signer');
  const checks = {
    receipt_present: false,
    receipt_matches_signature_payload: false,
    signature: false,
    signer_chain: false,
    local_policy: false,
    trusted_issuance_time: false
  };
  const errors = [];

  try {
    if (!exists(receiptPath)) throw new Error('Missing receipt.json');
    checks.receipt_present = true;
    const receiptBytes = fs.readFileSync(receiptPath);
    const receipt = JSON.parse(receiptBytes.toString('utf8'));
    const jwsPath = findJwsFile(bundleDir);
    const jwsText = readText(jwsPath);
    const signerChain = loadCertChain(signerDir);
    if (signerChain.length === 0) throw new Error('Missing signer/ certificate chain');

    const sig = verifyCompactJwsWithCert(jwsText, signerChain[0].cert);
    checks.signature = sig.ok;
    if (!sig.ok) errors.push('JWS signature failed');

    checks.receipt_matches_signature_payload = Buffer.compare(sig.parsed.payloadBytes, receiptBytes) === 0;
    if (!checks.receipt_matches_signature_payload) {
      errors.push('receipt.json bytes do not match the signed JWS payload');
    }

    const timestamp = verifyTimestampToken(bundleDir, trustRoots, Buffer.from(jwsText, 'utf8'));
    checks.trusted_issuance_time = timestamp.trusted;
    const chainValidationTime = timestamp.trusted ? new Date(timestamp.time) : new Date();

    const signerChainCheck = validateCertChain(signerChain, trustRoots, chainValidationTime);
    checks.signer_chain = signerChainCheck.ok;
    checks.local_policy = signerChainCheck.anchored;
    if (!signerChainCheck.ok) errors.push(...signerChainCheck.errors);

    let status = 'not_proven';
    if (checks.signature && checks.receipt_matches_signature_payload) {
      if (checks.signer_chain && checks.trusted_issuance_time) status = 'verified';
      else if (checks.signer_chain && !checks.trusted_issuance_time) status = 'inferred';
      else status = 'declared';
    }

    return {
      status,
      disposition: status.replace('_', '-'),
      phrase: VERIFY_PHRASES[status],
      bundle: path.resolve(bundleDir),
      signer: formatCert(signerChain[0].cert),
      algorithm: sig.alg,
      issuanceTime: timestamp.trusted
        ? { value: timestamp.time, trusted: true, source: timestamp.source }
        : { value: receipt.issued_at || receipt.iat || null, trusted: false, source: timestamp.present ? 'untrusted timestamp.jws' : 'receipt declaration' },
      checks,
      chain: {
        validationTime: chainValidationTime.toISOString(),
        trustAnchor: signerChainCheck.trustAnchor,
        errors: signerChainCheck.errors,
        certificates: signerChain.map(({ file, cert }) => ({ file: path.relative(bundleDir, file), ...formatCert(cert) }))
      },
      timestamp,
      receipt,
      errors
    };
  } catch (err) {
    return {
      status: 'not_proven',
      disposition: 'not-proven',
      phrase: VERIFY_PHRASES.not_proven,
      bundle: path.resolve(bundleDir),
      signer: null,
      algorithm: null,
      issuanceTime: { value: null, trusted: false, source: 'none' },
      checks,
      chain: { validationTime: new Date().toISOString(), trustAnchor: null, errors: [], certificates: [] },
      timestamp: { present: false, trusted: false, source: 'none', time: null, errors: [] },
      receipt: null,
      errors: [err.message]
    };
  }
}

function symbol(value) {
  return value ? '✓' : '✗';
}

function printHuman(result) {
  console.log(result.phrase);
  console.log(`Bundle: ${result.bundle}`);
  console.log(`Disposition: ${result.disposition}`);
  console.log(`Signer: ${result.signer ? result.signer.subject : 'unknown'}`);
  console.log(`Algorithm: ${result.algorithm || 'unknown'}`);
  console.log(`Issuance time: ${result.issuanceTime.value || 'not proven'} (${result.issuanceTime.trusted ? 'trusted' : 'declared/untrusted'} via ${result.issuanceTime.source})`);
  console.log(`Trust anchor: ${result.chain?.trustAnchor?.subject || 'none'}`);
  console.log('Checks:');
  for (const [name, value] of Object.entries(result.checks || {})) {
    console.log(`  ${symbol(value)} ${name}`);
  }
  if (result.errors?.length) {
    console.log('Findings:');
    for (const err of result.errors) console.log(`  - ${err}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.help || !opts.bundleDir) {
      usage();
      process.exit(opts.help ? 0 : 1);
    }
    const result = await verifyBundle(opts.bundleDir, opts);
    if (opts.json) console.log(JSON.stringify(result, null, 2));
    else printHuman(result);

    const exitCode = result.status === 'not_proven' ? 2 : (opts.strict && result.status !== 'verified' ? 3 : 0);
    process.exit(exitCode);
  } catch (err) {
    console.error(`Verifier error: ${err.message}`);
    process.exit(1);
  }
}

export { verifyBundle, VERIFY_PHRASES };

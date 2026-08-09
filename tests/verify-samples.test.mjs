import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { verifyBundle } from '../verify-bundle.mjs';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const trustDirs = [path.join(repositoryRoot, 'trust', 'roots')];

const cases = [
  ['bundle-good', 'verified'],
  ['bundle-inferred', 'inferred'],
  ['bundle-declared', 'declared'],
  ['bundle-tampered', 'not_proven']
];

for (const [sample, expectedStatus] of cases) {
  test(`${sample} produces ${expectedStatus}`, async () => {
    const result = await verifyBundle(
      path.join(repositoryRoot, 'samples', sample),
      { trustDirs }
    );

    assert.equal(result.status, expectedStatus);
    assert.equal(typeof result.phrase, 'string');
    assert.ok(result.phrase.length > 0);
  });
}

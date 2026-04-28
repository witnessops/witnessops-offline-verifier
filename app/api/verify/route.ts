import { NextRequest, NextResponse } from 'next/server';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

export const runtime = 'nodejs';

type RunResult = { code: number | null; stdout: string; stderr: string };

const ROOT = process.cwd();
const CLI = path.join(ROOT, 'verify-bundle.mjs');
const TRUST_DIR = path.join(ROOT, 'trust', 'roots');
const SAMPLES_DIR = path.join(ROOT, 'samples');

function runVerifier(bundleDir: string): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, bundleDir, '--json', '--trust-dir', TRUST_DIR], { cwd: ROOT });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function safeRelativePath(input: string) {
  const slashPath = input.replace(/\\/g, '/');
  const normalized = path.posix.normalize(slashPath).replace(/^\/+/, '');
  if (!normalized || normalized === '.' || normalized.startsWith('../') || normalized.includes('/../')) {
    throw new Error(`Unsafe upload path: ${input}`);
  }
  return normalized;
}

async function findBundleRoot(dir: string): Promise<string | null> {
  const entries = await readdir(dir, { withFileTypes: true });
  if (entries.some((entry) => entry.isFile() && entry.name === 'receipt.json')) return dir;

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const found = await findBundleRoot(path.join(dir, entry.name));
    if (found) return found;
  }
  return null;
}

async function jsonFromVerifier(bundleDir: string) {
  const run = await runVerifier(bundleDir);
  let parsed: unknown;
  try {
    parsed = JSON.parse(run.stdout || '{}');
  } catch {
    return NextResponse.json({ error: run.stderr || run.stdout || 'Verifier did not return JSON' }, { status: 500 });
  }

  return NextResponse.json(parsed, { status: 200 });
}

export async function GET(request: NextRequest) {
  const sample = request.nextUrl.searchParams.get('sample') || 'bundle-good';
  if (!/^[a-z0-9_-]+$/i.test(sample)) {
    return NextResponse.json({ error: 'Invalid sample name' }, { status: 400 });
  }
  const bundleDir = path.join(SAMPLES_DIR, sample);
  const info = await stat(bundleDir).catch(() => null);
  if (!info?.isDirectory()) return NextResponse.json({ error: `Sample not found: ${sample}` }, { status: 404 });
  return jsonFromVerifier(bundleDir);
}

export async function POST(request: NextRequest) {
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'proof-bundle-'));
  try {
    const form = await request.formData();
    const files = form.getAll('files').filter((value): value is File => value instanceof File);
    const paths = form.getAll('paths').map((value) => String(value));
    if (!files.length) return NextResponse.json({ error: 'No files uploaded' }, { status: 400 });

    for (const [index, file] of files.entries()) {
      const rel = safeRelativePath(paths[index] || file.name);
      const out = path.join(tmp, rel);
      await mkdir(path.dirname(out), { recursive: true });
      await writeFile(out, Buffer.from(await file.arrayBuffer()));
    }

    const bundleRoot = await findBundleRoot(tmp);
    if (!bundleRoot) return NextResponse.json({ error: 'Uploaded files did not include receipt.json' }, { status: 400 });

    return await jsonFromVerifier(bundleRoot);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

'use client';

import { useRef, useState } from 'react';

type VerifyResult = {
  status: 'verified' | 'inferred' | 'declared' | 'not_proven';
  disposition: string;
  phrase: string;
  signer: null | { subject: string; fingerprint256: string };
  algorithm: string | null;
  issuanceTime: { value: string | null; trusted: boolean; source: string };
  checks: Record<string, boolean>;
  errors: string[];
  receipt?: unknown;
};

type UploadFile = { file: File; path: string };
type WebkitFileEntry = {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
} & Partial<FileSystemEntry> & {
  file?: (success: (file: File) => void, error?: (err: DOMException) => void) => void;
  createReader?: () => { readEntries: (success: (entries: WebkitFileEntry[]) => void, error?: (err: DOMException) => void) => void };
};

type DataTransferItemWithEntry = DataTransferItem & { webkitGetAsEntry?: () => WebkitFileEntry | null };

function label(status?: string) {
  if (status === 'verified') return 'Verified';
  if (status === 'inferred') return 'Inferred';
  if (status === 'declared') return 'Declared only';
  return 'Not proven';
}

function readFileEntry(entry: WebkitFileEntry, prefix: string): Promise<UploadFile[]> {
  return new Promise((resolve, reject) => {
    if (entry.isFile && entry.file) {
      entry.file((file) => resolve([{ file, path: `${prefix}${file.name}` }]), reject);
      return;
    }

    const reader = entry.createReader?.();
    if (!reader) {
      resolve([]);
      return;
    }
    const all: WebkitFileEntry[] = [];
    const readBatch = () => {
      reader.readEntries(async (entries) => {
        if (!entries.length) {
          const nested = await Promise.all(all.map((child) => readFileEntry(child, `${prefix}${entry.name}/`)));
          resolve(nested.flat());
          return;
        }
        all.push(...entries);
        readBatch();
      }, reject);
    };
    readBatch();
  });
}

async function uploadsFromDrop(event: React.DragEvent<HTMLElement>): Promise<UploadFile[]> {
  const entries = Array.from(event.dataTransfer.items || [])
    .map((item) => (item as DataTransferItemWithEntry).webkitGetAsEntry?.())
    .filter(Boolean) as WebkitFileEntry[];

  if (entries.length) {
    const nested = await Promise.all(entries.map((entry) => readFileEntry(entry, '')));
    return nested.flat();
  }

  return Array.from(event.dataTransfer.files).map((file) => ({ file, path: file.name }));
}

export default function Home() {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragging, setDragging] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function verifyUploads(uploads: UploadFile[]) {
    if (!uploads.length) return;
    setLoading(true);
    setError(null);
    setResult(null);

    const form = new FormData();
    for (const upload of uploads) {
      form.append('files', upload.file, upload.file.name);
      form.append('paths', upload.path);
    }

    const res = await fetch('/api/verify', { method: 'POST', body: form });
    const body = await res.json();
    setLoading(false);
    if (!res.ok) setError(body?.error || 'Verification failed');
    else setResult(body);
  }

  async function verifySample(sample: string) {
    setLoading(true);
    setError(null);
    setResult(null);
    const res = await fetch(`/api/verify?sample=${encodeURIComponent(sample)}`);
    const body = await res.json();
    setLoading(false);
    if (!res.ok) setError(body?.error || 'Sample verification failed');
    else setResult(body);
  }

  return (
    <main>
      <h1>/verify, offline.</h1>
      <p>
        Drop a proof bundle folder, or choose one with the folder picker. The verdict uses the same dispositions:
        verified, declared, inferred, and not-proven.
      </p>

      <input
        ref={inputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={(event) => {
          const files = Array.from(event.target.files || []).map((file) => ({
            file,
            path: (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name
          }));
          verifyUploads(files);
        }}
        {...({ webkitdirectory: 'true', directory: 'true' } as Record<string, string>)}
      />

      <div
        className={`dropzone ${dragging ? 'dragging' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={async (event) => {
          event.preventDefault();
          setDragging(false);
          verifyUploads(await uploadsFromDrop(event));
        }}
      >
        <div>
          <strong>{loading ? 'Verifying…' : 'Drop a bundle folder, or click to choose one'}</strong>
          <p><small>Expected paths: receipt.json, receipt.jws, signer/00-leaf.pem, optional timestamp.jws and tsa/00-tsa.pem.</small></p>
        </div>
      </div>

      <div className="actions">
        <button type="button" onClick={() => verifySample('bundle-good')}>Good sample</button>
        <button type="button" className="secondary" onClick={() => verifySample('bundle-inferred')}>Inferred sample</button>
        <button type="button" className="secondary" onClick={() => verifySample('bundle-declared')}>Declared sample</button>
        <button type="button" className="secondary" onClick={() => verifySample('bundle-tampered')}>Tampered sample</button>
      </div>

      {error && (
        <section className="card">
          <span className="verdict not_proven">Not proven</span>
          <p>{error}</p>
        </section>
      )}

      {result && (
        <section className="card">
          <span className={`verdict ${result.status}`}>{label(result.status)}</span>
          <h2>{result.phrase}</h2>
          <div className="grid">
            <div className="kv"><span>Signer</span><strong>{result.signer?.subject || 'unknown'}</strong></div>
            <div className="kv"><span>Algorithm</span><strong>{result.algorithm || 'unknown'}</strong></div>
            <div className="kv"><span>Issuance time</span><strong>{result.issuanceTime.value || 'not proven'}</strong></div>
            <div className="kv"><span>Time source</span><strong>{result.issuanceTime.trusted ? 'trusted' : 'declared/untrusted'} via {result.issuanceTime.source}</strong></div>
          </div>
          <div className="checks">
            {Object.entries(result.checks).map(([name, ok]) => (
              <span className="check" key={name}>{ok ? '✓' : '✗'} {name.replaceAll('_', ' ')}</span>
            ))}
          </div>
          {result.errors?.length > 0 && <pre>{result.errors.join('\n')}</pre>}
        </section>
      )}
    </main>
  );
}

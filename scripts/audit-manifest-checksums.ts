#!/usr/bin/env bun
/**
 * Read-only audit of the public data plane (nemarOrg/nemar-cli#2118): every manifest entry whose
 * `sha256` value is not 64 lowercase hex digits, or whose `md5` is not 32, per dataset and version.
 *
 * It only issues GET requests to the public data host (index at `/`, a dataset's versions at
 * `/<id>/`, each version's `manifest_url`). It writes nothing anywhere but standard output, and it
 * needs no credential. A manifest that answers 413 (too many files for `manifest.json`) is listed,
 * not read; any other non-200 answer is listed as unreadable.
 *
 * Usage:
 *   bun scripts/audit-manifest-checksums.ts [--base https://data.nemar.org] [--concurrency 6]
 *                                           [--only <dataset id>[,<id>...]] [--json]
 */

const SHAPE: Readonly<Record<string, { length: number; label: string }>> = {
  sha256: { length: 64, label: "64 lowercase hex" },
  md5: { length: 32, label: "32 lowercase hex" },
};

export interface ManifestRow {
  path?: unknown;
  checksum_algorithm?: unknown;
  checksum?: unknown;
}

export interface VersionFinding {
  dataset: string;
  version: string;
  entries: number;
  bad: number;
  /** Count by `<algorithm>:<length>` of the offending values, for example `sha256:65`. */
  shapes: Record<string, number>;
  examples: Array<{ path: string; algorithm: string; length: number }>;
}

/** True when the value is a digest of the shape its algorithm names. Other algorithms are not judged. */
export function checksumIsWellFormed(algorithm: unknown, value: unknown): boolean {
  if (typeof algorithm !== "string") return true;
  const shape = SHAPE[algorithm];
  if (!shape) return true;
  return typeof value === "string" && value.length === shape.length && /^[0-9a-f]+$/.test(value);
}

/** Classify one manifest's rows. Never throws on a malformed row; a non-object row counts as bad. */
export function auditEntries(
  dataset: string,
  version: string,
  rows: unknown[],
  maxExamples = 3,
): VersionFinding {
  const finding: VersionFinding = {
    dataset,
    version,
    entries: rows.length,
    bad: 0,
    shapes: {},
    examples: [],
  };
  for (const raw of rows) {
    const row = (raw && typeof raw === "object" ? raw : {}) as ManifestRow;
    if (checksumIsWellFormed(row.checksum_algorithm, row.checksum)) continue;
    const algorithm = String(row.checksum_algorithm);
    const length = typeof row.checksum === "string" ? row.checksum.length : -1;
    finding.bad++;
    const shape = `${algorithm}:${length}`;
    finding.shapes[shape] = (finding.shapes[shape] ?? 0) + 1;
    if (finding.examples.length < maxExamples) {
      finding.examples.push({ path: String(row.path), algorithm, length });
    }
  }
  return finding;
}

interface Options {
  base: string;
  concurrency: number;
  only: Set<string> | null;
  json: boolean;
}

function parseArgs(argv: string[]): Options {
  const opts: Options = { base: "https://data.nemar.org", concurrency: 6, only: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--base") opts.base = (argv[++i] ?? "").replace(/\/+$/, "");
    else if (a === "--concurrency") opts.concurrency = Math.max(1, Number(argv[++i]) || 6);
    else if (a === "--only") opts.only = new Set((argv[++i] ?? "").split(",").filter(Boolean));
    else if (a === "--json") opts.json = true;
    else throw new Error(`unknown argument ${a}`);
  }
  return opts;
}

async function getJson(url: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (res.status !== 200) {
    await res.body?.cancel();
    return { status: res.status, body: null };
  }
  return { status: 200, body: await res.json() };
}

/** Run `fn` over `items` with at most `limit` in flight. */
async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++]);
  });
  await Promise.all(workers);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const index = await getJson(`${opts.base}/`);
  if (index.status !== 200) throw new Error(`index answered HTTP ${index.status}`);
  const datasets = (index.body as { datasets: Array<{ id: string }> }).datasets
    .map((d) => d.id)
    .filter((id) => !opts.only || opts.only.has(id));

  const jobs: Array<{ dataset: string; version: string; url: string }> = [];
  const unreadable: string[] = [];
  await pool(datasets, opts.concurrency, async (dataset) => {
    const res = await getJson(`${opts.base}/${dataset}/`);
    if (res.status !== 200) {
      unreadable.push(`${dataset} (version list HTTP ${res.status})`);
      return;
    }
    const versions = (res.body as { versions?: Array<{ version: string; manifest_url?: string }> })
      .versions;
    for (const v of versions ?? []) {
      if (!v.manifest_url) continue;
      jobs.push({
        dataset,
        version: v.version,
        url: new URL(v.manifest_url, `${opts.base}/`).href,
      });
    }
  });

  const findings: VersionFinding[] = [];
  const tooLarge: string[] = [];
  let read = 0;
  await pool(jobs, opts.concurrency, async (job) => {
    let res: { status: number; body: unknown };
    try {
      res = await getJson(job.url);
    } catch (err) {
      unreadable.push(`${job.dataset}@${job.version} (${(err as Error).message})`);
      return;
    }
    if (res.status === 413) {
      tooLarge.push(`${job.dataset}@${job.version}`);
      return;
    }
    if (res.status !== 200 || !Array.isArray(res.body)) {
      unreadable.push(`${job.dataset}@${job.version} (HTTP ${res.status})`);
      return;
    }
    read++;
    const finding = auditEntries(job.dataset, job.version, res.body);
    if (finding.bad > 0) findings.push(finding);
  });

  const key = (f: { dataset: string; version: string }) => `${f.dataset}@${f.version}`;
  findings.sort((a, b) => (key(a) < key(b) ? -1 : 1));
  tooLarge.sort();
  unreadable.sort();

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          base: opts.base,
          datasets: datasets.length,
          manifests_read: read,
          findings,
          tooLarge,
          unreadable,
        },
        null,
        2,
      ),
    );
    return;
  }
  console.log(
    `base ${opts.base}: ${datasets.length} datasets, ${jobs.length} versions listed, ${read} manifests read`,
  );
  console.log(`rule: sha256 = ${SHAPE.sha256.label}, md5 = ${SHAPE.md5.label}`);
  console.log(`\nversions with a wrong-shaped checksum: ${findings.length}`);
  for (const f of findings) {
    const shapes = Object.entries(f.shapes)
      .map(([s, n]) => `${s} x${n}`)
      .join(", ");
    console.log(`  ${key(f)}: ${f.bad} of ${f.entries} entries (${shapes})`);
    for (const e of f.examples)
      console.log(`    e.g. ${e.path} (${e.algorithm}, length ${e.length})`);
  }
  console.log(`\nanswered 413, not read (${tooLarge.length}): ${tooLarge.join(", ") || "none"}`);
  console.log(`unreadable (${unreadable.length}): ${unreadable.join(", ") || "none"}`);
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}

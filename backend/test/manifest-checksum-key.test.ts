/**
 * nemarOrg/nemar-cli#2118: 260 `sha256` entries in the published manifest of
 * on003104 at v1.0.0 carried the annex key's file name after the digest
 * (`...cc31C`, `...789701`).
 *
 * The keys below are the real ones read from nemarDatasets/on003104 at v1.0.0.
 * git-annex keeps the whole tail of a name that has no dot as its "extension"
 * and appends it to the digest with no separator, so the greedy hex match in
 * `extractChecksumFromKey` took the leading hex digits of `COR-001` (`C`) and
 * `01_brain_surface` (`01`) as part of the digest.
 *
 * Two layers are covered: the key parser, and the real `dataRoutes` app serving
 * `manifest.json` from a stored manifest that already holds the wrong values
 * (every manifest published before the fix does), over a real D1 and a real
 * local HTTP server standing in for S3.
 */

import type { Database } from "bun:sqlite";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { dataRoutes } from "../src/routes/data";
import {
  extractChecksumFromKey,
  extractHashAlgorithm,
  isWellFormedChecksum,
  repairStoredChecksum,
} from "../src/services/manifest";
import { resetManifestAnswerMemo } from "../src/services/manifest-source";
import type { Bindings, Variables } from "../src/types/bindings";
import { freshDb, realD1 } from "./helpers/d1";
import { type S3ManifestStandin, startS3ManifestStandin } from "./helpers/s3-manifest-standin";

const COR = "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31";
const BRAIN = "a61f15d4bcaf7ceafd6f07da5192495bfdeec4492a415e8d46577405caeb7897";
const MD5 = "9e107d9d372bb6826bd81d3542a419d6";

describe("extractChecksumFromKey on real annex key shapes", () => {
  test("a dotless name starting with a hex digit does not leak into the digest", () => {
    expect(extractChecksumFromKey(`SHA256E-s65536--${COR}COR-001`)).toBe(COR);
    expect(extractChecksumFromKey(`SHA256E-s369273--${BRAIN}01_brain_surface`)).toBe(BRAIN);
  });

  test("an extension made only of hex characters is not part of the digest", () => {
    // `.abc` and a whole hex name (`deadbeef`): both look like the end of a digest.
    expect(extractChecksumFromKey(`SHA256E-s9--${COR}.abc`)).toBe(COR);
    expect(extractChecksumFromKey(`SHA256E-s9--${COR}deadbeef`)).toBe(COR);
    expect(extractChecksumFromKey(`SHA256E-s9--${COR}0123456789`)).toBe(COR);
  });

  test("MD5E keys are cut at 32 characters", () => {
    expect(extractChecksumFromKey(`MD5E-s10--${MD5}face`)).toBe(MD5);
    expect(extractChecksumFromKey(`MD5E-s10--${MD5}.bdf`)).toBe(MD5);
  });

  test("keys that were right stay byte for byte the same", () => {
    for (const tail of ["", ".edf", ".nii.gz", ".tar.gz", ".C", ".01", "README", ".m3z"]) {
      expect(extractChecksumFromKey(`SHA256E-s1--${COR}${tail}`)).toBe(COR);
    }
    // Non-E backend: the digest is the whole tail.
    expect(extractChecksumFromKey(`SHA256-s65536--${COR}`)).toBe(COR);
    expect(extractChecksumFromKey(`MD5-s10--${MD5}`)).toBe(MD5);
    // Chunked key: the size/chunk fields use single dashes, so `--` is still the digest delimiter.
    expect(extractChecksumFromKey(`SHA256E-s100-S10-C3--${COR}.edf`)).toBe(COR);
  });

  test("a digest shorter than its backend's length is returned as found, for the checker to flag", () => {
    expect(extractChecksumFromKey("SHA256E-s12345--abc123def456.edf")).toBe("abc123def456");
    expect(isWellFormedChecksum("sha256", "abc123def456")).toBe(false);
  });

  test("a backend with no known length keeps the old greedy match", () => {
    const blake = "a".repeat(64);
    expect(extractChecksumFromKey(`BLAKE2B256E-s1--${blake}.edf`)).toBe(blake);
    expect(extractHashAlgorithm(`BLAKE2B256E-s1--${blake}.edf`)).toBe("blake2b256");
  });

  test("no digest at all", () => {
    expect(extractChecksumFromKey("git:abcd")).toBe("");
    expect(extractChecksumFromKey("")).toBe("");
  });
});

describe("isWellFormedChecksum", () => {
  test("sha256 is 64 lowercase hex, md5 is 32", () => {
    expect(isWellFormedChecksum("sha256", COR)).toBe(true);
    expect(isWellFormedChecksum("sha256", `${COR}C`)).toBe(false);
    expect(isWellFormedChecksum("sha256", `${COR}01`)).toBe(false);
    expect(isWellFormedChecksum("sha256", COR.toUpperCase())).toBe(false);
    expect(isWellFormedChecksum("sha256", COR.slice(1))).toBe(false);
    expect(isWellFormedChecksum("sha256", "")).toBe(false);
    expect(isWellFormedChecksum("md5", MD5)).toBe(true);
    expect(isWellFormedChecksum("md5", `${MD5}f`)).toBe(false);
  });

  test("git and unknown algorithms are not judged", () => {
    expect(isWellFormedChecksum("git", "66fda97533307ffdbd0d7995ab97297aa16b54d4")).toBe(true);
    expect(isWellFormedChecksum("unknown", "x")).toBe(true);
  });
});

describe("repairStoredChecksum", () => {
  test("a well-formed value is returned untouched, whatever the key says", () => {
    expect(repairStoredChecksum("sha256", COR, "SHA256E-s1--other.edf")).toEqual({
      value: COR,
      status: "ok",
    });
  });

  test("a stored value with the extension attached is re-derived from the key", () => {
    expect(repairStoredChecksum("sha256", `${COR}C`, `SHA256E-s65536--${COR}COR-001`)).toEqual({
      value: COR,
      status: "repaired",
    });
  });

  test("a value that cannot be repaired is reported, not invented", () => {
    // No key.
    expect(repairStoredChecksum("sha256", `${COR}C`, undefined).status).toBe("malformed");
    // The key is for another algorithm.
    expect(repairStoredChecksum("sha256", `${COR}C`, `MD5E-s1--${MD5}.edf`).status).toBe(
      "malformed",
    );
    // The key itself is short.
    expect(repairStoredChecksum("sha256", "abc123", "SHA256E-s1--abc123.edf")).toEqual({
      value: "abc123",
      status: "malformed",
    });
  });
});

// --- the served manifest.json, over the real route -------------------------------------------

const ID = "nm000904";
const VERSION_KEY = `/${ID}/version/v1.0.0.json`;
const BASE = "derivatives/freesurfer/subjects/01/bem/watershed";

const STORED = {
  dataset_id: ID,
  version: "1.0.0",
  doi: null,
  concept_doi: null,
  created: "2026-01-01T00:00:00.000Z",
  files: {
    [`${BASE}/01_brain_surface`]: {
      key: `SHA256E-s369273--${BRAIN}01_brain_surface`,
      size: 369273,
      checksum: `sha256:${BRAIN}01`,
    },
    [`${BASE}/ws/COR-001`]: {
      key: `SHA256E-s65536--${COR}COR-001`,
      size: 65536,
      checksum: `sha256:${COR}C`,
    },
    "sub-01/eeg/valid.edf": {
      key: `SHA256E-s10--${COR}.edf`,
      size: 10,
      checksum: `sha256:${COR}`,
    },
    "sub-01/eeg/valid_md5.bdf": {
      key: `MD5E-s10--${MD5}.bdf`,
      size: 10,
      checksum: `md5:${MD5}`,
    },
    "sub-01/eeg/broken.edf": {
      key: "SHA256E-s10--abc123.edf",
      size: 10,
      checksum: "sha256:abc123",
    },
    "participants.tsv": {
      key: "git:66fda97533307ffdbd0d7995ab97297aa16b54d4",
      size: 8,
      checksum: "git:66fda97533307ffdbd0d7995ab97297aa16b54d4",
    },
  },
};

let s3: S3ManifestStandin;
let db: Database;
const logged: string[] = [];
const realError = console.error;

beforeAll(() => {
  s3 = startS3ManifestStandin();
});

afterAll(() => {
  s3.stop();
});

beforeEach(() => {
  db = freshDb();
  db.prepare(
    `INSERT INTO datasets (dataset_id, name, owner_user_id, status, visibility, is_sandbox)
     VALUES (?, ?, 1, 'active', 'public', 0)`,
  ).run(ID, ID);
  db.prepare(
    `INSERT INTO dataset_versions (dataset_id, version, doi, provider, created_at)
     VALUES (?, '1.0.0', ?, 'ezid', '2026-01-01 00:00:00')`,
  ).run(ID, `10.5072/FK2${ID}`);
  s3.put(VERSION_KEY, JSON.stringify(STORED));
  s3.setBucketPolicy(null);
  resetManifestAnswerMemo();
  logged.length = 0;
  // Capture only; every message still reaches the real console.
  console.error = (...args: unknown[]) => {
    logged.push(args.map(String).join(" "));
    realError(...args);
  };
});

afterEach(() => {
  console.error = realError;
});

async function manifestJson(): Promise<Array<Record<string, string | number>>> {
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
  app.route("/", dataRoutes);
  const env = {
    DB: realD1(db),
    ENVIRONMENT: "test",
    DATA_BASE_URL: "https://data.nemar.org",
    S3_ENDPOINT_URL: s3.url,
    S3_BUCKET: "nemar",
    AWS_REGION: "us-east-2",
    AWS_ACCESS_KEY_ID: "AKIATEST",
    AWS_SECRET_ACCESS_KEY: "secret",
  } as Bindings;
  const res = await app.request(`https://data.nemar.org/${ID}/v1.0.0/manifest.json`, {}, env);
  expect(res.status).toBe(200);
  return (await res.json()) as Array<Record<string, string | number>>;
}

describe("manifest.json over a stored manifest written before the fix (#2118)", () => {
  test("entries stored with the key's extension attached are served with the real digest", async () => {
    const byPath = new Map((await manifestJson()).map((e) => [e.path, e]));
    expect(byPath.get(`${BASE}/ws/COR-001`)).toMatchObject({
      checksum_algorithm: "sha256",
      checksum: COR,
      size: 65536,
    });
    expect(byPath.get(`${BASE}/01_brain_surface`)).toMatchObject({
      checksum_algorithm: "sha256",
      checksum: BRAIN,
    });
  });

  test("valid sha256, md5 and git entries are served exactly as stored", async () => {
    const byPath = new Map((await manifestJson()).map((e) => [e.path, e]));
    expect(byPath.get("sub-01/eeg/valid.edf")).toMatchObject({
      checksum_algorithm: "sha256",
      checksum: COR,
    });
    expect(byPath.get("sub-01/eeg/valid_md5.bdf")).toMatchObject({
      checksum_algorithm: "md5",
      checksum: MD5,
    });
    expect(byPath.get("participants.tsv")).toMatchObject({
      checksum_algorithm: "git",
      checksum: "66fda97533307ffdbd0d7995ab97297aa16b54d4",
    });
  });

  test("no served sha256 or md5 value has the wrong length except the one nothing can repair", async () => {
    const wrong = (await manifestJson()).filter(
      (e) =>
        (e.checksum_algorithm === "sha256" && String(e.checksum).length !== 64) ||
        (e.checksum_algorithm === "md5" && String(e.checksum).length !== 32),
    );
    expect(wrong.map((e) => e.path)).toEqual(["sub-01/eeg/broken.edf"]);
  });

  test("the repair and the unrepairable entry are reported, not silent", async () => {
    await manifestJson();
    const line = logged.find((l) => l.includes("[data] MANIFEST CHECKSUM"));
    expect(line).toBeDefined();
    expect(line).toContain(`dataset=${ID}`);
    expect(line).toContain("repaired=2");
    expect(line).toContain("malformed=1");
    expect(line).toContain("first_malformed=sub-01/eeg/broken.edf");
  });
});

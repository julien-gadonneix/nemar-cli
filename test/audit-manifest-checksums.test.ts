/**
 * The classification behind scripts/audit-manifest-checksums.ts (nemarOrg/nemar-cli#2118), run on
 * the checksum values that were actually served for on003104 at v1.0.0.
 */

import { describe, expect, test } from "bun:test";
import { auditEntries, checksumIsWellFormed } from "../scripts/audit-manifest-checksums";

const COR = "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31";
const BRAIN = "a61f15d4bcaf7ceafd6f07da5192495bfdeec4492a415e8d46577405caeb7897";
const MD5 = "9e107d9d372bb6826bd81d3542a419d6";

describe("checksumIsWellFormed", () => {
  test("the two served shapes from on003104 are refused", () => {
    expect(checksumIsWellFormed("sha256", `${COR}C`)).toBe(false);
    expect(checksumIsWellFormed("sha256", `${BRAIN}01`)).toBe(false);
  });

  test("real digests, git object ids and other algorithms pass", () => {
    expect(checksumIsWellFormed("sha256", COR)).toBe(true);
    expect(checksumIsWellFormed("md5", MD5)).toBe(true);
    expect(checksumIsWellFormed("git", "66fda97533307ffdbd0d7995ab97297aa16b54d4")).toBe(true);
    expect(checksumIsWellFormed("blake2b256", "zz")).toBe(true);
  });

  test("uppercase, short, empty and non-string values are refused", () => {
    expect(checksumIsWellFormed("sha256", COR.toUpperCase())).toBe(false);
    expect(checksumIsWellFormed("md5", MD5.slice(1))).toBe(false);
    expect(checksumIsWellFormed("sha256", "")).toBe(false);
    expect(checksumIsWellFormed("sha256", undefined)).toBe(false);
  });
});

describe("auditEntries", () => {
  const rows = [
    { path: "a/COR-001", checksum_algorithm: "sha256", checksum: `${COR}C` },
    { path: "a/COR-002", checksum_algorithm: "sha256", checksum: `${COR}C` },
    { path: "a/01_brain_surface", checksum_algorithm: "sha256", checksum: `${BRAIN}01` },
    { path: "a/ok.edf", checksum_algorithm: "sha256", checksum: COR },
    { path: "a/ok.bdf", checksum_algorithm: "md5", checksum: MD5 },
    { path: "a/bad.bdf", checksum_algorithm: "md5", checksum: `${MD5}0` },
    {
      path: "README",
      checksum_algorithm: "git",
      checksum: "66fda97533307ffdbd0d7995ab97297aa16b54d4",
    },
  ];

  test("counts offenders by algorithm and length, and keeps a few examples", () => {
    const f = auditEntries("on003104", "v1.0.0", rows, 2);
    expect(f.entries).toBe(7);
    expect(f.bad).toBe(4);
    expect(f.shapes).toEqual({ "sha256:65": 2, "sha256:66": 1, "md5:33": 1 });
    expect(f.examples).toEqual([
      { path: "a/COR-001", algorithm: "sha256", length: 65 },
      { path: "a/COR-002", algorithm: "sha256", length: 65 },
    ]);
  });

  test("a clean manifest reports nothing", () => {
    expect(auditEntries("nm000104", "v2.0.0", rows.slice(3, 5)).bad).toBe(0);
  });

  test("a row that is not an object, so names no algorithm, is not judged and does not throw", () => {
    expect(auditEntries("x", "v1", [null, 3, "s"]).bad).toBe(0);
  });
});

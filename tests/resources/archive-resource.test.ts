import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { listFiles, getRawFile } from "../../src/resources/archive-resource.js";
import { CONTENT_BUDGET_CHARS, OUTPUT_BUDGET_CHARS } from "../../src/tools/output-budget.js";

const textOf = (r: { content: { type: string; text: string }[] }) => r.content[0].text;
const nextOffset = (text: string) => {
  const m = /Pass offset=(\d+) for more/.exec(text);
  return m ? Number(m[1]) : null;
};

describe("archive resource tools", () => {
  let store: BugReportStore;
  let tempDir: string;
  let archiveDir: string;
  let multibyte: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "archive-resource-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    await mkdir(join(archiveDir, "synthetic"), { recursive: true });
    multibyte = Array.from({ length: 40 }, (_, i) => `line ${i} café \u{1F600} ${"x".repeat(i % 5)}`).join("\n") + "\n";
    await writeFile(join(archiveDir, "synthetic", "multibyte.log"), multibyte);
    await writeFile(join(archiveDir, "synthetic", "oneline.txt"), "é".repeat(50));
    await writeFile(
      join(archiveDir, "synthetic", "large.log"),
      Array.from({ length: 6000 }, (_, i) => `2026-01-01T00:00:00Z\tinfo\tsynthetic line ${i}`).join("\n") + "\n",
    );
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("lists all files", () => {
    const text = textOf(listFiles(store));
    expect(text).toContain("versions");
    expect(text).toContain("cluster/k8s-resources");
    expect(text).not.toContain("Showing");
  });

  it("pages the file list with offset", () => {
    const total = store.getAllFiles().length;
    const text = textOf(listFiles(store, { offset: total - 1 }));
    expect(text).toContain(`Showing files ${total}-${total} of ${total}.`);
    expect(text.split("\n")[0]).toBe(store.getAllFiles()[total - 1]);
  });

  it("gets raw file content whole when it fits, with no footer", async () => {
    const text = textOf(await getRawFile(store, "versions"));
    expect(text).toContain("1.31.2");
    expect(text).not.toContain("Showing bytes");
  });

  it("returns error for missing file", async () => {
    const result = await getRawFile(store, "nonexistent");
    expect(result.isError).toBe(true);
  });

  it("returns an error for an offset past the end", async () => {
    const result = await getRawFile(store, "versions", { offset: 10_000_000 });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("past the end");
  });

  it("pages a large file within the budget, line-aligned, covering it exactly", async () => {
    const whole = await readFile(join(archiveDir, "synthetic", "large.log"), "utf8");
    expect(whole.length).toBeGreaterThan(2 * OUTPUT_BUDGET_CHARS);
    const bodies: string[] = [];
    let offset: number | undefined;
    for (let guard = 0; guard < 20; guard++) {
      const text = textOf(await getRawFile(store, "synthetic/large.log", offset === undefined ? {} : { offset }));
      expect(text.length).toBeLessThanOrEqual(OUTPUT_BUDGET_CHARS);
      const range = store.readFileRange("synthetic/large.log", offset ?? 0, CONTENT_BUDGET_CHARS)!;
      expect(text.startsWith(range.text)).toBe(true);
      bodies.push(range.text);
      if (range.end >= range.size) {
        expect(text).toMatch(/Showing bytes \d+-\d+ of \d+\.$/);
        break;
      }
      expect(range.text.endsWith("\n")).toBe(true);
      expect(text).toContain(`Pass offset=${range.end} for more.`);
      offset = range.end;
    }
    expect(bodies.join("")).toBe(whole);
  });

  it("never splits a multi-byte character, with or without newlines in range", async () => {
    const bodies: string[] = [];
    let offset = 0;
    for (let guard = 0; guard < 200; guard++) {
      const range = store.readFileRange("synthetic/multibyte.log", offset, 37)!;
      expect(range.text).not.toContain("�");
      bodies.push(range.text);
      if (range.end >= range.size) break;
      expect(range.end).toBeGreaterThan(offset);
      offset = range.end;
    }
    expect(bodies.join("")).toBe(multibyte);

    // A single line of 2-byte characters, read in odd-sized ranges.
    const single: string[] = [];
    offset = 0;
    for (let guard = 0; guard < 200; guard++) {
      const range = store.readFileRange("synthetic/oneline.txt", offset, 7)!;
      expect(range.text).not.toContain("�");
      single.push(range.text);
      if (range.end >= range.size) break;
      offset = range.end;
    }
    expect(single.join("")).toBe("é".repeat(50));
  });

  it("starts a mid-character offset on the next character", () => {
    // Byte 1 is the second byte of the first "é".
    const range = store.readFileRange("synthetic/oneline.txt", 1, 4)!;
    expect(range.start).toBe(2);
    expect(range.text).toBe("é");
  });

  it("honours a caller-supplied length and points at the next range", async () => {
    const text = textOf(await getRawFile(store, "synthetic/multibyte.log", { length: 60 }));
    const next = nextOffset(text);
    expect(next).not.toBeNull();
    expect(next!).toBeLessThanOrEqual(60);
    expect(text).toMatch(/Showing bytes 1-\d+ of \d+\. Pass offset=\d+ for more\.$/);
  });

  it("hints at get_cluster_resources when paging a cluster dump", async () => {
    const text = textOf(await getRawFile(store, "cluster/k8s-resources", { length: 20 }));
    expect(text).toContain("or use get_cluster_resources to query its resources");
  });
});

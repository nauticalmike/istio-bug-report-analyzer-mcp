import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getAnalyzeResults } from "../../src/tools/analyze-results.js";

describe("getAnalyzeResults", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "analyze-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns all analyze results when no filter", () => {
    const result = getAnalyzeResults(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("IST0101");
    expect(text).toContain("IST0107");
    expect(text).toContain("IST0118");
  });

  it("filters by severity", () => {
    const result = getAnalyzeResults(store, { severity: "Error" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("IST0101");
    expect(text).not.toContain("IST0118");
  });

  it("summarizes by code and pages the findings", () => {
    const all = getAnalyzeResults(store, {});
    const total = store.getAnalyzeResults().length;
    const text = (all.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("By code:");
    expect(text).toMatch(/IST0101 \(Error\): \d+/);
    expect(text).not.toContain("Showing");

    const page = (getAnalyzeResults(store, { limit: 1, offset: 1 }).content[0] as { type: "text"; text: string }).text;
    const findingLines = page.split("\n").filter((l) => l.startsWith("["));
    expect(findingLines).toHaveLength(1);
    expect(findingLines[0]).toContain(store.getAnalyzeResults()[1].resource);
    expect(page).toContain(`Showing 2-2 of ${total}.`);
  });

  it("filters by code", () => {
    const result = getAnalyzeResults(store, { code: "IST0107" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("IST0107");
    expect(text).not.toContain("IST0101");
  });
});

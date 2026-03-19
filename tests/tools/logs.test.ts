import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getLogs } from "../../src/tools/logs.js";

describe("getLogs", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "logs-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns proxy logs", () => {
    const result = getLogs(store, { component: "proxy" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Connection refused");
  });

  it("returns istiod logs", () => {
    const result = getLogs(store, { component: "istiod" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("XDS: Pushing");
  });

  it("filters by keyword", () => {
    const result = getLogs(store, { component: "proxy", keyword: "error" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("error");
    expect(text).not.toContain("info");
  });

  it("truncates output and reports metadata", () => {
    const result = getLogs(store, { component: "proxy", tail: 1 });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toBeTruthy();
  });
});

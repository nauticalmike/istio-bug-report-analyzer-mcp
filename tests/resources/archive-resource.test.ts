import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { listFiles, getRawFile } from "../../src/resources/archive-resource.js";

describe("archive resource tools", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "archive-resource-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("lists all files", () => {
    const result = listFiles(store);
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("versions");
    expect(text).toContain("cluster/k8s-resources");
  });

  it("gets raw file content", async () => {
    const result = await getRawFile(store, "versions");
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("1.29.1");
  });

  it("returns error for missing file", async () => {
    const result = await getRawFile(store, "nonexistent");
    expect(result.isError).toBe(true);
  });
});

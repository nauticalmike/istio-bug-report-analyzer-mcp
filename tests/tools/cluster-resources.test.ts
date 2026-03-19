import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getClusterResources } from "../../src/tools/cluster-resources.js";

describe("getClusterResources", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cluster-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns resources filtered by kind", () => {
    const result = getClusterResources(store, { kind: "Namespace" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Namespace");
    expect(text).toContain("default");
  });

  it("returns summary by default", () => {
    const result = getClusterResources(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("resources found");
  });
});

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getIstiodDebug } from "../../src/tools/istiod-debug.js";

describe("getIstiodDebug", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "istiod-debug-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns syncz data", async () => {
    const result = await getIstiodDebug(store, { endpoint: "syncz" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("SYNCED");
  });

  it("returns configz data", async () => {
    const result = await getIstiodDebug(store, { endpoint: "configz" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("virtualservices");
  });

  it("returns mesh config", async () => {
    const result = await getIstiodDebug(store, { endpoint: "mesh" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("discoveryAddress");
  });

  it("returns error for unknown endpoint", async () => {
    const result = await getIstiodDebug(store, { endpoint: "nonexistent" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("not found");
  });

  it("lists available endpoints when no endpoint specified", async () => {
    const result = await getIstiodDebug(store, { endpoint: "" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("syncz");
    expect(text).toContain("configz");
  });
});

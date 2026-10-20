import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getVersions } from "../../src/tools/versions.js";

describe("getVersions", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "versions-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns version matrix", () => {
    const result = getVersions(store);
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Client Version:");
    expect(text).toContain("1.31.2");
  });

  it("does not print a proxy count the versions file does not record", () => {
    const text = (getVersions(store).content[0] as { type: "text"; text: string }).text;
    expect(text).not.toContain("(0 proxies)");
  });
});

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getProxyConfig } from "../../src/tools/proxy-config.js";

describe("getProxyConfig", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "proxy-config-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns config_dump for a proxy pod", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "test-pod-abc123" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("BootstrapConfigDump");
  });

  it("returns specific section", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "test-pod-abc123", section: "listeners" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("LISTENER");
  });

  it("returns error for unknown pod", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "nonexistent" });
    expect(result.isError).toBe(true);
  });
});

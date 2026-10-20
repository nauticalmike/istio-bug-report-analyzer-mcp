import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { findErrors } from "../../src/tools/find-errors.js";

describe("findErrors", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "errors-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    await mkdir(join(archiveDir, "cni", "istio-cni-node-abcde"), { recursive: true });
    await writeFile(
      join(archiveDir, "cni", "istio-cni-node-abcde", "cni.log"),
      "2026-10-20T20:00:01.000000Z\terror\tcni\tfailed to add iptables rules\n",
    );
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("finds error lines in proxy logs", async () => {
    const result = await findErrors(store, { component: "proxy" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Connection refused");
  });

  it("finds error lines in cni logs", async () => {
    const result = await findErrors(store, { component: "cni" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("cni/istio-cni-node-abcde");
    expect(text).toContain("failed to add iptables rules");
  });

  it("includes cni errors when scanning all components", async () => {
    const result = await findErrors(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("failed to add iptables rules");
  });

  it("deduplicates similar error patterns", async () => {
    const result = await findErrors(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toMatch(/\d+ unique/);
  });
});

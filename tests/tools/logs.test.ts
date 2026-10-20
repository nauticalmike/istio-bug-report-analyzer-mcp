import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
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
    await mkdir(join(archiveDir, "cni", "istio-cni-node-abcde"), { recursive: true });
    await writeFile(
      join(archiveDir, "cni", "istio-cni-node-abcde", "cni.log"),
      "2026-10-20T20:00:00.000000Z\tinfo\tcni\tAdding pod to ambient\n2026-10-20T20:00:01.000000Z\terror\tcni\tfailed to add iptables rules\n",
    );
    await mkdir(join(archiveDir, "operator", "istio-operator-xyz"), { recursive: true });
    await writeFile(
      join(archiveDir, "operator", "istio-operator-xyz", "operator.log"),
      "2026-10-20T20:00:00.000000Z\tinfo\tReconciling IstioOperator\n",
    );
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns proxy logs", async () => {
    const result = await getLogs(store, { component: "proxy" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Connection refused");
  });

  it("returns istiod logs", async () => {
    const result = await getLogs(store, { component: "istiod" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("XDS: Pushing");
  });

  it("filters by keyword", async () => {
    const result = await getLogs(store, { component: "proxy", keyword: "error" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("error");
    expect(text).not.toContain("info");
  });

  it("returns cni logs", async () => {
    const result = await getLogs(store, { component: "cni" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("[cni/istio-cni-node-abcde]");
    expect(text).toContain("failed to add iptables rules");
  });

  it("filters cni logs by pod", async () => {
    const result = await getLogs(store, { component: "cni", pod: "istio-cni-node-other" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("No log lines found");
  });

  it("returns operator logs when the archive has them", async () => {
    const result = await getLogs(store, { component: "operator" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Reconciling IstioOperator");
  });

  it("includes cni and operator logs for component all", async () => {
    const result = await getLogs(store, { component: "all" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("failed to add iptables rules");
    expect(text).toContain("XDS: Pushing");
  });

  it("truncates output and reports metadata", async () => {
    const result = await getLogs(store, { component: "proxy", tail: 1 });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toBeTruthy();
  });
});

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getOverview } from "../../src/tools/overview.js";

describe("getOverview", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "overview-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    const gw = join(archiveDir, "proxies", "istio-ingress", "istio-ingressgateway-7d9-abcde");
    await mkdir(gw, { recursive: true });
    const bootstrap = { bootstrap: { node: { id: "router~10.0.0.7~istio-ingressgateway-7d9-abcde.istio-ingress~istio-ingress.svc.cluster.local" } } };
    await writeFile(join(gw, "config_dump?include_eds"), JSON.stringify({ configs: [bootstrap] }, null, 2));
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns structured overview", async () => {
    const result = await getOverview(store);
    expect(result.content[0].type).toBe("text");
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("1.31.2");
    expect(text).toContain("Proxies:");
    expect(text).toContain("Analyze Results:");
  });

  it("counts gateways separately from sidecars", async () => {
    const text = ((await getOverview(store)).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Data Plane Mode: sidecar (sidecars: 1, gateways: 1)");
  });

  it("does not force the full cluster parse, and reports the count once parsed", async () => {
    const archiveDir = join(tempDir, "bug-report-lazy-overview");
    await createMinimalArchive(archiveDir);
    const pods = Array.from({ length: 600 }, (_, i) => `- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: pod-${i}\n    namespace: default\n`);
    await writeFile(join(archiveDir, "cluster", "pods"), `apiVersion: v1\nitems:\n${pods.join("")}kind: List\n`);
    const fresh = await BugReportStore.fromDirectory(archiveDir);

    const before = (await getOverview(fresh)).content[0] as { type: "text"; text: string };
    expect(fresh.isClusterResourcesParsed()).toBe(false);
    expect(before.text).toMatch(/Cluster Resources: not parsed yet \(\d+ dump files?, [\d.]+ [KMG]?B\)/);
    const { bytes } = fresh.getClusterDumpSummary();
    const shown = /, ([\d.]+) ([KMG]?)B\)/.exec(before.text)!;
    const scale = { "": 1, K: 1e3, M: 1e6, G: 1e9 }[shown[2] as "" | "K" | "M" | "G"];
    expect(bytes).toBeGreaterThan(30_000);
    expect(Math.abs(Number(shown[1]) * scale - bytes) / bytes).toBeLessThan(0.01);

    const count = fresh.getClusterResources().length;
    const after = (await getOverview(fresh)).content[0] as { type: "text"; text: string };
    expect(after.text).toContain(`Cluster Resources: ${count} objects`);
  });
});

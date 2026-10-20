import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";

describe("BugReportStore", () => {
  let tempDir: string;
  let archiveDir: string;
  let store: BugReportStore;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "store-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("loads version info", () => {
    expect(store.getVersions()).not.toBeNull();
    expect(store.getVersions()!.clientVersion).toBe("1.29.1");
  });

  it("loads analyze results", () => {
    const results = store.getAnalyzeResults();
    expect(results.length).toBe(3);
    expect(results[0].code).toBe("IST0101");
  });

  it("lists proxy pods by namespace", () => {
    const proxies = store.getProxyPods("default");
    expect(proxies.length).toBe(1);
    expect(proxies[0].podName).toBe("test-pod-abc123");
  });

  it("returns proxy logs", () => {
    const logs = store.getProxyLogs("default", "test-pod-abc123");
    expect(logs).toContain("error");
  });

  it("returns istiod debug endpoint data", () => {
    const syncz = store.getIstiodDebug("istio-system", "istiod-abc", "syncz");
    expect(syncz).not.toBeNull();
  });

  it("returns cluster resources filtered by kind", () => {
    const namespaces = store.getClusterResources({ kind: "Namespace" });
    expect(namespaces.length).toBe(2);
  });

  it("returns raw file by relative path", async () => {
    const content = await store.getRawFile("versions");
    expect(content).toContain("1.29.1");
  });

  it("returns null for missing files", async () => {
    expect(await store.getRawFile("nonexistent")).toBeNull();
  });
});

describe("BugReportStore lazy cluster resources", () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "store-lazy-cluster-test-"));
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("does not read cluster dumps at load, then parses once and caches", async () => {
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    const dump = join(archiveDir, "cluster", "k8s-resources");
    const store = await BugReportStore.fromDirectory(archiveDir);

    // Rewriting the dump after load is only visible if load did not parse it.
    await writeFile(dump, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: written-after-load\n");
    expect(store.getClusterResources({ kind: "Namespace" }).map((r) => r.metadata.name)).toEqual([
      "written-after-load",
    ]);

    await writeFile(dump, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: second-rewrite\n");
    expect(store.getClusterResources({ kind: "Namespace" }).map((r) => r.metadata.name)).toEqual([
      "written-after-load",
    ]);
    expect(store.detectDataPlaneMode().mode).toBe("sidecar");
  });
});

describe("BugReportStore istiod debug endpoint iteration", () => {
  let tempDir: string;
  let store: BugReportStore;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "store-debug-iter-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    const debugDir = join(archiveDir, "istio", "istio-system", "istiod-abc", "debug");
    await writeFile(join(debugDir, "plain"), "not json\n");
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const freshEndpoints = () => store.getIstiodPods("istio-system")[0].debugEndpoints;

  it("never yields the internal placeholder from values, entries, forEach or spread", () => {
    const fromValues = Array.from(freshEndpoints().values());
    const fromEntries = Array.from(freshEndpoints().entries()).map(([, v]) => v);
    const fromSpread = [...freshEndpoints()].map(([, v]) => v);
    const fromForEach: unknown[] = [];
    freshEndpoints().forEach((v) => fromForEach.push(v));

    for (const values of [fromValues, fromEntries, fromSpread, fromForEach]) {
      expect(values.length).toBeGreaterThanOrEqual(2);
      expect(values.some((v) => typeof v === "symbol")).toBe(false);
    }
  });

  it("iterates the same parsed values that get() returns", () => {
    const endpoints = freshEndpoints();
    for (const [key, value] of endpoints) {
      expect(value).toBe(endpoints.get(key));
    }
    expect(endpoints.get("plain")).toBe("not json\n");
    expect(Array.isArray(endpoints.get("syncz"))).toBe(true);
  });
});

describe("BugReportStore cluster resource dedup", () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "store-dedup-test-"));
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("deduplicates resources that appear in both cluster/k8s-resources and cluster/nodes or cluster/pods", async () => {
    // Real istioctl bug-report archives put Nodes in both `cluster/k8s-resources`
    // (full cluster dump) and `cluster/nodes` (dedicated subset). Without dedup,
    // every Node was counted twice — inflating node count, allocatable CPU,
    // and memory by 2× in resource-savings output.
    const archiveDir = join(tempDir, "bug-report");
    const clusterDir = join(archiveDir, "cluster");
    await mkdir(clusterDir, { recursive: true });

    const node = [
      "apiVersion: v1",
      "kind: Node",
      "metadata:",
      "  name: node-1",
      "status:",
      "  allocatable:",
      "    cpu: \"4\"",
      "    memory: 16Gi",
    ].join("\n");
    const pod = [
      "apiVersion: v1",
      "kind: Pod",
      "metadata:",
      "  name: istiod-abc",
      "  namespace: istio-system",
    ].join("\n");

    await writeFile(join(clusterDir, "k8s-resources"), `${node}\n---\n${pod}\n`);
    await writeFile(join(clusterDir, "nodes"), `${node}\n`);
    await writeFile(join(clusterDir, "pods"), `${pod}\n`);

    const store = await BugReportStore.fromDirectory(archiveDir);

    expect(store.getClusterResources({ kind: "Node" }).length).toBe(1);
    expect(store.getClusterResources({ kind: "Pod" }).length).toBe(1);
  });
});

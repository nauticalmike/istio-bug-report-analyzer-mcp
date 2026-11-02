import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanClusterDumpItems, type ItemScanInfo } from "../../src/archive/namespace-scan.js";
import { scanPodInventory } from "../../src/archive/pod-inventory.js";
import { computeCompleteness } from "../../src/archive/completeness.js";
import { BugReportStore } from "../../src/archive/store.js";
import { createMinimalArchive } from "../fixtures/create-fixture.js";

type Obj = Record<string, unknown>;

const sidecar = (namespace: string, name: string): Obj => ({
  apiVersion: "v1",
  kind: "Pod",
  metadata: { name, namespace, ownerReferences: [{ kind: "ReplicaSet", name: name.split("-").slice(0, -1).join("-") }] },
  spec: { containers: [{ name: "app" }, { name: "istio-proxy", args: ["proxy", "sidecar"] }] },
  status: { phase: "Running" },
});

// JSON is a dump the line scanner does not model, so it falls back to the whole parse.
const jsonList = (items: Obj[]) => JSON.stringify({ apiVersion: "v1", kind: "List", items }, null, 2);
const ROOMY = { heap_size_limit: 8 * 2 ** 30, used_heap_size: 0 };

describe("scanClusterDumpItems whole-parse fallback", () => {
  let dir: string;
  let file: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "item-scan-fallback-"));
    file = join(dir, "dump");
    await writeFile(file, jsonList([sidecar("shop", "cart-7d9f8b6c4d-x2k9p"), sidecar("web", "ui-5b6c7d8f9g-h2j4k")]));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("parses a dump it does not model whole, and says so", () => {
    const info: ItemScanInfo = {};
    const found = scanClusterDumpItems(file, () => true, { info, heap: ROOMY });
    expect(found).toHaveLength(2);
    expect(info.fallback).toMatch(/flow-style/);
    expect(info.gaveUp).toBeUndefined();
  });

  it("reports that it gave up, with the reason, on a dump over the whole-parse limit", () => {
    const info: ItemScanInfo = {};
    expect(scanClusterDumpItems(file, () => true, { info, heap: ROOMY, maxWholeParseBytes: 100 })).toEqual([]);
    expect(info.gaveUp).toMatch(/does not model \(flow-style.*\) and is over the 0 MiB whole-parse limit/);
  });

  it("does not parse whole a dump that would not fit in the heap (heap guard)", () => {
    const info: ItemScanInfo = {};
    const tiny = { heap_size_limit: 4096, used_heap_size: 0 };
    expect(scanClusterDumpItems(file, () => true, { info, heap: tiny })).toEqual([]);
    expect(info.gaveUp).toMatch(/would not fit in the heap/);
  });

  it("uses a whole parse already made instead of parsing again", () => {
    const info: ItemScanInfo = {};
    const given = [sidecar("other", "x-7d9f8b6c4d-x2k9p")] as never[];
    expect(scanClusterDumpItems(file, () => true, { info, heap: ROOMY, maxWholeParseBytes: 100, wholeParse: () => given })).toEqual(given);
    expect(info.fallback).toBeDefined();
    expect(info.gaveUp).toBeUndefined();
  });
});

describe("pod inventory of a dump the scan gave up on", () => {
  let tempDir: string;
  let archiveDir: string;
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "inventory-gave-up-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    await writeFile(join(archiveDir, "cluster", "k8s-resources"), jsonList([sidecar("shop", "cart-7d9f8b6c4d-x2k9p")]));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const files = () => ["cluster/k8s-resources", "cluster/pods"].map((relativePath) => ({ relativePath, absolutePath: join(archiveDir, relativePath) }));

  it("records the reason instead of returning an empty pod list silently", () => {
    const inv = scanPodInventory(files(), { heap: ROOMY, maxWholeParseBytes: 100 });
    expect(inv.gaveUp).toHaveLength(1);
    expect(inv.gaveUp[0]).toMatch(/^cluster\/k8s-resources: /);
    expect(inv.wholeCluster).toBe(false);
  });

  it("turns proxy-coverage and stale-proxy-dirs into not evaluated with that reason", async () => {
    const store = await BugReportStore.fromDirectory(archiveDir);
    const c = computeCompleteness(store, scanPodInventory(files(), { heap: ROOMY, maxWholeParseBytes: 100 }));
    for (const id of ["proxy-coverage", "stale-proxy-dirs"] as const) {
      const s = c.signals.find((x) => x.id === id)!;
      expect(s.status, id).toBe("not_evaluated");
      expect(s.summary, id).toMatch(/pod list is incomplete: cluster\/k8s-resources: .*whole-parse limit/);
    }
    // The ztunnel/CNI check still reports the dirs it has, and says the pod list could not be compared.
    expect(c.signals.find((x) => x.id === "ztunnel-cni-logs")!.details.join("\n")).toMatch(/not compared against the pod list: the pod list is incomplete/);
  });
});

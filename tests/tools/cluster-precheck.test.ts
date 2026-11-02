import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";

// A heap too small for even the minimal archive's dumps, so every guard path triggers.
const fakeHeap = vi.hoisted(() => ({ heap_size_limit: 200, used_heap_size: 0 }));
vi.mock("node:v8", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:v8")>();
  return { ...real, getHeapStatistics: () => ({ ...real.getHeapStatistics(), ...fakeHeap }) };
});

const { BugReportStore } = await import("../../src/archive/store.js");
const { loadBugReport } = await import("../../src/tools/load.js");
const { getOverview } = await import("../../src/tools/overview.js");
const { clusterPreCheckLines } = await import("../../src/tools/cluster-warnings.js");

const textOf = (r: { content: { type: string; text?: string }[] }) => r.content.map((c) => c.text ?? "").join("\n");

describe("cluster dump pre-check", () => {
  let tempDir: string;
  let archiveDir: string;

  beforeEach(async () => {
    fakeHeap.heap_size_limit = 200;
    tempDir = await mkdtemp(join(tmpdir(), "precheck-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
  });

  afterAll(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it("plans from index sizes without parsing anything", async () => {
    const store = await BugReportStore.fromDirectory(archiveDir);
    const plan = store.getClusterDumpPreCheck();
    expect(plan.skipped.length).toBeGreaterThan(0);
    expect(plan.skipped[0].message).toContain("will not be parsed");
    expect(store.isClusterResourcesParsed()).toBe(false);
  });

  it("accepts an injected heap and is silent when the dumps fit", async () => {
    const store = await BugReportStore.fromDirectory(archiveDir);
    expect(store.getClusterDumpPreCheck({ heap_size_limit: 2 ** 32, used_heap_size: 0 }).skipped).toEqual([]);
    expect(clusterPreCheckLines(store, { heap_size_limit: 2 ** 32, used_heap_size: 0 })).toEqual([]);
  });

  it("is reported by load_bug_report and get_overview before any cluster tool runs", async () => {
    let store: InstanceType<typeof BugReportStore> | null = null;
    const loaded = textOf(await loadBugReport({ path: archiveDir }, () => store, (s) => { store = s; }, () => {}));
    expect(loaded).toContain("Cluster dump size warning");
    expect(loaded).toContain("will not be parsed");
    expect(loaded).toContain("NODE_OPTIONS=--max-old-space-size=1024");

    const overview = textOf(await getOverview(store!));
    expect(overview).toContain("Cluster dump size warning");
    expect(store!.isClusterResourcesParsed()).toBe(false);
  });

  it("predicts exactly what the lazy guard reports once the parse runs", async () => {
    const store = await BugReportStore.fromDirectory(archiveDir);
    const predicted = store.getClusterDumpPreCheck().skipped.map((s) => s.message.replace("will not be parsed", "was not parsed"));
    await store.ensureClusterResources();
    expect(store.getClusterLoadIssues()).toEqual(predicted);

    // After the parse, overview shows the parse's own warnings, not the pre-check.
    const overview = textOf(await getOverview(store));
    expect(overview).toContain("Cluster data warnings");
    expect(overview).not.toContain("Cluster dump size warning");
    expect(clusterPreCheckLines(store)).toEqual([]);
  });
});

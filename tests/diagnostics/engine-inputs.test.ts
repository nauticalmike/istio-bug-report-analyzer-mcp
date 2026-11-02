import { describe, it, expect, afterEach } from "vitest";
import { chmod, mkdir, mkdtemp, rm, truncate, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { writeRepeatedLog } from "../fixtures/create-log-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { runDiagnostics } from "../../src/tools/diagnostics.js";
import { MAX_STRING_BYTES } from "../../src/archive/namespace-scan.js";
import type { DiagnosticTemplate, Signal } from "../../src/types.js";
import { cleanupArchives, runEngine } from "./template-harness.js";

const RUN_LARGE = process.env.RUN_LARGE === "1";
const MB = 1024 * 1024;

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  await cleanupArchives();
});

async function archive(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "engine-inputs-"));
  dirs.push(dir);
  const archiveDir = join(dir, "bug-report");
  await createMinimalArchive(archiveDir);
  return archiveDir;
}

function template(id: string, ...signals: Signal[]): DiagnosticTemplate {
  return { id, name: `${id} test`, category: "config", severity: "info", signals, description: "", rootCause: "", impact: "", remediation: [], references: [] };
}

async function run(store: BugReportStore, ...templates: DiagnosticTemplate[]) {
  const engine = new DiagnosticEngine();
  for (const t of templates) engine.addTemplate(t);
  const findings = await engine.run(store);
  return { ids: findings.map((f) => f.templateId), notEvaluated: engine.getNotEvaluated() };
}

const noSidecar: Signal = { source: { type: "resource", kind: "Sidecar", field: "metadata.name" }, check: { op: "not_exists" } };
const fewDeployments: Signal = { source: { type: "resource", kind: "Deployment", field: "metadata.name" }, check: { op: "count_lt", value: 2 } };

describe("templates whose input data is missing from the archive", () => {
  it("lists a 'no Sidecar resource' check as not evaluated when cluster/crs is missing", async () => {
    const dir = await archive();
    await unlink(join(dir, "cluster", "crs"));
    const { ids, notEvaluated } = await run(await BugReportStore.fromDirectory(dir), template("T-CRS", noSidecar));
    expect(ids).toEqual([]);
    expect(notEvaluated).toHaveLength(1);
    expect(notEvaluated[0]).toMatchObject({ templateId: "T-CRS" });
    expect(notEvaluated[0].reason).toMatch(/^not evaluated: cluster\/crs missing/);
  });

  it("lists it as not evaluated when cluster/crs is empty", async () => {
    const dir = await archive();
    await writeFile(join(dir, "cluster", "crs"), "");
    const { ids, notEvaluated } = await run(await BugReportStore.fromDirectory(dir), template("T-CRS", noSidecar));
    expect(ids).toEqual([]);
    expect(notEvaluated[0]?.reason).toMatch(/cluster\/crs is empty/);
  });

  it("still evaluates the check when cluster/crs was collected", async () => {
    const dir = await archive();
    const { ids, notEvaluated } = await run(await BugReportStore.fromDirectory(dir), template("T-CRS", noSidecar));
    expect(ids).toEqual(["T-CRS"]);
    expect(notEvaluated).toEqual([]);
  });

  it("lists a Kubernetes-object count check as not evaluated when cluster/k8s-resources is missing", async () => {
    const dir = await archive();
    await unlink(join(dir, "cluster", "k8s-resources"));
    await unlink(join(dir, "cluster", "pods"));
    const { ids, notEvaluated } = await run(await BugReportStore.fromDirectory(dir), template("T-K8S", fewDeployments));
    expect(ids).toEqual([]);
    expect(notEvaluated[0]?.reason).toMatch(/cluster\/k8s-resources missing/);
  });

  it("lists the version templates as not evaluated when neither the versions file nor pod images give a version", async () => {
    const { findings, engine } = await runEngine({ noVersions: true }, ["version"]);
    expect(findings).toEqual([]);
    const skipped = engine.getNotEvaluated().map((n) => n.templateId).sort();
    expect(skipped).toEqual(["DIAG-001", "DIAG-006"]);
    expect(engine.getNotEvaluated()[0].reason).toMatch(/versions file missing/);
  });

  it("shows the not-evaluated templates in run_diagnostics after the completeness verdict", async () => {
    const dir = await archive();
    await unlink(join(dir, "cluster", "crs"));
    const text = ((await runDiagnostics(await BugReportStore.fromDirectory(dir), {})).content[0] as { text: string }).text;
    expect(text.indexOf("Data completeness: INCOMPLETE")).toBe(0);
    expect(text).toMatch(/Not evaluated or skipped:\n {2}- DIAG-004 \([^)]*\): not evaluated: cluster\/crs missing/);
  });
});

describe("sources that read one file whole", () => {
  it("lists a proxy check as not evaluated when the config dump is over V8's string limit", async () => {
    const dir = await archive();
    // Sparse: the size is all the check looks at.
    await truncate(join(dir, "proxies", "default", "test-pod-abc123", "config_dump?include_eds"), MAX_STRING_BYTES + 1);
    const signal: Signal = { source: { type: "proxy", section: "config_dump", path: "configs" }, check: { op: "not_exists" } };
    const { ids, notEvaluated } = await run(await BugReportStore.fromDirectory(dir), template("T-DUMP", signal));
    expect(ids).toEqual([]);
    expect(notEvaluated[0]?.reason).toMatch(/config_dump\?include_eds is .* MB, over the .* MB that can be read as one string/);
  });
});

describe("log signals read logs through the streaming scanner", () => {
  it.skipIf(process.getuid?.() === 0)("lists a log check as not evaluated when a log cannot be read and nothing matched", async () => {
    const dir = await archive();
    const log = join(dir, "proxies", "default", "test-pod-abc123", "istio-proxy.log");
    await chmod(log, 0o000);
    try {
      const signal: Signal = { source: { type: "logs", component: "proxy", pattern: "Connection refused" }, check: { op: "exists" } };
      const { ids, notEvaluated } = await run(await BugReportStore.fromDirectory(dir), template("T-UNREAD", signal));
      expect(ids).toEqual([]);
      expect(notEvaluated[0]?.reason).toMatch(/^not evaluated: 1 log file\(s\) could not be read \(proxies\/default\/test-pod-abc123\/istio-proxy\.log: /);
    } finally {
      await chmod(log, 0o644);
    }
  });

  /** Makes every whole-file log read fail, as it does for files past V8's string limit. */
  function withoutWholeFileReads(store: BugReportStore): void {
    for (const pod of store.getProxyPods()) Object.defineProperty(pod, "logs", { get: () => null });
    for (const pod of store.getIstiodPods()) Object.defineProperty(pod, "discoveryLog", { get: () => null });
    store.getRawFile = async () => null;
  }

  it("matches proxy, istiod and CNI logs without whole-file reads", async () => {
    const dir = await archive();
    await mkdir(join(dir, "cni", "istio-cni-node-x7k2p"), { recursive: true });
    await writeFile(join(dir, "cni", "istio-cni-node-x7k2p", "cni.log"), "2026-03-18T10:00:00Z\terror\tcni\tSYNTHETIC-CNI-FAILURE\n");
    const store = await BugReportStore.fromDirectory(dir);
    withoutWholeFileReads(store);
    const { ids } = await run(
      store,
      template("T-PROXY", { source: { type: "logs", component: "proxy", pattern: "Connection refused" }, check: { op: "exists" } }),
      template("T-ISTIOD", { source: { type: "logs", component: "istiod", pattern: "XDS: Pushing" }, check: { op: "count_gt", value: 0 } }),
      template("T-CNI", { source: { type: "logs", component: "cni", pattern: "SYNTHETIC-CNI-FAILURE" }, check: { op: "exists" } }),
    );
    expect(ids).toEqual(["T-PROXY", "T-ISTIOD", "T-CNI"]);
  });

  it("hands pattern checks the matching lines", async () => {
    const dir = await archive();
    const store = await BugReportStore.fromDirectory(dir);
    withoutWholeFileReads(store);
    const { ids } = await run(
      store,
      template("T-HIT", { source: { type: "logs", component: "proxy", pattern: "Connection refused" }, check: { op: "contains", value: "10.0.0.5:8080" } }),
      template("T-MISS", { source: { type: "logs", component: "proxy", pattern: "Connection refused" }, check: { op: "contains", value: "Initializing" } }),
    );
    expect(ids).toEqual(["T-HIT"]);
  });

  it.skipIf(!RUN_LARGE)("matches a line at the end of a proxy log over V8's string limit", { timeout: 300_000 }, async () => {
    const dir = await archive();
    const podDir = join(dir, "proxies", "big", "big-pod-0");
    await mkdir(podDir, { recursive: true });
    const block = Array.from({ length: 100 }, (_, i) => `2026-01-01T00:00:00.000000Z\tinfo\tenvoy\trequest ${i} ok`).join("\n") + "\n";
    await writeRepeatedLog(join(podDir, "istio-proxy.log"), 560 * MB, block, "2026-01-01T01:00:00.000000Z\terror\tenvoy\tSYNTHETIC-LATE-FAILURE\n");
    const { ids } = await run(
      await BugReportStore.fromDirectory(dir),
      template("T-LATE", { source: { type: "logs", component: "proxy", pattern: "SYNTHETIC-LATE-FAILURE" }, check: { op: "count_gt", value: 0 } }),
    );
    expect(ids).toEqual(["T-LATE"]);
  });
});

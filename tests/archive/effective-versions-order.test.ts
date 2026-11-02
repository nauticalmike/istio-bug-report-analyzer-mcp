import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { TEMPLATES_DIR, istiodPod, pod } from "../diagnostics/template-harness.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

/** An archive with a valid versions file and ztunnel / istio-cni pods older than the control plane. */
async function archiveWithDaemonPods(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "eff-versions-"));
  dirs.push(dir);
  const a = join(dir, "bug-report");
  await createMinimalArchive(a);
  const resources = [
    istiodPod("istiod-7f9c-abcde", "1.31.2"),
    pod("istio-system", "ztunnel-aaaaa", { app: "ztunnel" }, [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.28.0" }]),
    pod("istio-system", "istio-cni-node-bbbbb", { "k8s-app": "istio-cni-node" }, [{ name: "install-cni", image: "docker.io/istio/install-cni:1.28.0" }]),
    // A DaemonSet template carries the image too; only Pods count.
    { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { namespace: "istio-system", name: "ztunnel" }, spec: { template: { spec: { containers: [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.27.0" }] } } } },
  ];
  await writeFile(join(a, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: resources }));
  return a;
}

describe("getEffectiveVersions call-order independence", () => {
  it("lists ztunnel and CNI versions before the cluster dump is parsed, the same as after", async () => {
    const a = await archiveWithDaemonPods();
    const store = await BugReportStore.fromDirectory(a);
    expect(store.isClusterResourcesParsed()).toBe(false);
    const before = store.getEffectiveVersions();
    expect(store.isClusterResourcesParsed()).toBe(false); // a cheap scan, not the full parse
    expect(before?.ztunnelVersions).toEqual([{ version: "1.28.0", count: 1 }]);
    expect(before?.cniVersions).toEqual([{ version: "1.28.0", count: 1 }]);

    const fresh = await BugReportStore.fromDirectory(a);
    fresh.getClusterResources();
    expect(fresh.getEffectiveVersions()).toEqual(before);
  });

  it("DIAG-001 reports the same skew on the first and the second run", async () => {
    const a = await archiveWithDaemonPods();
    const store = await BugReportStore.fromDirectory(a);
    const engine = new DiagnosticEngine();
    await engine.loadTemplates(TEMPLATES_DIR);
    const first = (await engine.run(store, ["version"])).find((f) => f.templateId === "DIAG-001");
    store.getClusterResources();
    const second = (await engine.run(store, ["version"])).find((f) => f.templateId === "DIAG-001");
    expect(first).toBeDefined();
    expect(first?.affectedResources).toEqual(second?.affectedResources);
    expect(JSON.stringify(first?.affectedResources)).toMatch(/ztunnel/i);
  });

  it("reads ztunnel versions from a JSON pod dump the line scanner does not model", async () => {
    const a = await archiveWithDaemonPods();
    const ztunnel = pod("istio-system", "ztunnel-ccccc", { app: "ztunnel" }, [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.29.1" }]);
    await writeFile(join(a, "cluster", "pods"), JSON.stringify({ apiVersion: "v1", kind: "List", items: [ztunnel] }));
    const store = await BugReportStore.fromDirectory(a);
    const scanned = store.getEffectiveVersions();
    expect(scanned?.ztunnelVersions).toEqual([{ version: "1.28.0", count: 1 }, { version: "1.29.1", count: 1 }]);
    const fresh = await BugReportStore.fromDirectory(a);
    fresh.getClusterResources();
    expect(fresh.getEffectiveVersions()).toEqual(scanned);
  });
});

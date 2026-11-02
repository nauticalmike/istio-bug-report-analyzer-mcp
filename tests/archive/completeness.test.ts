import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { appendFile, mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { bugReportVersions, createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { formatCompleteness, type CompletenessSignalId } from "../../src/archive/completeness.js";
import { writeRepeatedLog } from "../fixtures/create-log-fixture.js";
import { dump } from "js-yaml";
import { istiodPod, sidecarPod, unretrievableVersions } from "../diagnostics/template-harness.js";
import { getCollectionIssues } from "../../src/tools/collection-issues.js";
import { getVersions } from "../../src/tools/versions.js";

describe("data completeness verdict", () => {
  let tempDir: string;
  let dir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "completeness-test-"));
    dir = join(tempDir, "bug-report");
    await createMinimalArchive(dir);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const load = () => BugReportStore.fromDirectory(dir);
  const signal = async (id: CompletenessSignalId) => (await load()).getCompletenessSignal(id);

  it("reports complete for an archive with every section", async () => {
    const store = await load();
    const c = store.getCompleteness();
    const notOk = c.signals.filter((s) => s.status !== "ok");
    expect(notOk).toEqual([]);
    expect(c.verdict).toBe("complete");
    expect(formatCompleteness(c)[0]).toMatch(/^Data completeness: complete/);
  });

  it("flags a missing versions file", async () => {
    await unlink(join(dir, "versions"));
    const s = await signal("versions");
    expect(s.status).toBe("gap");
    expect((await load()).getCompleteness().verdict).toBe("incomplete");
  });

  it("flags a versions file where istioctl could not retrieve pods", async () => {
    await writeFile(join(dir, "versions"), "CLI version:\nversion.BuildInfo{Version:\"1.31.2\"}\n\nunable to retrieve Pods: connection refused\n");
    expect((await signal("versions")).status).toBe("gap");
  });

  it("flags missing or empty cluster/k8s-resources", async () => {
    await writeFile(join(dir, "cluster", "k8s-resources"), "");
    expect((await signal("k8s-resources")).status).toBe("gap");
    await unlink(join(dir, "cluster", "k8s-resources"));
    expect((await signal("k8s-resources")).status).toBe("gap");
  });

  it("flags missing cluster/crs, and empty crs while analyze lists Istio resources", async () => {
    await writeFile(join(dir, "cluster", "crs"), "");
    const empty = await signal("crs");
    expect(empty.status).toBe("gap");
    expect(empty.summary).toMatch(/analyze/);
    await unlink(join(dir, "cluster", "crs"));
    expect((await signal("crs")).status).toBe("gap");
  });

  it("accepts empty cluster/crs when analyze lists no Istio resources", async () => {
    await writeFile(join(dir, "cluster", "crs"), "");
    await writeFile(join(dir, "analyze", "allNamespaces"), "Info [IST0118] (Service default/my-svc) Port name is not following Istio conventions\n");
    expect((await signal("crs")).status).toBe("ok");
  });

  it("flags missing istiod debug endpoints", async () => {
    await rm(join(dir, "istio", "istio-system", "istiod-abc", "debug"), { recursive: true });
    expect((await signal("istiod-debug")).status).toBe("gap");
  });

  it("flags debug output only from an idle istiod revision that serves no proxies", async () => {
    await writeFile(join(dir, "istio", "istio-system", "istiod-abc", "debug", "syncz"), "[]");
    const s = await signal("istiod-debug");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/no proxies/);
  });

  it("flags proxy dirs without a config_dump", async () => {
    await unlink(join(dir, "proxies", "default", "test-pod-abc123", "config_dump?include_eds"));
    const s = await signal("proxy-config-dump");
    expect(s.status).toBe("gap");
    expect(s.details.join("\n")).toContain("default/test-pod-abc123");
  });

  it("flags ztunnel and CNI pods without logs", async () => {
    const zt = join(dir, "proxies", "istio-system", "ztunnel-ab12c");
    await mkdir(zt, { recursive: true });
    await writeFile(join(zt, "config_dump"), JSON.stringify({ workloads: [] }));
    await appendFile(join(dir, "cluster", "pods"), "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ztunnel-ab12c\n  namespace: istio-system\n");
    expect((await signal("ztunnel-cni-logs")).status).toBe("gap");

    await writeFile(join(zt, "istio-proxy.log"), "2026-03-18T10:00:00Z\tinfo\tztunnel started\n");
    expect((await signal("ztunnel-cni-logs")).status).toBe("ok");

    await mkdir(join(dir, "cni", "istio-cni-node-x7k2p"), { recursive: true });
    await writeFile(join(dir, "cni", "istio-cni-node-x7k2p", "cni.log"), "");
    const s = await signal("ztunnel-cni-logs");
    expect(s.status).toBe("gap");
    expect(s.details.join("\n")).toContain("istio-cni-node-x7k2p");
  });

  it("flags a CNI pod in the cluster dump whose logs were not collected", async () => {
    await appendFile(join(dir, "cluster", "pods"), "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: istio-cni-node-q9w8e\n  namespace: kube-system\n");
    const s = await signal("ztunnel-cni-logs");
    expect(s.status).toBe("gap");
    expect(s.details.join("\n")).toContain("istio-cni-node-q9w8e");
  });

  for (const [kind, line] of [
    ["auth", "2026-03-18T10:00:00.000Z\terror\tfailed to list pods: Unauthorized"],
    ["404", "Error: failed to fetch /debug/syncz: the server could not find the requested resource (404)"],
    ["timeout", "2026-03-18T10:00:00.000Z\twarn\tcontext deadline exceeded while fetching proxy logs"],
  ] as const) {
    it(`flags ${kind} errors in bug-report.log`, async () => {
      await writeFile(join(dir, "bug-report.log"), `2026-03-18T10:00:00.000Z\tinfo\tstarting\n${line}\n`);
      const s = await signal("bug-report-log");
      expect(s.status).toBe("gap");
      expect(s.summary).toContain(kind);
    });
  }

  it("does not call bug-report.log clean when lines past the distinct-issue cap were not checked", async () => {
    const lines = Array.from({ length: 5100 }, (_, i) => `2026-03-18T10:00:00.000Z\twarn\tunique warning w${i}`);
    await writeFile(join(dir, "bug-report.log"), lines.join("\n") + "\n");
    const s = await signal("bug-report-log");
    expect(s.status).toBe("not_evaluated");
    expect(s.summary).toContain("100 line(s)");
  });

  it("does not flag info lines that merely mention a timeout setting", async () => {
    await writeFile(join(dir, "bug-report.log"), "2026-03-18T10:00:00.000Z\tinfo\tusing --timeout=30m\n");
    expect((await signal("bug-report-log")).status).toBe("ok");
  });

  it("flags an istioctl client older than the control plane", async () => {
    const v = bugReportVersions("1.29.0").split("\n");
    // CLI 1.29.0, control plane and proxies 1.31.2.
    const cp = bugReportVersions("1.31.2").split("\n");
    await writeFile(join(dir, "versions"), [...v.slice(0, 2), ...cp.slice(2)].join("\n"));
    const s = await signal("istioctl-client");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/1\.29\.0.*1\.31/);
  });

  it("reports the client check as not evaluated when versions are missing", async () => {
    await unlink(join(dir, "versions"));
    const s = await signal("istioctl-client");
    expect(s.status).toBe("not_evaluated");
    expect(formatCompleteness((await load()).getCompleteness()).join("\n")).toMatch(/not evaluated/);
  });

  it("flags proxy dirs with no live pod in the cluster dump (B12)", async () => {
    const stale = join(dir, "proxies", "default", "old-pod-zzz99");
    await mkdir(stale, { recursive: true });
    await writeFile(join(stale, "config_dump?include_eds"), "{}");
    const store = await load();
    const s = store.getCompletenessSignal("stale-proxy-dirs");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/1 of 2 proxy dirs/);
    expect(store.getStaleProxyDirs()).toEqual({ evaluated: true, stale: ["default/old-pod-zzz99"] });
  });

  it("gives the same stale-dir answer before and after the cluster dump is parsed", async () => {
    const stale = join(dir, "proxies", "default", "old-pod-zzz99");
    await mkdir(stale, { recursive: true });
    await writeFile(join(stale, "config_dump?include_eds"), "{}");
    const store = await load();
    const before = store.getStaleProxyDirs();
    await store.ensureClusterResources();
    expect(store.getStaleProxyDirs()).toEqual(before);
  });

  it("flags every proxy dir as stale when the dump lists pods but none of them", async () => {
    await writeFile(join(dir, "cluster", "pods"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: other-pod-11111\n  namespace: default\n");
    const s = await signal("stale-proxy-dirs");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/1 of 1 proxy dir/);
  });

  it("passes the stale-dir check for an archive with no proxy dirs", async () => {
    await rm(join(dir, "proxies"), { recursive: true });
    expect((await signal("stale-proxy-dirs")).status).toBe("ok");
  });

  it("reports the stale-dir check as not evaluated without a pod list", async () => {
    await unlink(join(dir, "cluster", "pods"));
    await unlink(join(dir, "cluster", "k8s-resources"));
    expect((await signal("stale-proxy-dirs")).status).toBe("not_evaluated");
  });

  it("notes the collection span from file times when it is long", async () => {
    const stale = join(dir, "proxies", "default", "old-pod-zzz99");
    await mkdir(stale, { recursive: true });
    const old = join(stale, "config_dump?include_eds");
    await writeFile(old, "{}");
    const { utimes } = await import("node:fs/promises");
    const fiveHoursAgo = new Date(Date.now() - 5 * 3600 * 1000);
    await utimes(old, fiveHoursAgo, fiveHoursAgo);
    const s = await signal("stale-proxy-dirs");
    expect(s.details.join("\n")).toMatch(/over ~5\.0 h/);
  });

  it("finds collection errors past the first 64 MiB of bug-report.log", async () => {
    const info = Array.from({ length: 100 }, (_, i) => `2026-03-18T10:00:00.000Z\tinfo\tcollecting proxy ${i}`).join("\n") + "\n";
    await writeRepeatedLog(join(dir, "bug-report.log"), 70 * 2 ** 20, info, "2026-03-18T11:00:00.000Z\terror\tfailed to list pods: Unauthorized\n");
    const s = await signal("bug-report-log");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/auth x1/);
    expect(s.summary).not.toMatch(/scanned/);
  });

  it("reads bug-report.log once per load for both the verdict and the collection issues", async () => {
    await writeFile(join(dir, "bug-report.log"), "Error: failed to fetch /debug/syncz: the server could not find the requested resource (404)\n");
    const spy = vi.spyOn(BugReportStore.prototype, "scanFileLines");
    const ranges = vi.spyOn(BugReportStore.prototype, "readFileRange");
    try {
      const store = await load();
      store.getCompleteness();
      await getCollectionIssues(store);
      expect(store.getCompletenessSignal("bug-report-log").status).toBe("gap");
      expect(spy.mock.calls.filter(([path]) => path === "bug-report.log")).toHaveLength(1);
      // Only the capture-time tail read; no second, bounded read of the whole log.
      expect(ranges.mock.calls.filter(([path, , length]) => path === "bug-report.log" && length > 16 * 1024)).toHaveLength(0);
    } finally {
      spy.mockRestore();
      ranges.mockRestore();
    }
  });

  it("counts collection errors listed under an 'N errors occurred' header", async () => {
    await writeFile(join(dir, "bug-report.log"), "Error: 2 errors occurred:\n\t* failed to get proxy-a: Forbidden\n\t* failed to get proxy-b: Forbidden\n");
    const s = await signal("bug-report-log");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/auth x2/);
  });

  it("does not read a timeout query parameter in a URL as a timeout error", async () => {
    await writeFile(join(dir, "bug-report.log"), 'Error: Get "https://10.96.0.1:443/api/v1/namespaces/shop/pods?timeout=10m0s": dial tcp 10.96.0.1:443: connect: connection refused\n');
    expect((await signal("bug-report-log")).status).toBe("ok");
  });

  it("still flags a timeout reported after a URL", async () => {
    await writeFile(join(dir, "bug-report.log"), 'Error: Get "https://10.96.0.1:443/api/v1/pods?timeout=32s": context deadline exceeded\n');
    expect((await signal("bug-report-log")).summary).toMatch(/timeout x1/);
  });

  it("counts each repeat of an identical bullet under a header", async () => {
    await writeFile(join(dir, "bug-report.log"), "Error: 3 errors occurred:\n\t* failed to get proxy-a: Forbidden\n\t* failed to get proxy-a: Forbidden\n\t* failed to get proxy-a: Forbidden\n");
    expect((await signal("bug-report-log")).summary).toMatch(/auth x3/);
  });

  it("says when versions come from pod image tags instead of calling them unknown", async () => {
    await writeFile(join(dir, "versions"), unretrievableVersions("1.31.2"));
    await writeFile(join(dir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: [istiodPod("istiod-7f9c-abcde", "1.31.2"), sidecarPod("shop", "cart-1", "1.31.2")] }));
    const s = await signal("versions");
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/versions file unusable.*versions derived from pod image tags/);
    expect(s.summary).not.toMatch(/unknown/);
  });

  it("keeps 'versions unknown' when neither the versions file nor pod images give a version", async () => {
    await unlink(join(dir, "versions"));
    expect((await signal("versions")).summary).toMatch(/unknown/);
  });

  it("agrees with the versions tool on an istioctl older than a control plane known from images", async () => {
    await writeFile(join(dir, "versions"), unretrievableVersions("1.29.0"));
    await writeFile(join(dir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: [istiodPod("istiod-7f9c-abcde", "1.31.2"), sidecarPod("shop", "cart-1", "1.31.2")] }));
    const store = await load();
    const s = store.getCompletenessSignal("istioctl-client");
    const tool = (getVersions(store).content[0] as { text: string }).text;
    expect(tool).toMatch(/istioctl client 1\.29\.0 is older than the control plane \(1\.31\)/);
    expect(s.status).toBe("gap");
    expect(s.summary).toMatch(/istioctl 1\.29\.0 is older than the control plane \(1\.31\)/);
  });
});

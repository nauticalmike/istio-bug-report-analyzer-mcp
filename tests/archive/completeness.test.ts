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

  it("notes collected ztunnel and CNI dirs with an empty log without calling them missing", async () => {
    const zt = join(dir, "proxies", "istio-system", "ztunnel-bc2d4");
    await mkdir(zt, { recursive: true });
    await writeFile(join(zt, "config_dump"), JSON.stringify({ workloads: [] }));
    await appendFile(join(dir, "cluster", "pods"), "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ztunnel-bc2d4\n  namespace: istio-system\n");
    await mkdir(join(dir, "cni", "istio-cni-node-x7k2p"), { recursive: true });
    await writeFile(join(dir, "cni", "istio-cni-node-x7k2p", "cni.log"), "");
    const s = await signal("ztunnel-cni-logs");
    // istioctl skips a log with no lines in its time window: the pod was collected.
    expect(s.status).toBe("ok");
    expect(s.details.join("\n")).toMatch(/2 collected dirs with an empty or no log.*ztunnel-bc2d4.*istio-cni-node-x7k2p/);
  });

  it("flags a ztunnel pod in the cluster dump with no dir collected", async () => {
    await appendFile(join(dir, "cluster", "pods"), "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ztunnel-bc2d4\n  namespace: istio-system\n");
    const s = await signal("ztunnel-cni-logs");
    expect(s.status).toBe("gap");
    expect(s.details.join("\n")).toContain("istio-system/ztunnel-bc2d4 (ztunnel, in cluster dump, not collected)");
  });

  it("does not take non-pod objects or names outside the Kubernetes suffix alphabet as ztunnel/CNI pods", async () => {
    await appendFile(
      join(dir, "cluster", "pods"),
      [
        "---\napiVersion: v1\nkind: Event\nmetadata:\n  name: ztunnel-bc2d4\n  namespace: istio-system\n",
        "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: istio-cni-node-x7k2p\n  namespace: kube-system\n",
        "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ztunnel-aeiou\n  namespace: istio-system\n",
      ].join(""),
    );
    expect((await signal("ztunnel-cni-logs")).status).toBe("ok");
  });

  it("flags a CNI pod in the cluster dump whose logs were not collected", async () => {
    await appendFile(join(dir, "cluster", "pods"), "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: istio-cni-node-q9w8z\n  namespace: kube-system\n");
    const s = await signal("ztunnel-cni-logs");
    expect(s.status).toBe("gap");
    expect(s.details.join("\n")).toContain("istio-cni-node-q9w8z");
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
    expect(store.getStaleProxyDirs()).toEqual({ evaluated: true, stale: ["default/old-pod-zzz99"], unknown: [] });
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

  it("does not call proxy dirs stale in namespaces a partial pod dump does not cover", async () => {
    // No cluster/k8s-resources: cluster/pods holds only the Istio namespace.
    await unlink(join(dir, "cluster", "k8s-resources"));
    await writeFile(join(dir, "cluster", "pods"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\n");
    const gw = join(dir, "proxies", "istio-system", "old-gateway-zzz99");
    await mkdir(gw, { recursive: true });
    await writeFile(join(gw, "config_dump?include_eds"), "{}");
    const store = await load();
    expect(store.getStaleProxyDirs()).toEqual({ evaluated: true, stale: ["istio-system/old-gateway-zzz99"], unknown: ["default/test-pod-abc123"] });
    const s = store.getCompletenessSignal("stale-proxy-dirs");
    expect(s.summary).toMatch(/^1 of 1 proxy dir have no live pod/);
    expect(s.details.join("\n")).toMatch(/1 of 2 proxy dirs are in namespaces the pod dump does not cover/);
  });

  it("reports the stale-dir check as not evaluated when the pod dump covers none of the proxy namespaces", async () => {
    await unlink(join(dir, "cluster", "k8s-resources"));
    await writeFile(join(dir, "cluster", "pods"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\n");
    expect((await signal("stale-proxy-dirs")).status).toBe("not_evaluated");
  });

  it("counts a stale proxy dir only as stale, not also as a missing config_dump or log", async () => {
    const stale = join(dir, "proxies", "istio-system", "ztunnel-zzz99");
    await mkdir(stale, { recursive: true });
    await writeFile(join(stale, "istio-proxy.log"), "");
    const store = await load();
    expect(store.getCompletenessSignal("stale-proxy-dirs").status).toBe("gap");
    expect(store.getCompletenessSignal("proxy-config-dump").status).toBe("ok");
    expect(store.getCompletenessSignal("ztunnel-cni-logs").details.join("\n")).not.toContain("ztunnel-zzz99");
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

describe("three-level completeness verdict", () => {
  let tempDir: string;
  let dir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "completeness-levels-"));
    dir = join(tempDir, "bug-report");
    await createMinimalArchive(dir);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const load = () => BugReportStore.fromDirectory(dir);
  const signal = async (id: CompletenessSignalId) => (await load()).getCompletenessSignal(id);
  const podDoc = (namespace: string, name: string, proxy = true) =>
    `---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ${name}\n  namespace: ${namespace}\n  ownerReferences:\n  - apiVersion: apps/v1\n    kind: ReplicaSet\n    name: ${name.replace(/-[^-]+$/, "")}\nspec:\n  containers:\n    - name: app\n${proxy ? "    - name: istio-proxy\n      args:\n        - proxy\n        - sidecar\n" : ""}status:\n  phase: Running\n`;
  /** n injected pods in the dump, the first `withDirs` of them with a proxy dir (config_dump unless noDump). */
  const sidecars = async (n: number, withDirs: number, noDump = 0) => {
    for (let i = 0; i < n; i++) {
      const name = `app-${i}-7d9f8b6c4d-x2k9p`;
      await appendFile(join(dir, "cluster", "pods"), podDoc("shop", name));
      if (i >= withDirs) continue;
      const d = join(dir, "proxies", "shop", name);
      await mkdir(d, { recursive: true });
      await writeFile(join(d, i < noDump ? "istio-proxy.log" : "config_dump?include_eds"), "{}");
    }
  };

  it("is complete with minor gaps when only minor signals have gaps", async () => {
    const stale = join(dir, "proxies", "default", "old-pod-zzz99");
    await mkdir(stale, { recursive: true });
    await writeFile(join(stale, "config_dump?include_eds"), "{}");
    const c = (await load()).getCompleteness();
    expect(c.signals.filter((s) => s.status === "gap").map((s) => [s.id, s.minor])).toEqual([["stale-proxy-dirs", true]]);
    expect(c.verdict).toBe("complete_with_minor_gaps");
    const text = formatCompleteness(c);
    expect(text[0]).toMatch(/^Data completeness: complete with minor gaps \(1 minor gap\)/);
    expect(text[1]).toMatch(/^  - \[minor\] stale-proxy-dirs: /);
  });

  it("is incomplete when any signal has a major gap, and lists major before minor", async () => {
    await unlink(join(dir, "cluster", "crs"));
    const stale = join(dir, "proxies", "default", "old-pod-zzz99");
    await mkdir(stale, { recursive: true });
    await writeFile(join(stale, "config_dump?include_eds"), "{}");
    const c = (await load()).getCompleteness();
    expect(c.verdict).toBe("incomplete");
    const text = formatCompleteness(c);
    expect(text[0]).toMatch(/^Data completeness: INCOMPLETE \(1 major gap, 1 minor gap\)/);
    expect(text[1]).toMatch(/^  - \[missing\] crs: /);
    expect(text[2]).toMatch(/^  - \[minor\] stale-proxy-dirs: /);
  });

  it("does not let a check that could not run set the verdict", async () => {
    await unlink(join(dir, "bug-report.log"));
    const c = (await load()).getCompleteness();
    expect(c.verdict).toBe("complete");
    const text = formatCompleteness(c);
    expect(text[0]).toMatch(/^Data completeness: complete \(\d+ checks passed, 1 not evaluated\):$/);
    expect(text[1]).toMatch(/^  - \[not evaluated\] bug-report-log: /);
  });

  it("rates missing config_dumps as minor under 10% of live proxy dirs and major from 10%", async () => {
    await sidecars(19, 19, 1);
    // 1 of 20 live dirs (19 plus the fixture's).
    expect(await signal("proxy-config-dump")).toMatchObject({ status: "gap", minor: true });
    await rm(join(dir, "proxies", "shop", "app-1-7d9f8b6c4d-x2k9p", "config_dump?include_eds"));
    await writeFile(join(dir, "proxies", "shop", "app-1-7d9f8b6c4d-x2k9p", "istio-proxy.log"), "x");
    // 2 of 20.
    expect((await signal("proxy-config-dump")).minor).toBeUndefined();
  });

  it("rates uncollected ztunnel/CNI pods as minor under 25% of those in the dump and major from 25%", async () => {
    const names = ["ztunnel-b2c4d", "ztunnel-f5g6h", "ztunnel-j7k8l", "ztunnel-m9n2p", "ztunnel-q4r5s"];
    for (const name of names) await appendFile(join(dir, "cluster", "pods"), podDoc("istio-system", name, false));
    for (const name of names.slice(1)) {
      await mkdir(join(dir, "proxies", "istio-system", name), { recursive: true });
      await writeFile(join(dir, "proxies", "istio-system", name, "istio-proxy.log"), "x");
    }
    expect(await signal("ztunnel-cni-logs")).toMatchObject({ status: "gap", minor: true }); // 1 of 5
    await rm(join(dir, "proxies", "istio-system", names[1]), { recursive: true });
    expect((await signal("ztunnel-cni-logs")).minor).toBeUndefined(); // 2 of 5
  });

  it("rates per-pod collection errors as minor and auth errors on list/watch as major", async () => {
    await writeFile(join(dir, "bug-report.log"), "Error: failed to port-forward to shop/cart-1: context deadline exceeded\nError: 2 errors occurred:\n\t* exec into shop/cart-2: the server could not find the requested resource (404)\n\t* exec into shop/cart-3: Forbidden\n");
    expect(await signal("bug-report-log")).toMatchObject({ status: "gap", minor: true });
    await appendFile(join(dir, "bug-report.log"), "2026-03-18T10:00:00.000Z\terror\tfailed to list *v1.Pod: pods is forbidden: User cannot list resource\n");
    expect((await signal("bug-report-log")).minor).toBeUndefined();
  });

  it("rates a missing istiod as major", async () => {
    await writeFile(join(dir, "bug-report.log"), "Error: could not find istiod in namespace istio-system\n");
    const s = await signal("bug-report-log");
    expect(s.summary).toMatch(/no istiod x1/);
    expect(s.minor).toBeUndefined();
  });

  it("rates an istioctl one minor behind as minor and two or more as major", async () => {
    const cp = bugReportVersions("1.31.2").split("\n");
    const withClient = (v: string) => [...bugReportVersions(v).split("\n").slice(0, 2), ...cp.slice(2)].join("\n");
    await writeFile(join(dir, "versions"), withClient("1.30.1"));
    expect(await signal("istioctl-client")).toMatchObject({ status: "gap", minor: true });
    await writeFile(join(dir, "versions"), withClient("1.29.0"));
    expect((await signal("istioctl-client")).minor).toBeUndefined();
  });

  it("rates istiod pods without debug output as minor when another istiod has it", async () => {
    await mkdir(join(dir, "istio", "istio-system", "istiod-def"), { recursive: true });
    await writeFile(join(dir, "istio", "istio-system", "istiod-def", "discovery.log"), "x");
    const s = await signal("istiod-debug");
    expect(s).toMatchObject({ status: "gap", minor: true });
    expect(s.summary).toBe("1 of 2 istiod pods have no debug output");
  });

  it("rates versions derived from pod image tags as minor and unknown versions as major", async () => {
    await writeFile(join(dir, "versions"), unretrievableVersions("1.31.2"));
    await writeFile(join(dir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: [istiodPod("istiod-7f9c-abcde", "1.31.2"), sidecarPod("shop", "cart-1", "1.31.2")] }));
    expect(await signal("versions")).toMatchObject({ status: "gap", minor: true });
    await unlink(join(dir, "versions"));
    await writeFile(join(dir, "cluster", "k8s-resources"), "");
    expect((await signal("versions")).minor).toBeUndefined();
  });

  it("flags proxy coverage below half of the injected pods as a major gap", async () => {
    await sidecars(9, 4);
    // 5 of 10 injected pods (with the fixture's) have a dir: half is enough.
    expect((await signal("proxy-coverage")).status).toBe("ok");
    await rm(join(dir, "proxies", "shop", "app-0-7d9f8b6c4d-x2k9p"), { recursive: true });
    const s = await signal("proxy-coverage");
    expect(s.status).toBe("gap");
    expect(s.minor).toBeUndefined();
    expect(s.summary).toMatch(/^4 of 10 proxy pods in the pod dump have a proxy dir \(sidecars 4\/10\)/);
    expect(s.summary).not.toMatch(/sample/);
  });

  it("keeps the structured API: every signal has an id, a status and details", async () => {
    const store = await load();
    for (const s of store.getCompleteness().signals) {
      expect(store.getCompletenessSignal(s.id)).toBe(s);
      expect(["ok", "gap", "not_evaluated"]).toContain(s.status);
      expect(Array.isArray(s.details)).toBe(true);
    }
  });
});

describe("proxy-coverage signal", () => {
  type Obj = Record<string, unknown>;
  let tempDir: string;
  let dir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "proxy-coverage-"));
    dir = join(tempDir, "bug-report");
    await createMinimalArchive(dir);
    // Only istiod in cluster/pods and no proxy dirs: each test adds its own.
    await writeFile(join(dir, "cluster", "pods"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\nspec:\n  containers:\n    - name: discovery\n");
    await rm(join(dir, "proxies"), { recursive: true });
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const signal = async () => (await BugReportStore.fromDirectory(dir)).getCompletenessSignal("proxy-coverage");
  const owner = (kind: string, name: string) => [{ apiVersion: "apps/v1", kind, name, controller: true }];
  const rsOf = (name: string) => name.split("-").slice(0, -1).join("-");
  type Role = "sidecar" | "gateway" | "waypoint" | "ztunnel";
  /** A pod of the given role; owned by a ReplicaSet named after it unless `ownerKind` says otherwise. */
  const pod = (namespace: string, name: string, role: Role = "sidecar", opts: { ownerKind?: string; phase?: string } = {}): Obj => {
    const ownerKind = opts.ownerKind ?? (role === "ztunnel" ? "DaemonSet" : "ReplicaSet");
    const labels = role === "waypoint" ? { "gateway.istio.io/managed": "istio.io-mesh-controller" } : { app: name };
    const args = role === "sidecar" ? ["proxy", "sidecar"] : role === "ztunnel" ? ["proxy", "ztunnel"] : ["proxy", "router"];
    const image = role === "ztunnel" ? "docker.io/istio/ztunnel:1.31.2" : "docker.io/istio/proxyv2:1.31.2";
    return {
      apiVersion: "v1",
      kind: "Pod",
      metadata: { name, namespace, labels, ownerReferences: owner(ownerKind, ownerKind === "ReplicaSet" ? rsOf(name) : name.replace(/-\d+$/, "")) },
      spec: { containers: [...(role === "sidecar" ? [{ name: "app" }] : []), { name: "istio-proxy", image, args }] },
      status: { phase: opts.phase ?? "Running" },
    };
  };
  const replicaSet = (namespace: string, name: string, ownerKind: string): Obj => ({
    apiVersion: "apps/v1",
    kind: "ReplicaSet",
    metadata: { name, namespace, ownerReferences: owner(ownerKind, name.replace(/-[^-]+$/, "")) },
  });
  const writeDump = (items: Obj[]) => writeFile(join(dir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items }));
  const addDir = async (namespace: string, name: string) => {
    const d = join(dir, "proxies", namespace, name);
    await mkdir(d, { recursive: true });
    await writeFile(join(d, "config_dump"), "{}");
  };
  const names = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => `${prefix}-${i}-7d9f8b6c4d-x2k9p`);

  /** Fix A: 4 Deployment pods with dirs, plus pods istioctl never collects or that are not Running. */
  async function fixA(withReplicaSets: boolean) {
    const deployed = names("app", 4);
    const rollout = Array.from({ length: 6 }, (_, i) => `canary-5f6d7c8b9d-k${"bcdfgh"[i]}2j4`);
    await writeDump([
      ...deployed.map((n) => pod("shop", n)),
      ...rollout.map((n) => pod("shop", n)),
      pod("shop", "db-0", "sidecar", { ownerKind: "StatefulSet" }),
      pod("kube-system", "dns-7d9f8b6c4d-m2n4p"),
      pod("shop", "late-7d9f8b6c4d-q8z4w", "sidecar", { phase: "Pending" }),
      ...(withReplicaSets ? [replicaSet("shop", "app-0-7d9f8b6c4d", "Deployment"), replicaSet("shop", "canary-5f6d7c8b9d", "Rollout")] : []),
    ]);
    for (const n of deployed) await addDir("shop", n);
  }

  it("counts only Running pods istioctl bug-report can collect (Fix A)", async () => {
    await fixA(true);
    const s = await signal();
    expect(s.status).toBe("ok");
    expect(s.summary).toMatch(/^4 of 4 proxy pods/);
    expect(s.details).toContain("8 injected pods istioctl bug-report never collects (StatefulSet/Job/Rollout/bare pod or system namespace)");
    expect(s.details).toContain("1 injected pod not Running (Pending/Unknown)");
  });

  it("counts Rollout pods again when their ReplicaSet was not dumped (unknown owner is collectable)", async () => {
    await fixA(false);
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBeUndefined();
    expect(s.summary).toMatch(/^4 of 10 proxy pods/);
  });

  it("is not evaluated when the pod dump (cluster/pods only) does not cover the proxy dirs' namespaces (Fix B)", async () => {
    await rm(join(dir, "cluster", "k8s-resources"));
    const gateways = ["istio-ingressgateway-5b6c7d8f9g-h2j4k", "istio-ingressgateway-5b6c7d8f9g-q8z4w", "istio-eastwestgateway-6c7d8f9b5d-x2k9p"];
    await appendFile(join(dir, "cluster", "pods"), gateways.map((n) => `---\n${dump(pod("istio-system", n, "gateway"))}`).join(""));
    for (const n of names("app", 10)) await addDir("shop", n);
    const s = await signal();
    expect(s.status).toBe("not_evaluated");
    expect(s.summary).toMatch(/the pod dump covers only 1 namespace \(no cluster\/k8s-resources\); 10 of 10 proxy dirs are in namespaces it does not cover/);
    expect(s.details.join("\n")).toMatch(/0 of 3 proxy pods in the namespaces the pod dump covers have a proxy dir/);
    expect(`${s.summary}\n${s.details.join("\n")}`).not.toMatch(/sample/);
  });

  it("says no proxy dirs were collected when proxies/ is missing (Fix C)", async () => {
    await writeDump(names("app", 5).map((n) => pod("shop", n)));
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBeUndefined();
    expect(s.summary).toMatch(/^no proxy dirs \(proxies\/ missing\): proxy configs and logs were not collected for any of the 5 proxy pods/);
    expect(s.summary).not.toMatch(/sample/);
  });

  const ztunnels = ["ztunnel-bc2d4", "ztunnel-x7k2p", "ztunnel-q9w8z"];
  async function ambient(ztunnelDirs: number) {
    await writeDump([...ztunnels.map((n) => pod("istio-system", n, "ztunnel")), pod("shop", "waypoint-6c7d8f9b5d-q8z4w", "waypoint")]);
    for (const n of ztunnels.slice(0, ztunnelDirs)) await addDir("istio-system", n);
  }

  it("counts ztunnel as the ambient data plane: a waypoint-only shortfall is minor (Fix D)", async () => {
    await ambient(3);
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBe(true);
    expect(s.summary).toMatch(/waypoints 0\/1, ztunnel 3\/3/);
  });

  it("is a major gap when the ztunnel data plane itself is not covered", async () => {
    await ambient(1);
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBeUndefined();
    expect(s.summary).toMatch(/^1 of 4 proxy pods .*\(waypoints 0\/1, ztunnel 1\/3\)/);
  });

  async function threeNamespaces(covered: [number, number, number]) {
    const sizes = [3, 5, 4];
    const items: Obj[] = [];
    for (const [i, ns] of ["a", "b", "c"].entries()) {
      const ns_names = names(`app${ns}`, sizes[i]);
      items.push(...ns_names.map((n) => pod(ns, n)));
      for (const n of ns_names.slice(0, covered[i])) await addDir(ns, n);
    }
    await writeDump(items);
  }

  it("calls a namespace-scoped collection a minor gap with scope wording (Fix E)", async () => {
    await threeNamespaces([3, 0, 0]);
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBe(true);
    expect(s.summary).toMatch(/proxy dirs cover 1 of 3 namespaces with proxy pods \(3 of 12 pods, 100% within those namespaces\): a namespace-scoped collection/);
    expect(s.details.join("\n")).toMatch(/2 namespaces with proxy pods have no proxy dir: b, c/);
    expect(s.summary).not.toMatch(/sample/);
  });

  it("keeps a shortfall spread across namespaces major", async () => {
    await threeNamespaces([1, 1, 1]);
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBeUndefined();
    expect(s.summary).toMatch(/^3 of 12 proxy pods/);
  });

  it("calls a gateway-only collection a minor gap with scope wording (Fix E)", async () => {
    const gws = ["istio-ingressgateway-5b6c7d8f9g-h2j4k", "istio-ingressgateway-5b6c7d8f9g-q8z4w"];
    await writeDump([...gws.map((n) => pod("istio-system", n, "gateway")), ...names("app", 10).map((n) => pod("istio-system", n))]);
    for (const n of gws) await addDir("istio-system", n);
    const s = await signal();
    expect(s.status).toBe("gap");
    expect(s.minor).toBe(true);
    expect(s.summary).toMatch(/only gateway proxies were collected/);
    expect(s.summary).toMatch(/sidecars 0\/10, gateways 2\/2/);
  });
});

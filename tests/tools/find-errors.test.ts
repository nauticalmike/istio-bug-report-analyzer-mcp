import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { chmod, mkdtemp, rm, mkdir, writeFile, appendFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { findErrors } from "../../src/tools/find-errors.js";
import { noisyProxyLogBlock } from "../fixtures/create-log-fixture.js";

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
    const proxyNs = join(archiveDir, "proxies", "default");
    const [proxyPod] = await readdir(proxyNs);
    await appendFile(
      join(proxyNs, proxyPod, "istio-proxy.log"),
      '2026-10-20T20:22:24.038239Z\tinfo\tFLAG: --proxyComponentLogLevel="misc:error"\n',
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

  it("ignores info lines that merely mention error", async () => {
    const result = await findErrors(store, { component: "proxy" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).not.toContain("proxyComponentLogLevel");
    expect(text).toContain("Slow response from upstream");
  });

  it("deduplicates similar error patterns", async () => {
    const result = await findErrors(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toMatch(/\d+ unique/);
  });
});

describe("findErrors grouping", () => {
  let tempDir: string;
  let store: BugReportStore;
  const textOf = async (params: Parameters<typeof findErrors>[1] = {}) =>
    ((await findErrors(store, params)).content[0] as { type: "text"; text: string }).text;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "errors-grouping-"));
    const archiveDir = join(tempDir, "bug-report");
    // 10k lines per pod that differ only in normalized tokens: five patterns, three pods.
    for (const pod of ["web-a", "web-b", "web-c"]) {
      const dir = join(archiveDir, "proxies", "shop", pod);
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "istio-proxy.log"), noisyProxyLogBlock(10_000));
    }
    await appendFile(
      join(archiveDir, "proxies", "shop", "web-c", "istio-proxy.log"),
      "2026-01-01T01:00:00.000000Z\terror\tca\tRARE-REAL-ERROR certificate signing failed\n",
    );
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("collapses lines that differ only in volatile tokens", async () => {
    const text = await textOf();
    expect(text).toContain("=== 6 unique error patterns found (30001 total lines) ===");
  });

  it("counts the distinct pods of each pattern", async () => {
    const text = await textOf();
    expect(text).toMatch(/\[x6000\] proxy\/shop\/web-a \(3 pods\) \[error\]\n {2}Pattern: error cache secret fetch/);
    expect(text).toMatch(/\[x1\] proxy\/shop\/web-c \[error\]\n {2}Pattern: error ca RARE-REAL-ERROR/);
  });

  it("ranks errors above warnings, then by count, and known noise last", async () => {
    const text = await textOf();
    const order = ["secret fetch", "RARE-REAL-ERROR", "upstream <IP> reset", "health check failed", "failed scraping", "Request to probe app"].map((s) => text.indexOf(s));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(text).toMatch(/\[x6000\] proxy\/shop\/web-a \(3 pods\) \[error\] \[noise: metrics scrape\]/);
    expect(text).toMatch(/\[x6000\] proxy\/shop\/web-a \(3 pods\) \[warn\] \[noise: probe\]/);
  });

  it("keeps the ranking across pages", async () => {
    const first = await textOf({ limit: 2 });
    expect(first).toContain("RARE-REAL-ERROR");
    expect(first).toContain("Showing patterns 1-2 of 6. Pass offset=2 for more");
    const last = await textOf({ limit: 2, offset: 4 });
    expect(last).toContain("Request to probe app");
  });
});

describe("findErrors limits", () => {
  let tempDir: string;
  let store: BugReportStore;
  // Distinct letters-only words, which no normalization rule touches.
  const word = (n: number) => n.toString(26).replace(/./g, (c) => String.fromCharCode(97 + parseInt(c, 26)));

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "errors-limits-"));
    const dir = join(tempDir, "bug-report", "proxies", "big", "many-pod-0");
    await mkdir(dir, { recursive: true });
    const lines = Array.from({ length: 20_005 }, (_, i) => `2026-01-01T00:00:00Z\terror\tdistinct failure ${word(i)}`);
    lines.push(`2026-01-01T00:00:00Z\terror\tlong ${"x".repeat(1024 * 1024 + 10)}`);
    await writeFile(join(dir, "istio-proxy.log"), lines.join("\n") + "\n");
    store = await BugReportStore.fromDirectory(join(tempDir, "bug-report"));
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("says when lines fell past the pattern cap or were cut, instead of dropping them silently", async () => {
    const text = ((await findErrors(store, { limit: 1 })).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("=== 20000 unique error patterns found (20006 total lines) ===");
    expect(text).toContain("Note: 6 line(s) matched none of the first 20,000 patterns and are only counted in the total");
    expect(text).toContain("Note: 1 line(s) longer than 1 MB were matched on their first 1 MB only.");
  });
});

describe("findErrors with an unreadable log", () => {
  let tempDir: string;
  let logPath: string;

  afterAll(async () => {
    if (logPath) await chmod(logPath, 0o644).catch(() => {});
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it.skipIf(process.getuid?.() === 0)("says which file it skipped instead of treating it as empty", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "errors-unreadable-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    const store = await BugReportStore.fromDirectory(archiveDir);
    const [pod] = store.getProxyPods();
    logPath = join(archiveDir, "proxies", pod.namespace, pod.podName, "istio-proxy.log");
    await chmod(logPath, 0o000);
    const text = ((await findErrors(store, { component: "proxy" })).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("No error/warning lines found.");
    expect(text).toContain(`1 log file(s) could not be read and were skipped: proxies/${pod.namespace}/${pod.podName}/istio-proxy.log`);
  });
});

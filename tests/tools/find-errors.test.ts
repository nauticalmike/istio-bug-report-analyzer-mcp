import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { chmod, mkdtemp, rm, mkdir, writeFile, appendFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { findErrors } from "../../src/tools/find-errors.js";

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

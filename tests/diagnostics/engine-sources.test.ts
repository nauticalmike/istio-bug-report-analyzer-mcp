import { describe, it, expect, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { meshConfig } from "../../src/diagnostics/checks.js";
import type { DiagnosticTemplate, Signal } from "../../src/types.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function archive(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "engine-sources-"));
  dirs.push(dir);
  const archiveDir = join(dir, "bug-report");
  await createMinimalArchive(archiveDir);
  return archiveDir;
}

async function istiod(archiveDir: string, pod: string, debug: Record<string, unknown>): Promise<void> {
  const dir = join(archiveDir, "istio", "istio-system", pod, "debug");
  await mkdir(dir, { recursive: true });
  for (const [endpoint, value] of Object.entries(debug)) await writeFile(join(dir, endpoint), JSON.stringify(value));
}

function template(signal: Signal): DiagnosticTemplate {
  return {
    id: "TEST-SRC",
    name: "source test",
    category: "config",
    severity: "info",
    signals: [signal],
    description: "",
    rootCause: "",
    impact: "",
    remediation: [],
    references: [],
  };
}

async function fires(archiveDir: string, signal: Signal): Promise<boolean> {
  const store = await BugReportStore.fromDirectory(archiveDir);
  const engine = new DiagnosticEngine();
  engine.addTemplate(template(signal));
  return (await engine.run(store)).length > 0;
}

const syncz = (n: number) => Array.from({ length: n }, (_, i) => ({ proxy: `app-${i}.shop`, sync_status: "SYNCED" }));

describe("engine signal sources in multi-revision archives", () => {
  it("istiod signals read the istiod serving the most proxies, not the first one listed", async () => {
    const dir = await archive();
    await rm(join(dir, "istio", "istio-system", "istiod-abc"), { recursive: true });
    // Listed first, but an idle revision that serves nothing.
    await istiod(dir, "istiod-1-30-aaaaa", { syncz: [], mesh: { rootNamespace: "idle-root" } });
    await istiod(dir, "istiod-1-31-bbbbb", { syncz: syncz(3), mesh: { rootNamespace: "istio-system" } });
    const signal: Signal = { source: { type: "istiod", endpoint: "mesh", path: "rootNamespace" }, check: { op: "equals", value: "istio-system" } };
    expect(await fires(dir, signal)).toBe(true);
    expect(meshConfig(await BugReportStore.fromDirectory(dir))?.rootNamespace).toBe("istio-system");
  });

  it("log counts cover every matching file, not just the first", async () => {
    const dir = await archive();
    const second = join(dir, "proxies", "shop", "cart-7d9-xyz12");
    await mkdir(second, { recursive: true });
    await writeFile(join(second, "istio-proxy.log"), "2026-03-18T10:00:00.000Z\twarning\tenvoy config\tgRPC config rejected\n");
    await writeFile(join(dir, "proxies", "default", "test-pod-abc123", "istio-proxy.log"), "2026-03-18T10:00:00.000Z\twarning\tenvoy config\tgRPC config rejected\n");
    const signal: Signal = { source: { type: "logs", component: "proxy", pattern: "config rejected" }, check: { op: "count_gt", value: 1 } };
    expect(await fires(dir, signal)).toBe(true);
  });

  it("log pattern checks still receive the matching log text", async () => {
    const dir = await archive();
    const signal: Signal = { source: { type: "logs", component: "proxy", pattern: "Connection refused" }, check: { op: "matches", pattern: "10\\.0\\.0\\.5" } };
    expect(await fires(dir, signal)).toBe(true);
  });
});

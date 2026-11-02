import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getLogs } from "../../src/tools/logs.js";

describe("getLogs", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "logs-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    await mkdir(join(archiveDir, "cni", "istio-cni-node-abcde"), { recursive: true });
    await writeFile(
      join(archiveDir, "cni", "istio-cni-node-abcde", "cni.log"),
      "2026-10-20T20:00:00.000000Z\tinfo\tcni\tAdding pod to ambient\n2026-10-20T20:00:01.000000Z\terror\tcni\tfailed to add iptables rules\n",
    );
    await mkdir(join(archiveDir, "operator", "istio-operator-xyz"), { recursive: true });
    await writeFile(
      join(archiveDir, "operator", "istio-operator-xyz", "operator.log"),
      "2026-10-20T20:00:00.000000Z\tinfo\tReconciling IstioOperator\n",
    );
    await appendFile(
      join(archiveDir, "proxies", "default", "test-pod-abc123", "istio-proxy.log"),
      '2026-10-20T20:22:24.038239Z\tinfo\tFLAG: --proxyComponentLogLevel="misc:error"\n',
    );
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns proxy logs", async () => {
    const result = await getLogs(store, { component: "proxy" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Connection refused");
  });

  it("returns istiod logs", async () => {
    const result = await getLogs(store, { component: "istiod" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("XDS: Pushing");
  });

  it("filters by keyword", async () => {
    const result = await getLogs(store, { component: "proxy", keyword: "error" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("error");
    expect(text).not.toContain("Initializing");
  });

  it("returns cni logs", async () => {
    const result = await getLogs(store, { component: "cni" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("[cni/istio-cni-node-abcde]");
    expect(text).toContain("failed to add iptables rules");
  });

  it("filters cni logs by pod", async () => {
    const result = await getLogs(store, { component: "cni", pod: "istio-cni-node-other" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("No log lines found");
  });

  it("returns operator logs when the archive has them", async () => {
    const result = await getLogs(store, { component: "operator" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Reconciling IstioOperator");
  });

  it("includes cni and operator logs for component all", async () => {
    const result = await getLogs(store, { component: "all" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("failed to add iptables rules");
    expect(text).toContain("XDS: Pushing");
  });

  it("filters by log level rather than substring for severity", async () => {
    const result = await getLogs(store, { component: "proxy", severity: "error" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Connection refused");
    expect(text).not.toContain("proxyComponentLogLevel");
  });

  it("matches warning lines for severity warn", async () => {
    const result = await getLogs(store, { component: "proxy", severity: "warn" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Slow response from upstream");
    expect(text).not.toContain("Connection refused");
  });

  it("truncates output and reports metadata", async () => {
    const result = await getLogs(store, { component: "proxy", tail: 1 });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toBeTruthy();
  });
});

describe("getLogs on a line longer than the scanner's line cap", () => {
  let tempDir: string;

  afterAll(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it("reports the line's full length and that it was cut while reading", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "logs-long-line-"));
    const dir = join(tempDir, "bug-report", "proxies", "ns", "long-pod-0");
    await mkdir(dir, { recursive: true });
    const long = `2026-01-01T00:00:00Z\tinfo\tdump ${"d".repeat(3 * 1024 * 1024)}`;
    await writeFile(join(dir, "istio-proxy.log"), `${long}\n2026-01-01T00:00:01Z\tinfo\tafter\n`);
    const store = await BugReportStore.fromDirectory(join(tempDir, "bug-report"));
    const text = ((await getLogs(store, { component: "proxy" })).content[0] as { type: "text"; text: string }).text;
    const shownChars = 2_000;
    const full = "[proxy/ns/long-pod-0] ".length + long.length;
    expect(text).toContain(`… [${(full - shownChars).toLocaleString("en-US")} more chars]`);
    expect(text).toContain("[proxy/ns/long-pod-0] 2026-01-01T00:00:01Z\tinfo\tafter");
    expect(text).toContain("Note: 1 line(s) longer than 1 MB were matched on their first 1 MB only.");
  });
});

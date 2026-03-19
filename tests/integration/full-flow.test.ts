import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { getOverview } from "../../src/tools/overview.js";
import { getVersions } from "../../src/tools/versions.js";
import { getAnalyzeResults } from "../../src/tools/analyze-results.js";
import { getClusterResources } from "../../src/tools/cluster-resources.js";
import { getProxyConfig } from "../../src/tools/proxy-config.js";
import { getLogs } from "../../src/tools/logs.js";
import { getIstiodDebug } from "../../src/tools/istiod-debug.js";
import { findErrors } from "../../src/tools/find-errors.js";
import { listFiles, getRawFile } from "../../src/resources/archive-resource.js";
import type { DiagnosticTemplate } from "../../src/types.js";

describe("Full analysis flow", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "integration-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("overview returns structured data", () => {
    const result = getOverview(store);
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Istio Mesh Overview");
    expect(text).toContain("1.29.1");
    expect(text).toContain("Proxies: 1");
    expect(text).toContain("Istiod: 1");
  });

  it("versions detects no skew in fixture", () => {
    const result = getVersions(store);
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("1.29.1");
    expect(text).not.toContain("VERSION SKEW");
  });

  it("analyze results returns all IST codes", () => {
    const result = getAnalyzeResults(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("IST0101");
    expect(text).toContain("IST0107");
    expect(text).toContain("IST0118");
  });

  it("cluster resources shows parsed K8s objects", () => {
    const result = getClusterResources(store, { kind: "VirtualService" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("VirtualService");
    expect(text).toContain("test-vs");
  });

  it("proxy config returns config dump", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "test-pod-abc123" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("BootstrapConfigDump");
  });

  it("logs returns filtered content", () => {
    const result = getLogs(store, { component: "proxy", keyword: "error" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Connection refused");
  });

  it("istiod debug returns syncz", () => {
    const result = getIstiodDebug(store, { endpoint: "syncz" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("SYNCED");
  });

  it("find_errors locates error patterns", () => {
    const result = findErrors(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("unique");
  });

  it("list_files and get_raw_file work together", async () => {
    const listResult = listFiles(store);
    const text = (listResult.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("versions");

    const rawResult = await getRawFile(store, "versions");
    const rawText = (rawResult.content[0] as { type: "text"; text: string }).text;
    expect(rawText).toContain("1.29.1");
  });

  it("diagnostic engine fires matching templates", async () => {
    const engine = new DiagnosticEngine();
    // Add a template that should match the fixture (IST0101 exists)
    engine.addTemplate({
      id: "INT-001",
      name: "IST0101 Present",
      category: "config",
      severity: "critical",
      signals: [{ source: { type: "analyze", code: "IST0101" }, check: { op: "exists" } }],
      description: "IST0101 found",
      rootCause: "Config issue",
      impact: "Broken routing",
      remediation: [{ order: 1, description: "Fix config", effort: "low", risk: "low" }],
      references: [],
    });
    // Add DIAG-003 (single istiod) which should match since fixture has 1 istiod
    engine.addTemplate({
      id: "DIAG-003",
      name: "Single Istiod Replica (No HA)",
      category: "config",
      severity: "warning",
      signals: [{ source: { type: "istiod", endpoint: "syncz", path: "" }, check: { op: "exists" } }],
      description: "Only one istiod",
      rootCause: "replicas=1",
      impact: "SPOF",
      remediation: [],
      references: [],
    });
    // Add DIAG-004 (missing Sidecar) which should match since fixture has no Sidecar resources
    engine.addTemplate({
      id: "DIAG-004",
      name: "No Sidecar Resources",
      category: "config",
      severity: "warning",
      signals: [{ source: { type: "resource", kind: "Sidecar", field: "kind" }, check: { op: "not_exists" } }],
      description: "No Sidecar resources",
      rootCause: "Not configured",
      impact: "Over-scoped proxies",
      remediation: [],
      references: [],
    });

    const findings = await engine.run(store);
    expect(findings.length).toBe(3);
    expect(findings.map((f) => f.templateId)).toContain("INT-001");
    expect(findings.map((f) => f.templateId)).toContain("DIAG-003");
    expect(findings.map((f) => f.templateId)).toContain("DIAG-004");
  });
});

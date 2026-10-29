import { describe, it, expect, afterEach, vi } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { cleanupArchives, deployment, finding, runTemplates } from "./template-harness.js";

afterEach(cleanupArchives);

describe("DIAG-003 single istiod template", () => {
  it("fires for a single-replica istiod Deployment without HPA", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 1 });
    const f = finding(await runTemplates({ resources: [istiod] }, ["config"]), "DIAG-003");
    expect(f?.affectedResources).toEqual(["istio-system/istiod: 1 replica (no HPA; raise Helm replicaCount)"]);
  });

  const hpaFor = (name: string, min: number) => ({
    apiVersion: "autoscaling/v2",
    kind: "HorizontalPodAutoscaler",
    metadata: { name, namespace: "istio-system" },
    spec: { minReplicas: min, maxReplicas: 5, scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name } },
  });

  it("names the top-level Helm keys for istiod charts 1.24+", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 1 });
    const hpa = finding(await runTemplates({ resources: [istiod, hpaFor("istiod", 1)], versions: bugReportVersions("1.24.0") }, ["config"]), "DIAG-003");
    expect(hpa?.affectedResources).toEqual(["istio-system/istiod: HPA minReplicas 1 (raise HPA istio-system/istiod minReplicas to 2, Helm autoscaleMin)"]);
    const plain = finding(await runTemplates({ resources: [istiod], versions: bugReportVersions("1.24.0") }, ["config"]), "DIAG-003");
    expect(plain?.affectedResources).toEqual(["istio-system/istiod: 1 replica (no HPA; raise Helm replicaCount)"]);
  });

  it("names the pilot.* Helm keys for istiod charts up to 1.23", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 1 });
    const f = finding(await runTemplates({ resources: [istiod, hpaFor("istiod", 1)], versions: bugReportVersions("1.23.3") }, ["config"]), "DIAG-003");
    expect(f?.affectedResources).toEqual(["istio-system/istiod: HPA minReplicas 1 (raise HPA istio-system/istiod minReplicas to 2, Helm pilot.autoscaleMin)"]);
  });

  it("uses the Deployment's own revision to pick the Helm key", async () => {
    const old = deployment("istio-system", "istiod-1-23", { labels: { app: "istiod", "istio.io/rev": "1-23" }, replicas: 1 });
    const meshInfo = (rev: string, v: string) =>
      `&version.MeshInfo{version.ServerInfo{Component:"pilot", Revision:"${rev}", Info:version.BuildInfo{Version:"${v}"}}}`;
    const versions = [
      "CLI version:",
      'version.BuildInfo{Version:"1.24.1"}',
      "",
      "✅ The following Istio control plane revisions/versions were found in the cluster:",
      "Revision 1-23:",
      meshInfo("1-23", "1.23.3"),
      "Revision 1-24:",
      meshInfo("1-24", "1.24.1"),
      "",
    ].join("\n");
    const f = finding(await runTemplates({ resources: [old], versions }, ["config"]), "DIAG-003");
    expect(f?.affectedResources).toEqual(["istio-system/istiod-1-23: 1 replica (no HPA; raise Helm pilot.replicaCount)"]);
  });

  it("gives both Helm keys, labelled, when the control plane version is unknown", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 1 });
    const f = finding(await runTemplates({ resources: [istiod], versions: "no versions recorded\n" }, ["config"]), "DIAG-003");
    expect(f?.affectedResources).toEqual(["istio-system/istiod: 1 replica (no HPA; raise Helm replicaCount for istiod chart 1.24+, pilot.replicaCount up to 1.23)"]);
  });

  it("ignores a revision scaled to 0 (inactive after an upgrade)", async () => {
    const old = deployment("istio-system", "istiod-1-29", { labels: { app: "istiod", "istio.io/rev": "1-29" }, replicas: 0 });
    const cur = deployment("istio-system", "istiod-1-31", { labels: { app: "istiod", "istio.io/rev": "1-31" }, replicas: 2 });
    expect(finding(await runTemplates({ resources: [old, cur] }, ["config"]), "DIAG-003")).toBeUndefined();
  });

  it("remediates through the HPA and Helm values, not kubectl scale", async () => {
    const { readFile } = await import("node:fs/promises");
    const { load } = await import("js-yaml");
    const t = load(await readFile(join(import.meta.dirname, "..", "..", "templates", "DIAG-003-single-istiod.yaml"), "utf-8")) as {
      remediation: { description: string; command?: string; yaml?: string }[];
    };
    const text = JSON.stringify(t.remediation);
    expect(text).not.toMatch(/kubectl scale/);
    expect(text).toContain("minReplicas");
    expect(text).toContain("pilot.autoscaleMin");
    expect(text).toMatch(/[^.]autoscaleMin=2/);
    expect(text).toContain("1.24");
    expect(text).toContain("replicaCount");
    expect(text).toContain("PodDisruptionBudget");
  });

  it("does not fire when an HPA keeps at least 2 replicas", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 1 });
    const hpa = {
      apiVersion: "autoscaling/v2",
      kind: "HorizontalPodAutoscaler",
      metadata: { name: "istiod", namespace: "istio-system" },
      spec: { minReplicas: 2, maxReplicas: 5, scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name: "istiod" } },
    };
    expect(finding(await runTemplates({ resources: [istiod, hpa] }, ["config"]), "DIAG-003")).toBeUndefined();
  });

  it("fires when the HPA allows a single replica", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 3 });
    const hpa = {
      apiVersion: "autoscaling/v2",
      kind: "HorizontalPodAutoscaler",
      metadata: { name: "istiod", namespace: "istio-system" },
      spec: { minReplicas: 1, maxReplicas: 5, scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name: "istiod" } },
    };
    const f = finding(await runTemplates({ resources: [istiod, hpa] }, ["config"]), "DIAG-003");
    expect(f?.affectedResources).toEqual(["istio-system/istiod: HPA minReplicas 1 (raise HPA istio-system/istiod minReplicas to 2, Helm autoscaleMin)"]);
  });

  it("does not fire for a 3-replica istiod even without debug endpoints", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, replicas: 3 });
    expect(finding(await runTemplates({ resources: [istiod], meshDebug: null }, ["config"]), "DIAG-003")).toBeUndefined();
  });

  it("flags each single-replica revision separately", async () => {
    const r1 = deployment("istio-system", "istiod-1-30", { labels: { app: "istiod", "istio.io/rev": "1-30" }, replicas: 1 });
    const r2 = deployment("istio-system", "istiod-1-31", { labels: { app: "istiod", "istio.io/rev": "1-31" }, replicas: 2 });
    const f = finding(await runTemplates({ resources: [r1, r2] }, ["config"]), "DIAG-003");
    expect(f?.affectedResources).toEqual(["istio-system/istiod-1-30: 1 replica (no HPA; raise Helm replicaCount)"]);
  });

  it("falls back to collected istiod pods when no Deployment is in the dump", async () => {
    const one = finding(await runTemplates({ resources: [], istiodPods: ["istiod-6dc487f44f-sffgt"] }, ["config"]), "DIAG-003");
    expect(one?.affectedResources).toEqual(["istio-system/istiod: 1 pod collected"]);
    const two = await runTemplates({ resources: [], istiodPods: ["istiod-6dc487f44f-sffgt", "istiod-6dc487f44f-x9k2p"] }, ["config"]);
    expect(finding(two, "DIAG-003")).toBeUndefined();
  });
});

describe("engine issue sources", () => {
  it("computes each issue source once per run", async () => {
    const { DiagnosticEngine } = await import("../../src/diagnostics/engine.js");
    const { BugReportStore } = await import("../../src/archive/store.js");
    const { createMinimalArchive } = await import("../fixtures/create-fixture.js");
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "issue-once-"));
    try {
      await createMinimalArchive(join(dir, "bug-report"));
      const store = await BugReportStore.fromDirectory(join(dir, "bug-report"));
      const engine = new DiagnosticEngine();
      const tpl = (id: string) => ({
        id, name: id, category: "config" as const, severity: "info" as const,
        signals: [{ source: { type: "istiod_replicas" as const }, check: { op: "exists" as const } }],
        description: "", rootCause: "", impact: "", remediation: [], references: [],
      });
      engine.addTemplate(tpl("T1"));
      engine.addTemplate(tpl("T2"));
      const spy = vi.spyOn(store, "getIstiodPods");
      await engine.run(store);
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("engine template independence", () => {
  it("has no template IDs hardcoded in the engine", async () => {
    const source = await readFile(join(import.meta.dirname, "..", "..", "src", "diagnostics", "engine.ts"), "utf-8");
    expect(source).not.toMatch(/DIAG-\d{3}/);
  });
});

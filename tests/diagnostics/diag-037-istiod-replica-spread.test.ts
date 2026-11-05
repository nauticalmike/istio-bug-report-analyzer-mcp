import { describe, it, expect, afterEach } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { load } from "js-yaml";
import { cleanupArchives, deployment, finding, runEngine, runTemplates, type Obj } from "./template-harness.js";

// DIAG-037: multi-replica istiods whose replicas nothing spreads across nodes or zones. DIAG-003
// keeps its v0.5.0 output (single replica only); its PodDisruptionBudget advice is advisory.

afterEach(cleanupArchives);

const node = (name: string): Obj => ({ apiVersion: "v1", kind: "Node", metadata: { name, labels: { "kubernetes.io/os": "linux" } } });
const nodes = [node("node-a"), node("node-b"), node("node-c")];

function istiod(replicas: number, podSpec: Obj = {}, name = "istiod"): Obj {
  const d = deployment("istio-system", name, { labels: { app: "istiod" }, replicas, containers: [{ name: "discovery", image: "docker.io/istio/pilot:1.31.2" }] });
  Object.assign((d.spec as { template: { spec: Obj } }).template.spec, podSpec);
  return d;
}

function istiodReplicaPod(name: string, nodeName: string, podSpec: Obj = {}, owner?: string, labels: Obj = {}): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: "istio-system", labels: { app: "istiod", ...labels }, ...(owner ? { ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: owner }] } : {}) },
    spec: { nodeName, containers: [{ name: "discovery", image: "docker.io/istio/pilot:1.31.2" }], ...podSpec },
    status: { phase: "Running" },
  };
}

const CATEGORIES = ["config"];

describe("DIAG-037 istiod replica spread", () => {
  it("reports (info) a multi-replica istiod with no topologySpreadConstraints or podAntiAffinity, and DIAG-003 stays silent", async () => {
    const findings = await runTemplates({ resources: [...nodes, istiod(2)] }, CATEGORIES);
    expect(finding(findings, "DIAG-003")).toBeUndefined();
    const f = finding(findings, "DIAG-037");
    expect(f?.severity).toBe("info");
    expect(f?.issues).toEqual([
      expect.objectContaining({ severity: "info", detail: expect.stringMatching(/^istio-system\/istiod: 2 replicas with no topologySpreadConstraints or podAntiAffinity/) }),
    ]);
  });

  it("counts the HPA floor as the replica count", async () => {
    const hpa = {
      apiVersion: "autoscaling/v2",
      kind: "HorizontalPodAutoscaler",
      metadata: { name: "istiod", namespace: "istio-system" },
      spec: { minReplicas: 3, maxReplicas: 5, scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name: "istiod" } },
    };
    const f = finding(await runTemplates({ resources: [...nodes, istiod(1), hpa] }, CATEGORIES), "DIAG-037");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^istio-system\/istiod: 3 replicas \(HPA minimum\) with no topologySpreadConstraints/)]);
  });

  it("is a warning when every live replica already runs on one node", async () => {
    const pods = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-a")];
    const f = finding(await runTemplates({ resources: [...nodes, istiod(2), ...pods] }, CATEGORIES), "DIAG-037");
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toMatch(/all 2 running replicas are on node node-a/);
  });

  it("is silent when replicas are spread, on a single-node cluster, or for a single replica", async () => {
    const spread = { topologySpreadConstraints: [{ maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: { matchLabels: { app: "istiod" } } }] };
    expect(finding(await runTemplates({ resources: [...nodes, istiod(2, spread)] }, CATEGORIES), "DIAG-037")).toBeUndefined();
    const anti = { affinity: { podAntiAffinity: { preferredDuringSchedulingIgnoredDuringExecution: [{ weight: 100, podAffinityTerm: { topologyKey: "kubernetes.io/hostname" } }] } } };
    expect(finding(await runTemplates({ resources: [...nodes, istiod(2, anti)] }, CATEGORIES), "DIAG-037")).toBeUndefined();
    // The archive fixture lists node-1 in cluster/nodes: one node in all.
    expect(finding(await runTemplates({ resources: [node("node-1"), istiod(2)] }, CATEGORIES), "DIAG-037")).toBeUndefined();
    // A single replica is DIAG-003's (unchanged v0.5.0 text), not a spread issue.
    const single = await runTemplates({ resources: [...nodes, istiod(1)] }, CATEGORIES);
    expect(finding(single, "DIAG-037")).toBeUndefined();
    expect(finding(single, "DIAG-003")?.affectedResources).toEqual(["istio-system/istiod: 1 replica (no HPA; raise Helm replicaCount)"]);
    expect(finding(single, "DIAG-003")?.severity).toBe("warning");
  });

  it("keeps DIAG-003 to the single-replica revision when an unspread one sits next to it", async () => {
    const findings = await runTemplates({ resources: [...nodes, istiod(1, {}, "istiod-1-30"), istiod(2, {}, "istiod-1-31")] }, CATEGORIES);
    expect(finding(findings, "DIAG-003")?.affectedResources).toEqual(["istio-system/istiod-1-30: 1 replica (no HPA; raise Helm replicaCount)"]);
    expect(finding(findings, "DIAG-037")?.affectedResources).toEqual([expect.stringMatching(/^istio-system\/istiod-1-31: 2 replicas/)]);
  });

  it("is not evaluated without an istiod Deployment in the dump", async () => {
    const { engine } = await runEngine({ resources: [...nodes] }, CATEGORIES);
    expect(engine.getNotEvaluated().find((n) => n.templateId === "DIAG-037")?.reason).toMatch(/no istiod Deployment/);
  });

  it("DIAG-003 keeps its v0.5.0 description and states that the PodDisruptionBudget advice cannot be checked", async () => {
    const t = load(await readFile(join(import.meta.dirname, "..", "..", "templates", "DIAG-003-single-istiod.yaml"), "utf-8")) as { description: string; remediation: { description: string }[] };
    expect(t.description.trim()).toBe("Only one istiod replica is running. This is a single point of failure for the entire mesh control plane.");
    const pdb = t.remediation.find((r) => r.description.includes("PodDisruptionBudget"))!;
    expect(pdb.description).toMatch(/not collected|not in the bug report/);
  });
});

describe("DIAG-037 istiod replica spread", () => {
  const zonedNode = (name: string, zone: string): Obj => ({ apiVersion: "v1", kind: "Node", metadata: { name, labels: { "kubernetes.io/os": "linux", "topology.kubernetes.io/zone": zone } } });

  it("falls back to the istiod pods' nodeName when no Deployment is in the dump", async () => {
    const pods = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-a")];
    const f = finding(await runTemplates({ resources: [...nodes, ...pods] }, CATEGORIES), "DIAG-037");
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^istio-system\/istiod: 2 replicas with no topologySpreadConstraints or podAntiAffinity, and all 2 running replicas are on node node-a: one node drain/)]);
    const apart = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-b")];
    const { findings, engine } = await runEngine({ resources: [...nodes, ...apart] }, CATEGORIES);
    const g = finding(findings, "DIAG-037");
    expect(g?.severity).toBe("info");
    expect(g?.affectedResources).toEqual([expect.stringMatching(/^istio-system\/istiod: 2 replicas with no topologySpreadConstraints or podAntiAffinity: the scheduler may place them .*running now on 2 nodes \(node-a, node-b\)/)]);
    expect(engine.getNotEvaluated().map((n) => n.templateId)).not.toContain("DIAG-037");
  });

  describe("pods only (no istiod Deployment in the dump): the live pods' own spec", () => {
    const spread = { topologySpreadConstraints: [{ maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: { matchLabels: { app: "istiod" } } }] };
    const anti = { affinity: { podAntiAffinity: { preferredDuringSchedulingIgnoredDuringExecution: [{ weight: 100, podAffinityTerm: { topologyKey: "kubernetes.io/hostname" } }] } } };

    it("is silent when the pods carry topologySpreadConstraints or podAntiAffinity and run apart", async () => {
      for (const podSpec of [spread, anti]) {
        const pods = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a", podSpec, "istiod-6d8f9c7b5"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-b", podSpec, "istiod-6d8f9c7b5")];
        expect(finding(await runTemplates({ resources: [...nodes, ...pods] }, CATEGORIES), "DIAG-037")).toBeUndefined();
      }
    });

    it("shows the zone placement of unspread replicas", async () => {
      const zonedNode = (name: string, zone: string): Obj => ({ apiVersion: "v1", kind: "Node", metadata: { name, labels: { "kubernetes.io/os": "linux", "topology.kubernetes.io/zone": zone } } });
      const pods = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a", {}, "istiod-6d8f9c7b5"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-b", {}, "istiod-6d8f9c7b5")];
      const f = finding(await runTemplates({ resources: [zonedNode("node-a", "zone-1"), zonedNode("node-b", "zone-1"), ...pods] }, CATEGORIES), "DIAG-037");
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources[0]).toMatch(/running now on 2 nodes \(node-a, node-b\), all in zone zone-1/);
    });

    it("groups replicas by owner, so each revision is judged on its own", async () => {
      const pods = [
        istiodReplicaPod("istiod-1-30-5c7d9f8b6-aaaaa", "node-a", {}, "istiod-1-30-5c7d9f8b6", { "istio.io/rev": "1-30" }),
        istiodReplicaPod("istiod-1-31-6d8f9c7b5-bbbbb", "node-a", {}, "istiod-1-31-6d8f9c7b5", { "istio.io/rev": "1-31" }),
        istiodReplicaPod("istiod-1-31-6d8f9c7b5-ccccc", "node-b", {}, "istiod-1-31-6d8f9c7b5", { "istio.io/rev": "1-31" }),
      ];
      const f = finding(await runTemplates({ resources: [...nodes, ...pods] }, CATEGORIES), "DIAG-037");
      expect(f?.affectedResources).toEqual([expect.stringMatching(/^istio-system\/istiod-1-31: 2 replicas with no topologySpreadConstraints or podAntiAffinity/)]);
    });

    it("keeps replicas that share one node a warning even when the pods carry a spread constraint", async () => {
      const pods = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a", spread, "istiod-6d8f9c7b5"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-a", spread, "istiod-6d8f9c7b5")];
      const f = finding(await runTemplates({ resources: [...nodes, ...pods] }, CATEGORIES), "DIAG-037");
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources[0]).toMatch(/all 2 running replicas are on node node-a/);
    });
  });

  it("shows the current node and zone placement", async () => {
    const pods = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-b")];
    const f = finding(await runTemplates({ resources: [zonedNode("node-a", "zone-1"), zonedNode("node-b", "zone-1"), istiod(2), ...pods] }, CATEGORIES), "DIAG-037");
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/running now on 2 nodes \(node-a, node-b\), all in zone zone-1/);
  });

  it("is not evaluated when the dump has no Node objects", async () => {
    const { findings, engine } = await runEngine({ resources: [istiod(2)], files: { "cluster/nodes": null } }, CATEGORIES);
    expect(finding(findings, "DIAG-037")).toBeUndefined();
    expect(engine.getNotEvaluated().find((n) => n.templateId === "DIAG-037")?.reason).toMatch(/no Node objects/);
  });

  it("without Node objects, is silent (not 'not evaluated') when no istiod runs two or more unspread replicas", async () => {
    for (const resources of [[istiod(1)], [istiod(2, { topologySpreadConstraints: [{ maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: { matchLabels: { app: "istiod" } } }] })], [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a")]]) {
      const { findings, engine } = await runEngine({ resources, files: { "cluster/nodes": null } }, CATEGORIES);
      expect(finding(findings, "DIAG-037")).toBeUndefined();
      expect(engine.getNotEvaluated().map((n) => n.templateId)).not.toContain("DIAG-037");
    }
    // pods only: their nodeName already shows two nodes to spread to, so Nodes are not needed.
    const apart = [istiodReplicaPod("istiod-6d8f9c7b5-aaaaa", "node-a"), istiodReplicaPod("istiod-6d8f9c7b5-bbbbb", "node-b")];
    const { findings, engine } = await runEngine({ resources: apart, files: { "cluster/nodes": null } }, CATEGORIES);
    expect(finding(findings, "DIAG-037")?.severity).toBe("info");
    expect(engine.getNotEvaluated().map((n) => n.templateId)).not.toContain("DIAG-037");
    // a 2-replica Deployment without spread constraints needs the node count.
    const multi = await runEngine({ resources: [istiod(2), istiod(1, {}, "istiod-canary")], files: { "cluster/nodes": null } }, CATEGORIES);
    expect(multi.engine.getNotEvaluated().find((n) => n.templateId === "DIAG-037")?.reason).toMatch(/no Node objects/);
  });
});

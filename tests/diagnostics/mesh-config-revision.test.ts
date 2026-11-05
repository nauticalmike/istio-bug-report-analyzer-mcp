import { describe, it, expect, afterEach } from "vitest";
import { istiodsByLoad, meshConfig, podLiveness } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives, deployment, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

// A second istiod dir whose pod is not in the pod dump (cluster/pods lists istiod-abc only):
// a replaced pod, or another cluster's istiod in a merged archive.
const STALE = "istio/istio-system/istiod-old-7f9c8d6b5-zz9xk";

function staleIstiod(mesh: Obj | null, proxies = 5): Record<string, string> {
  const syncz = Array.from({ length: proxies }, (_, i) => ({ proxy: `cart-${i}.shop`, cluster_id: "Kubernetes" }));
  return {
    [`${STALE}/discovery.log`]: "info\tready\n",
    [`${STALE}/debug/syncz`]: JSON.stringify(syncz),
    ...(mesh ? { [`${STALE}/debug/mesh`]: JSON.stringify(mesh) } : {}),
  };
}

function meshConfigMap(name: string, trustDomain: string): Obj {
  return { apiVersion: "v1", kind: "ConfigMap", metadata: { name, namespace: "istio-system" }, data: { mesh: `trustDomain: ${trustDomain}\n` } };
}

function istiodDeployment(rev: string | null, replicas: number): Obj {
  const labels: Obj = { app: "istiod", ...(rev ? { "istio.io/rev": rev } : {}) };
  return deployment("istio-system", rev ? `istiod-${rev}` : "istiod", { labels, replicas });
}

function istiodPodObj(name: string, rev: string | null): Obj {
  return { apiVersion: "v1", kind: "Pod", metadata: { name, namespace: "istio-system", labels: { app: "istiod", ...(rev ? { "istio.io/rev": rev } : {}) } }, spec: { containers: [{ name: "discovery" }] }, status: { phase: "Running" } };
}

describe("podLiveness", () => {
  it("is live for a pod in the dump, stale for a missing pod in a covered namespace, unknown elsewhere", async () => {
    const store = await buildStore({ files: staleIstiod(null) });
    expect(podLiveness(store, "istio-system", "istiod-abc")).toBe("live");
    expect(podLiveness(store, "istio-system", "istiod-old-7f9c8d6b5-zz9xk")).toBe("stale");
    // cluster/pods alone holds only the Istio namespaces; shop is not covered.
    expect(podLiveness(store, "shop", "cart-1")).toBe("unknown");
  });

  it("counts Failed and Succeeded pods still in the dump as live (their logs are of this cluster); only missing pods are stale", async () => {
    const pods = [
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\nspec:\n  containers:\n    - name: discovery\nstatus:\n  phase: Running\n",
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-evicted-1\n  namespace: istio-system\nspec:\n  containers:\n    - name: discovery\nstatus:\n  phase: Failed\n",
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istio-cni-node-k7x2p\n  namespace: istio-system\nspec:\n  containers:\n    - name: install-cni\n      image: docker.io/istio/install-cni:1.31.2\nstatus:\n  phase: Succeeded\n",
    ].join("---\n");
    const store = await buildStore({ files: { "cluster/pods": pods } });
    expect(podLiveness(store, "istio-system", "istiod-evicted-1")).toBe("live");
    expect(podLiveness(store, null, "istio-cni-node-k7x2p")).toBe("live");
    expect(podLiveness(store, null, "istio-cni-node-q9w4z")).toBe("stale");
    expect(podLiveness(store, "istio-system", "istiod-gone")).toBe("stale");
  });

  it("is unknown without a pod dump", async () => {
    const store = await buildStore({ noPodDump: true, files: staleIstiod(null) });
    expect(podLiveness(store, "istio-system", "istiod-old-7f9c8d6b5-zz9xk")).toBe("unknown");
  });
});

describe("meshConfig revision choice", () => {
  it("prefers a running istiod's debug/mesh over a busier istiod no longer in the pod dump", async () => {
    const store = await buildStore({ meshDebug: { trustDomain: "cluster.local" }, files: staleIstiod({ trustDomain: "other.example.com" }) });
    expect(istiodsByLoad(store).map((p) => p.podName)).toEqual(["istiod-abc", "istiod-old-7f9c8d6b5-zz9xk"]);
    expect(meshConfig(store)?.trustDomain).toBe("cluster.local");
  });

  it("uses the ConfigMap rather than a stale istiod's debug/mesh", async () => {
    const store = await buildStore({ meshDebug: null, resources: [meshConfigMap("istio", "cluster.local")], files: staleIstiod({ trustDomain: "other.example.com" }) });
    expect(meshConfig(store)?.trustDomain).toBe("cluster.local");
  });

  it("falls back to a stale istiod's debug/mesh when nothing else exists", async () => {
    const store = await buildStore({ meshDebug: null, files: staleIstiod({ trustDomain: "other.example.com" }) });
    expect(meshConfig(store)?.trustDomain).toBe("other.example.com");
  });

  it("orders by load as before when every istiod is live (or cannot be checked)", async () => {
    const store = await buildStore({ noPodDump: true, meshDebug: { trustDomain: "cluster.local" }, files: staleIstiod({ trustDomain: "busy.example.com" }) });
    expect(meshConfig(store)?.trustDomain).toBe("busy.example.com");
  });

  it("never picks the ConfigMap of a revision scaled to 0 over the running revision", async () => {
    const resources = [
      meshConfigMap("istio", "old.example.com"),
      meshConfigMap("istio-canary", "cluster.local"),
      istiodDeployment(null, 0),
      istiodDeployment("canary", 2),
    ];
    const store = await buildStore({ meshDebug: null, resources });
    expect(meshConfig(store)?.trustDomain).toBe("cluster.local");
  });

  it("picks the revision with the most running istiod pods", async () => {
    const resources = [
      meshConfigMap("istio", "old.example.com"),
      meshConfigMap("istio-canary", "cluster.local"),
      istiodDeployment(null, 1),
      istiodDeployment("canary", 1),
      istiodPodObj("istiod-canary-6b7c8d9f5-abcde", "canary"),
      istiodPodObj("istiod-canary-6b7c8d9f5-fghjk", "canary"),
    ];
    const store = await buildStore({ meshDebug: null, resources });
    expect(meshConfig(store)?.trustDomain).toBe("cluster.local");
  });

  it("keeps the `istio` ConfigMap first when the revisions tie, and a lone ConfigMap even when scaled to 0", async () => {
    const tie = await buildStore({ meshDebug: null, resources: [meshConfigMap("istio-canary", "canary.example.com"), meshConfigMap("istio", "cluster.local")] });
    expect(meshConfig(tie)?.trustDomain).toBe("cluster.local");
    const lone = await buildStore({ meshDebug: null, resources: [meshConfigMap("istio", "cluster.local"), istiodDeployment(null, 0)] });
    expect(meshConfig(lone)?.trustDomain).toBe("cluster.local");
  });
});

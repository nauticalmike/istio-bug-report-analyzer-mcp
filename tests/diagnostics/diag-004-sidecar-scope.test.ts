import { describe, it, expect, afterEach } from "vitest";
import { dump } from "js-yaml";
import { cleanupArchives, finding, pod, runEngine, sidecarPod, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

function sidecars(namespace: string, n: number, labels: Obj = {}): Obj[] {
  return Array.from({ length: n }, (_, i) => sidecarPod(namespace, `app-${i}`, "1.31.2", { app: `app-${i}`, ...labels }));
}

function sidecarResource(namespace: string, name: string, workloadSelector?: Obj): Obj {
  return {
    apiVersion: "networking.istio.io/v1",
    kind: "Sidecar",
    metadata: { name, namespace },
    spec: { ...(workloadSelector ? { workloadSelector: { labels: workloadSelector } } : {}), egress: [{ hosts: ["./*", "istio-system/*"] }] },
  };
}

function namespace(name: string, labels: Obj = {}): Obj {
  return { apiVersion: "v1", kind: "Namespace", metadata: { name, labels } };
}

/** cluster/crs as istioctl writes it: a List of the Istio custom resources. */
function crs(...items: Obj[]): Record<string, string> {
  return { "cluster/crs": dump({ apiVersion: "v1", kind: "List", items }) };
}

const virtualService = { apiVersion: "networking.istio.io/v1", kind: "VirtualService", metadata: { name: "vs", namespace: "shop" }, spec: { hosts: ["shop"] } };

async function run(resources: Obj[], files: Record<string, string | null>) {
  const { findings, engine } = await runEngine({ resources, files, mode: "sidecar" }, ["config"]);
  return { f: finding(findings, "DIAG-004"), skipped: engine.getNotEvaluated().find((s) => s.templateId === "DIAG-004") };
}

describe("DIAG-004 Sidecar scoping coverage", () => {
  it("is not evaluated when cluster/crs is missing (instead of reporting no Sidecar)", async () => {
    const { f, skipped } = await run(sidecars("shop", 30), { "cluster/crs": null });
    expect(f).toBeUndefined();
    // The reason points at the crs completeness signal, as for every check on a missing section.
    expect(skipped?.reason).toBe("not evaluated: cluster/crs missing (data completeness: crs)");
  });

  it("is not evaluated when cluster/crs is empty", async () => {
    const { f, skipped } = await run(sidecars("shop", 30), crs());
    expect(f).toBeUndefined();
    expect(skipped?.reason).toContain("not evaluated: cluster/crs is empty");
  });

  it("skips meshes below the size threshold", async () => {
    const { f, skipped } = await run(sidecars("shop", 12), crs(virtualService));
    expect(f).toBeUndefined();
    // The base fixture contributes its own sidecar pod, so the count is 12 plus that one.
    expect(skipped?.reason).toBe("skipped: 13 sidecar proxies, below the 20 where Sidecar scoping pays off");
  });

  it("does not count ztunnel pods or unrendered (image: auto) proxies as sidecars", async () => {
    const ztunnels = Array.from({ length: 25 }, (_, i) =>
      pod("istio-system", `ztunnel-${i}`, { app: "ztunnel" }, [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.31.2", args: ["proxy", "ztunnel"] }]),
    );
    const auto = Array.from({ length: 10 }, (_, i) => pod("edge", `gw-${i}`, { app: "gw" }, [{ name: "istio-proxy", image: "auto" }]));
    const { f, skipped } = await run([...ztunnels, ...auto, ...sidecars("shop", 5)], crs(virtualService));
    expect(f).toBeUndefined();
    expect(skipped?.reason).toBe("skipped: 6 sidecar proxies, below the 20 where Sidecar scoping pays off");
  });

  it("counts proxy dirs in namespaces a partial pod dump (cluster/pods only) does not cover", async () => {
    const dirs = Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`proxies/shop/app-${i}-7d9f8b6c4d-x2k9p/istio-proxy.log`, "started\n"]));
    const { f, skipped } = await run([], { ...dirs, ...crs(virtualService), "cluster/k8s-resources": null });
    expect(skipped).toBeUndefined();
    expect(f?.affectedResources).toContain("namespace shop: 25 sidecars, no Sidecar resource selects them");
  });

  it("does not add proxy-dir counts on top of a namespace's parsed pods the pod inventory does not list", async () => {
    // Pods parsed from a dump the inventory does not scan (or gave up on) still are the namespace's sidecars.
    const pods = sidecars("shop", 25).map((p, i) => ({ ...p, metadata: { ...(p.metadata as Obj), name: `app-${i}-7d9f8b6c4d-x2k9p` } }));
    const dirs = Object.fromEntries(pods.map((p) => [`proxies/shop/${(p.metadata as Obj).name}/istio-proxy.log`, "started\n"]));
    const { f } = await run([], { ...dirs, ...crs(virtualService), "cluster/k8s-cluster-resources": dump({ apiVersion: "v1", kind: "List", items: pods }) });
    expect(f?.affectedResources).toContain("namespace shop: 25 sidecars, no Sidecar resource selects them");
  });

  it("reports each sidecar namespace without a Sidecar resource", async () => {
    const resources = [...sidecars("shop", 15), ...sidecars("cart", 25)];
    const { f } = await run(resources, crs(virtualService, sidecarResource("shop", "default")));
    expect(f?.affectedResources).toContain("namespace cart: 25 sidecars, no Sidecar resource selects them");
    expect(f?.affectedResources.some((a) => a.startsWith("namespace shop"))).toBe(false);
  });

  it("counts sidecars a workload-scoped Sidecar does not select", async () => {
    const front = Array.from({ length: 18 }, (_, i) => sidecarPod("web", `front-${i}`, "1.31.2", { app: "front", tier: "front" }));
    const api = Array.from({ length: 4 }, (_, i) => sidecarPod("web", `api-${i}`, "1.31.2", { app: "api" }));
    const { f } = await run([...front, ...api], crs(virtualService, sidecarResource("web", "front", { tier: "front" })));
    expect(f?.affectedResources).toContain("namespace web: 4 of 22 sidecars not selected by any Sidecar resource");
  });

  it("does not fire when a mesh-wide default Sidecar exists in the root namespace", async () => {
    const { f, skipped } = await run(sidecars("cart", 25), crs(virtualService, sidecarResource("istio-system", "default")));
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("skips ambient namespaces, where a Sidecar resource has no effect", async () => {
    const resources = [namespace("pay", { "istio.io/dataplane-mode": "ambient" }), ...sidecars("pay", 25), ...sidecars("shop", 5)];
    const { f } = await run(resources, crs(virtualService, sidecarResource("shop", "default")));
    expect(f).toBeUndefined();
  });

  it("names the egress-gateway and waypoint namespaces the remediation must keep reachable", async () => {
    const resources = [
      ...sidecars("cart", 25),
      pod("istio-egress", "istio-egressgateway-5c-abcde", { istio: "egressgateway" }, [{ name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "router"] }]),
      pod("payments", "waypoint-7d-fghij", { "gateway.istio.io/managed": "istio.io-mesh-controller", "gateway.networking.k8s.io/gateway-name": "waypoint" }, [{ name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "waypoint"] }]),
    ];
    const { f } = await run(resources, crs(virtualService));
    expect(f?.affectedResources).toContain(
      "remediation: besides ./* and istio-system/*, keep these namespaces in egress.hosts: istio-egress/* (egress gateway), payments/* (waypoint)",
    );
    // Gateways and waypoints are not sidecars, so they are not counted.
    expect(f?.affectedResources).toContain("namespace cart: 25 sidecars, no Sidecar resource selects them");
    expect(f?.affectedResources.some((a) => a.startsWith("namespace istio-egress") || a.startsWith("namespace payments"))).toBe(false);
  });
});

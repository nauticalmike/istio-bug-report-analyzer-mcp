import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, service, sidecarPod, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

function dr(ns: string, name: string, host: string, trafficPolicy: Obj, extra: Obj = {}): Obj {
  return { apiVersion: "networking.istio.io/v1", kind: "DestinationRule", metadata: { name, namespace: ns }, spec: { host, trafficPolicy, ...extra } };
}

function node(name: string, zone?: string): Obj {
  return { apiVersion: "v1", kind: "Node", metadata: { name, labels: zone ? { "topology.kubernetes.io/zone": zone, "topology.kubernetes.io/region": "region-1" } : {} } };
}

const OUTLIER = { outlierDetection: { consecutive5xxErrors: 5, interval: "10s", baseEjectionTime: "30s" } };
const failover = { loadBalancer: { localityLbSetting: { enabled: true, failover: [{ from: "region-1", to: "region-2" }] } } };
const shop: Obj[] = [
  namespace("shop", { "istio-injection": "enabled" }),
  sidecarPod("shop", "cart-0", "1.31.2", { app: "cart" }),
  ...["cart", "web", "pay", "api"].map((name) => service("shop", name, { app: name })),
];

async function run(resources: Obj[], meshDebug: Obj = {}, files?: Record<string, string | null>) {
  const { findings, engine } = await runEngine({ resources: [...shop, ...resources], meshDebug, files }, ["connectivity"]);
  return { f: finding(findings, "DIAG-036"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-036") };
}

describe("DIAG-036 locality load balancing inert", () => {
  it("is silent when failover has outlierDetection and the cluster has one zone", async () => {
    const { f, skipped } = await run([dr("shop", "cart", "cart", { ...failover, ...OUTLIER }), dr("shop", "plain", "web", {})]);
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("flags DestinationRule failover or failoverPriority without outlierDetection", async () => {
    const { f } = await run([
      dr("shop", "cart", "cart", failover),
      dr("shop", "prio", "web.shop.svc.cluster.local", { loadBalancer: { localityLbSetting: { failoverPriority: ["topology.kubernetes.io/zone"] } } }),
      dr("shop", "port", "pay", { ...OUTLIER, portLevelSettings: [{ port: { number: 8080 }, loadBalancer: failover.loadBalancer }] }),
      dr("shop", "off", "api", { loadBalancer: { localityLbSetting: { enabled: false, failover: [{ from: "a", to: "b" }] } } }),
    ]);
    expect(f?.severity).toBe("warning");
    expect(f?.issues).toEqual([
      { detail: "DestinationRule shop/cart (host cart): localityLbSetting.failover without outlierDetection: Envoy never fails over, so the setting does nothing", severity: "warning", namespace: "shop" },
      { detail: "DestinationRule shop/prio (host web.shop.svc.cluster.local): localityLbSetting.failoverPriority without outlierDetection: Envoy never fails over, so the setting does nothing", severity: "warning", namespace: "shop" },
    ]);
  });

  it("flags distribute weights that do not sum to 100", async () => {
    const distribute = { loadBalancer: { localityLbSetting: { distribute: [{ from: "region-1/*", to: { "region-1/*": 70, "region-2/*": 20 } }] } } };
    const { f } = await run([dr("shop", "split", "cart", distribute)]);
    expect(f?.affectedResources).toEqual(['DestinationRule shop/split (host cart): localityLbSetting.distribute from "region-1/*" weights sum to 90, not 100 (istiod rejects or ignores it)']);
  });

  it("flags a mesh-wide failover setting with the DestinationRules that lack outlierDetection", async () => {
    const { f } = await run([dr("shop", "a", "cart", {}), dr("shop", "b", "web", OUTLIER)], { localityLbSetting: { enabled: true, failover: [{ from: "region-1", to: "region-2" }] } });
    expect(f?.affectedResources).toEqual([
      "meshConfig.localityLbSetting.failover applies only to hosts with outlierDetection: 1 of 2 DestinationRules has none (shop/a) and hosts without a DestinationRule get none either",
    ]);
  });

  it("reports default locality routing switched off by missing outlierDetection in a multi-zone cluster, and unlabeled nodes", async () => {
    const nodes = [node("n1", "zone-a"), node("n2", "zone-b"), node("n3")];
    const { f } = await run([dr("shop", "a", "cart", {}), dr("shop", "b", "web", OUTLIER), ...nodes], {}, { "cluster/nodes": null });
    expect(f?.issues).toEqual([
      {
        detail: "nodes span 2 zones (zone-a, zone-b) and locality load balancing is on (mesh default), but it only takes effect with outlierDetection: 1 of 2 DestinationRules has none (shop/a), so their traffic, and traffic to hosts without a DestinationRule, spreads across zones",
        severity: "info",
      },
      { detail: "1 of 3 nodes has no topology.kubernetes.io/zone label, so its endpoints get no zone for locality load balancing: n3", severity: "warning" },
    ]);
  });

  it("does not report the multi-zone note when the mesh disables locality load balancing", async () => {
    const nodes = [node("n1", "zone-a"), node("n2", "zone-b")];
    const { f } = await run([dr("shop", "a", "cart", {}), ...nodes], { localityLbSetting: { enabled: false } }, { "cluster/nodes": null });
    expect(f).toBeUndefined();
  });

  it("leaves ambient hosts without a waypoint to DIAG-013", async () => {
    const ambient: Obj[] = [
      namespace("amb", { "istio.io/dataplane-mode": "ambient" }),
      { apiVersion: "v1", kind: "Pod", metadata: { name: "x-0", namespace: "amb", labels: { app: "x" }, annotations: { "ambient.istio.io/redirection": "enabled" } }, spec: { containers: [{ name: "app" }] }, status: { phase: "Running" } },
      service("amb", "x", { app: "x" }),
    ];
    const { f } = await run([...ambient, dr("amb", "x", "x", failover)]);
    expect(f).toBeUndefined();
  });

  it("is not evaluated without cluster/crs", async () => {
    const { findings, engine } = await runEngine({ files: { "cluster/crs": null } }, ["connectivity"]);
    expect(finding(findings, "DIAG-036")).toBeUndefined();
    expect(engine.getNotEvaluated().find((n) => n.templateId === "DIAG-036")?.reason).toMatch(/not evaluated: cluster\/crs/);
  });
});

describe("DIAG-036 scope", () => {
  it("skips DestinationRules whose host is no Service or ServiceEntry", async () => {
    const { f } = await run([dr("shop", "gone", "retired", failover), dr("shop", "cart", "cart", failover)]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^DestinationRule shop\/cart \(host cart\)/)]);
  });

  it("counts subset-level outlierDetection and checks subset-level failover", async () => {
    const { f } = await run([
      dr("shop", "cart", "cart", failover, { subsets: [{ name: "v1", labels: { v: "1" }, trafficPolicy: OUTLIER }] }),
      dr("shop", "web", "web", OUTLIER, { subsets: [{ name: "v1", labels: { v: "1" }, trafficPolicy: { ...failover, outlierDetection: undefined } }] }),
      dr("shop", "pay", "pay", {}, { subsets: [{ name: "v1", labels: { v: "1" }, trafficPolicy: failover }] }),
    ]);
    // cart: the top level still has no outlierDetection; web inherits it; pay's subset has none.
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^DestinationRule shop\/cart /), expect.stringMatching(/^DestinationRule shop\/pay /)]);
  });

  it("is silent on DestinationRules when no Envoy proxy runs", async () => {
    const resources = [namespace("amb", { "istio.io/dataplane-mode": "ambient" }), ambientPod("amb", "x-0", { app: "x" }), service("amb", "x", { app: "x" }), dr("amb", "x", "x.amb.svc.cluster.local", failover)];
    const { findings } = await runEngine({ resources, noPodDump: true }, ["connectivity"]);
    expect(finding(findings, "DIAG-036")).toBeUndefined();
  });

  it('notes zone "0" as a locality of its own, and reports a missing zone label only when it is absent', async () => {
    const legacy: Obj = { apiVersion: "v1", kind: "Node", metadata: { name: "n4", labels: { "failure-domain.beta.kubernetes.io/zone": "zone-a" } } };
    const { f } = await run([node("n1", "zone-a"), node("n2", "0"), node("n3"), legacy], {}, { "cluster/nodes": null });
    expect(f?.issues).toEqual([
      { detail: "1 of 4 nodes has no topology.kubernetes.io/zone label, so its endpoints get no zone for locality load balancing: n3", severity: "warning" },
      {
        detail: '1 of 4 nodes has zone "0" (non-zonal pool), which istiod treats as a locality of its own ("<region>/0/"), so locality load balancing ranks its endpoints as another zone: n2',
        severity: "info",
      },
    ]);
  });

  it('counts zone "0" as a locality when deciding that nodes span several zones', async () => {
    const { f } = await run([dr("shop", "a", "cart", {}), node("n1", "zone-a"), node("n2", "0")], {}, { "cluster/nodes": null });
    expect(f?.issues?.[0]).toEqual({
      detail: "nodes span 2 zones (0, zone-a) and locality load balancing is on (mesh default), but it only takes effect with outlierDetection: 1 of 1 DestinationRule has none (shop/a), so their traffic, and traffic to hosts without a DestinationRule, spreads across zones",
      severity: "info",
    });
    // nodes all in zone "0" are one locality: nothing to report.
    const single = await run([dr("shop", "a", "cart", {}), node("n1", "0"), node("n2", "0")], {}, { "cluster/nodes": null });
    expect(single.f).toBeUndefined();
  });

  it('resolves a "*" host in the DestinationRule\'s namespace when skipping ambient hosts without a waypoint', async () => {
    const ambient: Obj[] = [
      namespace("amb", { "istio.io/dataplane-mode": "ambient" }),
      { apiVersion: "v1", kind: "Pod", metadata: { name: "x-0", namespace: "amb", labels: { app: "x" }, annotations: { "ambient.istio.io/redirection": "enabled" } }, spec: { containers: [{ name: "app" }] }, status: { phase: "Running" } },
      service("amb", "x", { app: "x" }),
    ];
    const { f } = await run([...ambient, dr("amb", "all", "*", failover), dr("shop", "all", "*", failover)]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^DestinationRule shop\/all \(host \*\): localityLbSetting\.failover without outlierDetection/)]);
  });

  it("merges generated DestinationRules into one line per rule, pointing at the generator", async () => {
    const gen = (name: string, host: string): Obj => ({ ...dr("shop", name, host, failover), metadata: { name, namespace: "shop", ownerReferences: [{ apiVersion: "example.com/v1", kind: "RouteTable", name: "shop", uid: "1" }] } });
    const { f } = await run([gen("gen-cart", "cart"), gen("gen-web", "web"), dr("shop", "hand", "pay", failover)]);
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^DestinationRule shop\/hand \(host pay\): localityLbSetting\.failover/), severity: "warning", namespace: "shop" },
      {
        detail: "2 generated DestinationRules (owner references or generator labels): localityLbSetting.failover without outlierDetection: Envoy never fails over, so the setting does nothing: shop/gen-cart, shop/gen-web; change the generator's source configuration",
        severity: "warning",
        namespace: "shop",
      },
    ]);
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, service, sidecarPod, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, destinationRule, httpRoute, istiodDeployment, serviceEntry, virtualService, waypointPod, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const shop: Obj[] = [ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];
const bound: Obj[] = [waypoint("shop", "wp"), waypointPod("shop", "wp"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })];
const unbound: Obj[] = [service("shop", "cart", { app: "cart" })];

const retryVs = (ns = "shop", extra: Obj = {}) =>
  virtualService(ns, "cart-retries", { hosts: ["cart"], http: [{ retries: { attempts: 3 }, timeout: "2s", route: [{ destination: { host: "cart" } }] }], ...extra });

async function run(resources: Obj[], files?: Record<string, string | null>) {
  const { findings, engine } = await runEngine({ resources, files }, ["sidecar-to-ambient"]);
  return { f: finding(findings, "DIAG-013"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-013") };
}

describe("DIAG-013 VirtualService / DestinationRule L7 features without a waypoint", () => {
  it("(a) flags mesh VS retries and timeouts on an ambient Service with no waypoint", async () => {
    const { f } = await run([...shop, ...unbound, retryVs()]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart \(ambient, no waypoint\): VirtualService shop\/cart-retries \(retries, timeout\)/)]);
    expect(f?.issues?.[0].namespace).toBe("shop");
  });

  it("(a) does not flag the same VS on a Service bound to a ready waypoint", async () => {
    const { f } = await run([...shop, ...bound, retryVs()]);
    expect(f).toBeUndefined();
  });

  it("(a) does not flag a VS bound only to an ingress gateway", async () => {
    const { f } = await run([...shop, ...unbound, retryVs("shop", { gateways: ["istio-system/public"] })]);
    expect(f).toBeUndefined();
  });

  it("(a) reports a sidecar Service as a migration blocker (warning) once ztunnel is installed", async () => {
    const { f } = await run([
      ztunnelDaemonSet(),
      namespace("shop", { "istio-injection": "enabled" }),
      sidecarPod("shop", "cart", "1.31.2", { app: "cart" }),
      ...unbound,
      retryVs(),
    ]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/\(sidecar, no waypoint; migration blocker\)/)]);
  });

  it("(b) flags DR consistentHash and outlierDetection on an ambient Service with no waypoint", async () => {
    const dr = destinationRule("shop", "cart-lb", { host: "cart.shop.svc.cluster.local", trafficPolicy: { loadBalancer: { consistentHash: { httpHeaderName: "x-user" } }, outlierDetection: { consecutive5xxErrors: 5 } } });
    const { f } = await run([...shop, ...unbound, dr]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart \(ambient, no waypoint\): DestinationRule shop\/cart-lb \(consistentHash, outlierDetection\)/)]);
  });

  it("(b) does not flag a DR with L4-only settings", async () => {
    const dr = destinationRule("shop", "cart-tls", { host: "cart", trafficPolicy: { connectionPool: { tcp: { maxConnections: 100 } } } });
    const { f } = await run([...shop, ...unbound, dr]);
    expect(f).toBeUndefined();
  });

  it("(c) flags sourceLabels matches, which waypoints drop", async () => {
    const vs = virtualService("shop", "cart-canary", { hosts: ["cart"], http: [{ match: [{ sourceLabels: { app: "web" } }], route: [{ destination: { host: "cart" } }] }] });
    const { f } = await run([...shop, ...bound, vs]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/sourceLabels match.*dropped by waypoint shop\/wp/)]);
  });

  it("(c) flags a VS outside the Service's and the waypoint's namespace, which the waypoint ignores", async () => {
    const vs = virtualService("web", "cart-from-web", { hosts: ["cart.shop.svc.cluster.local"], http: [{ timeout: "1s", route: [{ destination: { host: "cart.shop.svc.cluster.local" } }] }] });
    const { f } = await run([...shop, ...bound, namespace("web", AMBIENT_NS), vs]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^VirtualService web\/cart-from-web: .*ignored by waypoint shop\/wp/)]);
  });

  it("(d) flags a Service with both an HTTPRoute parentRef and a mesh VirtualService", async () => {
    const route = httpRoute("shop", "cart-route", [{ group: "", kind: "Service", name: "cart", port: 80 }], [{ name: "cart", port: 80 }]);
    const { f } = await run([...shop, ...bound, retryVs(), route]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart: HTTPRoute shop\/cart-route .*VirtualService shop\/cart-retries/)]);
  });

  it("(e) notes DR subsets used for routing on a waypoint-served Service (HTTPRoute has no subsets)", async () => {
    const vs = virtualService("shop", "cart-split", { hosts: ["cart"], http: [{ route: [{ destination: { host: "cart", subset: "v1" }, weight: 90 }, { destination: { host: "cart", subset: "v2" }, weight: 10 }] }] });
    const dr = destinationRule("shop", "cart-versions", { host: "cart", subsets: [{ name: "v1", labels: { version: "v1" } }, { name: "v2", labels: { version: "v2" } }] });
    const { f } = await run([...shop, ...bound, vs, dr]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^DestinationRule shop\/cart-versions: subsets v1, v2 .*per-version Services/)]);
  });

  it("merges the VirtualService and DestinationRule of one Service into one line", async () => {
    const dr = destinationRule("shop", "cart-lb", { host: "cart", trafficPolicy: { outlierDetection: { consecutive5xxErrors: 5 } } });
    const { f } = await run([...shop, ...unbound, retryVs(), dr]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart \(ambient, no waypoint\): VirtualService shop\/cart-retries \(retries, timeout\); DestinationRule shop\/cart-lb \(outlierDetection\)/)]);
  });

  it("ignores DestinationRule subsets nobody routes to", async () => {
    const dr = destinationRule("shop", "cart-versions", { host: "cart", subsets: [{ name: "v1", labels: { version: "v1" } }] });
    const { f } = await run([...shop, ...unbound, dr]);
    expect(f).toBeUndefined();
  });

  it("counts subsets a mesh VirtualService routes to", async () => {
    const vs = virtualService("shop", "cart-split", { hosts: ["cart"], http: [{ route: [{ destination: { host: "cart", subset: "v1" }, weight: 90 }, { destination: { host: "cart", subset: "v2" }, weight: 10 }] }] });
    const dr = destinationRule("shop", "cart-versions", { host: "cart", subsets: [{ name: "v1", labels: { version: "v1" } }, { name: "v2", labels: { version: "v2" } }] });
    const { f } = await run([...shop, ...unbound, vs, dr]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/VirtualService shop\/cart-split \(weighted routing, subset routing\); DestinationRule shop\/cart-versions \(subsets v1, v2\)/)]);
  });

  it("does not count a single-destination subset that selects the whole Service as routing", async () => {
    const vs = virtualService("shop", "cart-all", { hosts: ["cart"], http: [{ route: [{ destination: { host: "cart", subset: "all" } }] }] });
    const dr = destinationRule("shop", "cart-all", { host: "cart", subsets: [{ name: "all", labels: { app: "cart" } }] });
    const { f } = await run([...shop, ...unbound, vs, dr]);
    expect(f).toBeUndefined();
  });

  it("drops HTTP-only DestinationRule settings on a Service with no HTTP port", async () => {
    const tcp = service("shop", "cart", { app: "cart" }, {}, [{ name: "tcp-db", port: 5432 }]);
    const dr = destinationRule("shop", "cart-hash", { host: "cart", trafficPolicy: { loadBalancer: { consistentHash: { httpHeaderName: "x-user" } }, connectionPool: { http: { http2MaxRequests: 10 } } } });
    const { f } = await run([...shop, tcp, dr]);
    expect(f).toBeUndefined();
  });

  it("flags DestinationRule TLS origination for an external host ambient clients call without a waypoint", async () => {
    const se = serviceEntry("shop", "payments-api", ["api.payments.example.com"]);
    const dr = destinationRule("shop", "payments-tls", { host: "api.payments.example.com", trafficPolicy: { tls: { mode: "SIMPLE" } } });
    const { f } = await run([...shop, se, dr]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^ServiceEntry shop\/payments-api \(ambient clients, no waypoint\): DestinationRule shop\/payments-tls \(tls SIMPLE origination: ztunnel does not originate TLS, so this traffic leaves unencrypted\)/)]);
  });

  it("names the label when a ready waypoint already exists in the namespace but nothing binds the Service", async () => {
    const { f } = await run([...shop, ...unbound, waypoint("shop", "wp"), waypointPod("shop", "wp"), retryVs()]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/waypoint shop\/wp is ready in the namespace but does not serve this Service: kubectl label service cart -n shop istio.io\/use-waypoint=wp/)]);
  });

  it("honors PERMIT_CROSS_NAMESPACE_RESOURCE_ACCESS only for the waypoint's exact namespace/serviceaccount", async () => {
    const vs = virtualService("web", "cart-from-web", { hosts: ["cart.shop.svc.cluster.local"], http: [{ timeout: "1s", route: [{ destination: { host: "cart.shop.svc.cluster.local" } }] }] });
    const ok = await run([...shop, ...bound, namespace("web", AMBIENT_NS), vs, istiodDeployment({ PERMIT_CROSS_NAMESPACE_RESOURCE_ACCESS: "shop/wp" })]);
    expect(ok.f).toBeUndefined();
    const other = await run([...shop, ...bound, namespace("web", AMBIENT_NS), vs, istiodDeployment({ PERMIT_CROSS_NAMESPACE_RESOURCE_ACCESS: "shop/other-sa" })]);
    expect(other.f?.affectedResources).toEqual([expect.stringMatching(/ignored by waypoint shop\/wp/)]);
  });

  it("(e) drops the subsets note when the subset is the whole Service", async () => {
    const vs = virtualService("shop", "cart-all", { hosts: ["cart"], http: [{ route: [{ destination: { host: "cart", subset: "all" } }] }] });
    const dr = destinationRule("shop", "cart-all", { host: "cart", subsets: [{ name: "all", labels: { app: "cart" } }] });
    const { f } = await run([...shop, ...bound, vs, dr]);
    expect(f).toBeUndefined();
  });

  it("does not run on a mesh with no ambient footprint", async () => {
    const { f, skipped } = await run([namespace("shop", { "istio-injection": "enabled" }), sidecarPod("shop", "cart", "1.31.2", { app: "cart" }), ...unbound, retryVs()]);
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("is not evaluated without cluster/crs", async () => {
    const { f, skipped } = await run([...shop, ...unbound], { "cluster/crs": null });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/cluster\/crs/);
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { skipped } = await run(shop, { "cluster/k8s-resources": null });
    expect(skipped?.reason).toMatch(/k8s-resources/);
  });
});

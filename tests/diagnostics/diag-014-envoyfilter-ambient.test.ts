import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, envoyFilter, finding, namespace, pod, runEngine, service, sidecarPod, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, waypointPod, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const shop: Obj[] = [ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];
const bound: Obj[] = [waypoint("shop", "wp"), waypointPod("shop", "wp"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })];

const luaPatch = (context: string) => ({
  applyTo: "HTTP_FILTER",
  match: { context, listener: { filterChain: { filter: { name: "envoy.filters.network.http_connection_manager" } } } },
  patch: { operation: "INSERT_BEFORE", value: { name: "envoy.filters.http.lua", typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua" } } },
});

async function run(resources: Obj[], files?: Record<string, string | null>) {
  const { findings, engine } = await runEngine({ resources, files }, ["envoyfilter"]);
  return {
    f: finding(findings, "DIAG-014"),
    diag005: finding(findings, "DIAG-005"),
    skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-014"),
  };
}

describe("DIAG-014 EnvoyFilters inert or misattached in ambient", () => {
  it("flags a workloadSelector filter that selects only ambient pods", async () => {
    const ef = envoyFilter("shop", "cart-lua", { workloadSelector: { labels: { app: "cart" } }, configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f, diag005 } = await run([...shop, ef]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^EnvoyFilter shop\/cart-lua: inserts lua; selects 1 ambient pod \(shop: cart\)/)]);
    // DIAG-005 does not also report it: the selector matches a pod.
    expect(diag005).toBeUndefined();
  });

  it("flags a namespace-wide sidecar filter in an ambient namespace", async () => {
    const ef = envoyFilter("shop", "ns-lua", { configPatches: [luaPatch("SIDECAR_OUTBOUND")] });
    const { f } = await run([...shop, ef]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^EnvoyFilter shop\/ns-lua: .*1 ambient pod/)]);
  });

  it("flags a workloadSelector filter aimed at waypoint pods (waypoints ignore workloadSelector)", async () => {
    const ef = envoyFilter("shop", "wp-lua", { workloadSelector: { labels: { "gateway.networking.k8s.io/gateway-name": "wp" } }, configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f } = await run([...shop, ...bound, ef]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/waypoint pod.*use targetRefs/)]);
  });

  it("flags targetRefs to a Service that is not bound to a waypoint", async () => {
    const ef = envoyFilter("shop", "cart-wp-lua", { targetRefs: [{ kind: "Service", group: "", name: "cart" }], configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f } = await run([...shop, service("shop", "cart", { app: "cart" }), ef]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/targetRef Service cart has no waypoint/)]);
  });

  it("flags waypoint-targeted patches that use the GATEWAY context, which waypoints never apply", async () => {
    const ef = envoyFilter("shop", "cart-gw-ctx", { targetRefs: [{ kind: "Service", group: "", name: "cart" }], configPatches: [luaPatch("GATEWAY")] });
    const { f } = await run([...shop, ...bound, ef]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/context GATEWAY/)]);
  });

  it("does not flag targetRefs to a waypoint-bound Service with a sidecar context", async () => {
    const ef = envoyFilter("shop", "cart-wp-lua", { targetRefs: [{ kind: "Service", group: "", name: "cart" }], configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f } = await run([...shop, ...bound, ef]);
    expect(f).toBeUndefined();
  });

  it("does not flag a GATEWAY-context filter on an ingress gateway", async () => {
    const gw = pod("istio-system", "istio-ingressgateway-abc", { istio: "ingressgateway" }, [{ name: "istio-proxy", args: ["proxy", "router"] }]);
    const ef = envoyFilter("istio-system", "ingress-lua", { workloadSelector: { labels: { istio: "ingressgateway" } }, configPatches: [luaPatch("GATEWAY")] });
    const { f } = await run([...shop, gw, ef]);
    expect(f).toBeUndefined();
  });

  it("leaves a targetRef to a missing Service to DIAG-005", async () => {
    const ef = envoyFilter("shop", "cart-wp-lua", { targetRefs: [{ kind: "Service", group: "", name: "gone" }], configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f, diag005 } = await run([...shop, ...bound, ef]);
    expect(f).toBeUndefined();
    expect(diag005?.affectedResources).toEqual(["shop/cart-wp-lua: targetRef Service/gone does not exist"]);
  });

  it("reports sidecar pods relying on a sidecar filter as a migration blocker once ztunnel is installed", async () => {
    const ef = envoyFilter("legacy", "api-lua", { workloadSelector: { labels: { app: "api" } }, configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), sidecarPod("legacy", "api", "1.31.2", { app: "api" }), ef]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/1 sidecar pod .*migration blocker/)]);
  });

  it("does not report a selector that matches no pod (DIAG-005 does)", async () => {
    const ef = envoyFilter("shop", "orphan", { workloadSelector: { labels: { app: "nothing" } }, configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f, diag005 } = await run([...shop, ef]);
    expect(f).toBeUndefined();
    expect(diag005).toBeDefined();
  });

  it("ignores patches whose proxyVersion matches no running proxy", async () => {
    const patch = { ...luaPatch("SIDECAR_INBOUND"), match: { ...luaPatch("SIDECAR_INBOUND").match, proxy: { proxyVersion: "^1\\.2[0-9].*" } } };
    const ef = envoyFilter("shop", "old-lua", { workloadSelector: { labels: { app: "cart" } }, configPatches: [patch] });
    const { f } = await run([...shop, ef]);
    expect(f).toBeUndefined();
  });

  it("keeps patches whose proxyVersion matches a running proxy", async () => {
    const patch = { ...luaPatch("SIDECAR_INBOUND"), match: { ...luaPatch("SIDECAR_INBOUND").match, proxy: { proxyVersion: "^1\\.31.*" } } };
    const ef = envoyFilter("shop", "cur-lua", { workloadSelector: { labels: { app: "cart" } }, configPatches: [patch] });
    const { f } = await run([...shop, ef]);
    expect(f?.severity).toBe("critical");
  });

  it("reports root-namespace telemetry filters as info: built into ztunnel and waypoints", async () => {
    const stats = {
      applyTo: "HTTP_FILTER",
      match: { context: "SIDECAR_OUTBOUND", listener: { filterChain: { filter: { name: "envoy.filters.network.http_connection_manager" } } } },
      patch: { operation: "INSERT_BEFORE", value: { name: "istio.stats", typed_config: { "@type": "type.googleapis.com/stats.PluginConfig" } } },
    };
    const ef = envoyFilter("istio-system", "stats-filter-1.31", { configPatches: [stats] });
    const { f } = await run([...shop, ef]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^EnvoyFilter istio-system\/stats-filter-1.31: inserts Istio telemetry \(stats\); built into ztunnel and waypoints/)]);
  });

  it("describes MERGE patches as modifications of the matched filter", async () => {
    const merge = {
      applyTo: "NETWORK_FILTER",
      match: { context: "SIDECAR_INBOUND", listener: { filterChain: { filter: { name: "envoy.filters.network.http_connection_manager" } } } },
      patch: { operation: "MERGE", value: { typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", stream_idle_timeout: "0s" } } },
    };
    const ef = envoyFilter("shop", "hcm-tweak", { workloadSelector: { labels: { app: "cart" } }, configPatches: [merge] });
    const { f } = await run([...shop, ef]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^EnvoyFilter shop\/hcm-tweak: modifies http_connection_manager; selects 1 ambient pod/)]);
  });

  it("says a namespace-wide filter does not attach to the namespace's waypoints either", async () => {
    const ef = envoyFilter("shop", "ns-lua", { configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f } = await run([...shop, ...bound, ef]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/1 ambient pod .*does not attach to the 1 waypoint pod \(shop: wp-5d4f7c-abcde\) either/)]);
  });

  it("does not run on a mesh with no ambient footprint", async () => {
    const ef = envoyFilter("legacy", "api-lua", { workloadSelector: { labels: { app: "api" } }, configPatches: [luaPatch("SIDECAR_INBOUND")] });
    const { f } = await run([namespace("legacy", { "istio-injection": "enabled" }), sidecarPod("legacy", "api", "1.31.2", { app: "api" }), ef]);
    expect(f).toBeUndefined();
  });

  it("is not evaluated without cluster/crs", async () => {
    const { skipped } = await run(shop, { "cluster/crs": null });
    expect(skipped?.reason).toMatch(/cluster\/crs/);
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { skipped } = await run(shop, { "cluster/k8s-resources": null });
    expect(skipped?.reason).toMatch(/k8s-resources/);
  });
});

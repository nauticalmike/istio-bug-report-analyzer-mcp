import { describe, it, expect, afterEach } from "vitest";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, service, waypoint, type Obj } from "./template-harness.js";
import {
  AMBIENT_NS,
  authorizationPolicy,
  classGateway,
  controllerDeployment,
  gatewayClass,
  gatewayPod,
  httpRoute,
  ingressGateway,
  istiodDeployment,
  istioGateway,
  virtualService,
  waypointPod,
  ztunnelDaemonSet,
} from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const cartPolicy = authorizationPolicy("shop", "cart-l7", { targetRefs: [{ kind: "Service", group: "", name: "cart" }], rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
const mesh = (svcLabels: Obj = {}, nsLabels: Obj = {}, wpLabels: Obj = {}): Obj[] => [
  ztunnelDaemonSet(),
  namespace("shop", { ...AMBIENT_NS, ...nsLabels }),
  ambientPod("shop", "cart", { app: "cart" }),
  waypoint("shop", "wp", { labels: wpLabels }),
  waypointPod("shop", "wp"),
  service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp", ...svcLabels }),
];
const route = httpRoute("shop", "cart-public", [{ name: "public", namespace: "edge" }], [{ name: "cart", port: 80 }]);
const edge = ingressGateway("edge", "public");

async function run(resources: Obj[], opts: { files?: Record<string, string | null>; versions?: string } = {}) {
  const { findings, engine } = await runEngine({ resources, files: opts.files, versions: opts.versions }, ["ambient"]);
  return { f: finding(findings, "DIAG-015"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-015") };
}

describe("DIAG-015 ingress traffic bypasses the waypoint", () => {
  it("flags an HTTPRoute from an ingress Gateway to a waypoint Service with L7 authorization", async () => {
    const { f } = await run([...mesh(), edge, route, cartPolicy]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([
      expect.stringMatching(/^Service shop\/cart \(waypoint shop\/wp\): backend of Gateway edge\/public via HTTPRoute shop\/cart-public; .*AuthorizationPolicy shop\/cart-l7.*no istio.io\/ingress-use-waypoint=true/),
    ]);
  });

  it("flags a classic Istio Gateway VirtualService routing to the Service", async () => {
    const vs = virtualService("shop", "cart-ingress", { hosts: ["shop.example.com"], gateways: ["istio-system/public"], http: [{ route: [{ destination: { host: "cart" } }] }] });
    const { f } = await run([...mesh(), istioGateway("istio-system", "public"), vs, cartPolicy]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/backend of Gateway istio-system\/public via VirtualService shop\/cart-ingress/)]);
  });

  it("does not fire when the Service sets istio.io/ingress-use-waypoint=true", async () => {
    const { f } = await run([...mesh({ "istio.io/ingress-use-waypoint": "true" }), edge, route, cartPolicy]);
    expect(f).toBeUndefined();
  });

  it("does not fire when the namespace sets it (1.25+)", async () => {
    const { f } = await run([...mesh({}, { "istio.io/ingress-use-waypoint": "true" }), edge, route, cartPolicy]);
    expect(f).toBeUndefined();
  });

  it("fires for a namespace label on a 1.24 control plane, which only reads the Service label", async () => {
    const { f } = await run([...mesh({}, { "istio.io/ingress-use-waypoint": "true" }), edge, route, cartPolicy], { versions: bugReportVersions("1.24.3") });
    expect(f?.affectedResources).toEqual([expect.stringMatching(/namespace label needs Istio 1.25/)]);
  });

  it("a Service label of false overrides a namespace label of true", async () => {
    const { f } = await run([...mesh({ "istio.io/ingress-use-waypoint": "false" }, { "istio.io/ingress-use-waypoint": "true" }), edge, route, cartPolicy]);
    expect(f).toBeDefined();
  });

  it("fires when istiod disables ENABLE_INGRESS_WAYPOINT_ROUTING", async () => {
    const { f } = await run([...mesh({ "istio.io/ingress-use-waypoint": "true" }), edge, route, cartPolicy, istiodDeployment({ ENABLE_INGRESS_WAYPOINT_ROUTING: "false" })]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/ENABLE_INGRESS_WAYPOINT_ROUTING=false/)]);
  });

  it("does not fire when nothing is enforced or routed at the waypoint", async () => {
    const { f } = await run([...mesh(), edge, route]);
    expect(f).toBeUndefined();
  });

  it("treats a Gateway whose GatewayClass uses istio.io/gateway-controller as an Istio gateway", async () => {
    const gw = classGateway("edge", "public", "istio-public");
    const { f } = await run([...mesh(), gatewayClass("istio-public", "istio.io/gateway-controller"), gw, route, cartPolicy]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/no istio.io\/ingress-use-waypoint=true/)]);
  });

  it("warns for a captured non-Istio gateway when the waypoint is waypoint-for service", async () => {
    const { f } = await run([...mesh(), namespace("edge", AMBIENT_NS), gatewayClass("edge-proxy", "example.com/edge-controller"), classGateway("edge", "public", "edge-proxy"), gatewayPod("edge", "public", true), route, cartPolicy]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart \(waypoint shop\/wp\): backend of Gateway edge\/public \(controller example.com\/edge-controller\).*may address pod IPs/)]);
  });

  it("does not fire for a captured non-Istio gateway when the waypoint also serves workload traffic", async () => {
    const { f } = await run([...mesh({}, {}, { "istio.io/waypoint-for": "all" }), namespace("edge", AMBIENT_NS), gatewayClass("edge-proxy", "example.com/edge-controller"), classGateway("edge", "public", "edge-proxy"), gatewayPod("edge", "public", true), route, cartPolicy]);
    expect(f).toBeUndefined();
  });

  it("reports a non-Istio gateway outside the mesh as info", async () => {
    const { f } = await run([...mesh(), namespace("edge"), gatewayClass("edge-proxy", "example.com/edge-controller"), classGateway("edge", "public", "edge-proxy"), gatewayPod("edge", "public", false), route, cartPolicy]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/outside the mesh/)]);
  });

  it("does not fire for a kgateway controller with KGW_INGRESS_USE_WAYPOINTS and the label set", async () => {
    const { f } = await run([
      ...mesh({ "istio.io/ingress-use-waypoint": "true" }),
      namespace("edge"),
      gatewayClass("kgateway", "kgateway.dev/kgateway"),
      classGateway("edge", "public", "kgateway"),
      gatewayPod("edge", "public", false),
      controllerDeployment("kgateway-system", "kgateway", { KGW_INGRESS_USE_WAYPOINTS: "true" }),
      route,
      cartPolicy,
    ]);
    expect(f).toBeUndefined();
  });

  it("follows VirtualService delegates (namespace defaults to the root's) and resolves hosts in the delegate's namespace", async () => {
    const root = virtualService("istio-system", "root", { hosts: ["shop.example.com"], gateways: ["public"], http: [{ match: [{ uri: { prefix: "/cart" } }], delegate: { name: "cart-routes", namespace: "shop" } }] });
    const delegate = virtualService("shop", "cart-routes", { http: [{ route: [{ destination: { host: "cart" } }] }] });
    const { f } = await run([...mesh(), istioGateway("istio-system", "public"), root, delegate, cartPolicy]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/backend of Gateway istio-system\/public via VirtualService istio-system\/root \(delegate shop\/cart-routes\)/)]);
  });

  it("prints the API group of a policy when a same-named non-Istio kind exists", async () => {
    const foreign = { apiVersion: "policy.example.io/v1alpha1", kind: "AuthorizationPolicy", metadata: { name: "other", namespace: "shop" }, spec: {} };
    const { f } = await run([...mesh(), edge, route, cartPolicy, foreign]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/AuthorizationPolicy\.security\.istio\.io shop\/cart-l7/)]);
  });

  it("is not evaluated without cluster/crs", async () => {
    const { skipped } = await run(mesh(), { files: { "cluster/crs": null } });
    expect(skipped?.reason).toMatch(/cluster\/crs/);
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { skipped } = await run(mesh(), { files: { "cluster/k8s-resources": null } });
    expect(skipped?.reason).toMatch(/k8s-resources/);
  });
});

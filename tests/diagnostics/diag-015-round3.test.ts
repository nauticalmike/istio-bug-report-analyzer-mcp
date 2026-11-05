import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, service, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, authorizationPolicy, httpRoute, ingressGateway, policy, virtualService, waypointPod, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const mesh: Obj[] = [
  ztunnelDaemonSet(),
  namespace("shop", AMBIENT_NS),
  namespace("waypoints", AMBIENT_NS),
  ambientPod("shop", "cart", { app: "cart" }),
  waypoint("waypoints", "wp", { from: "All" }),
  waypointPod("waypoints", "wp"),
  service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp", "istio.io/use-waypoint-namespace": "waypoints" }),
  ingressGateway("edge", "public"),
  httpRoute("shop", "cart-public", [{ name: "public", namespace: "edge" }], [{ name: "cart", port: 80 }]),
];

async function run(resources: Obj[]) {
  const { findings } = await runEngine({ resources }, ["ambient"]);
  return finding(findings, "DIAG-015");
}

describe("DIAG-015 round 3: what the waypoint applies, from the target index", () => {
  it("lists Service, Gateway and GatewayClass targetRefs policies, Service-parent routes and VirtualServices of the Service's or the waypoint's namespace, each once and in kind order", async () => {
    const both = authorizationPolicy("shop", "cart-and-wp", { targetRefs: [{ kind: "Service", group: "", name: "cart" }, { kind: "Service", group: "", name: "cart" }] });
    const onGateway = policy("Telemetry", "waypoints", "wp-telemetry", { targetRefs: [{ kind: "Gateway", group: "gateway.networking.k8s.io", name: "wp" }] });
    const onClass = policy("RequestAuthentication", "istio-system", "all-waypoints", { targetRefs: [{ kind: "GatewayClass", group: "gateway.networking.k8s.io", name: "istio-waypoint" }] });
    const notRoot = policy("RequestAuthentication", "shop", "class-not-root", { targetRefs: [{ kind: "GatewayClass", group: "gateway.networking.k8s.io", name: "istio-waypoint" }] });
    const meshRoute = httpRoute("shop", "cart-mesh", [{ group: "", kind: "Service", name: "cart" }], [{ name: "cart", port: 80 }]);
    const vsHere = virtualService("waypoints", "cart-vs", { hosts: ["cart.shop.svc.cluster.local"], http: [{ timeout: "1s", route: [{ destination: { host: "cart.shop.svc.cluster.local" } }] }] });
    const vsElsewhere = virtualService("other", "cart-vs", { hosts: ["cart.shop.svc.cluster.local"], http: [{ timeout: "1s", route: [{ destination: { host: "cart.shop.svc.cluster.local" } }] }] });
    const f = await run([...mesh, both, onGateway, onClass, notRoot, meshRoute, vsHere, vsElsewhere]);
    expect(f?.severity).toBe("critical");
    const detail = f?.affectedResources[0] ?? "";
    expect(detail).toContain("(AuthorizationPolicy shop/cart-and-wp, RequestAuthentication istio-system/all-waypoints, Telemetry waypoints/wp-telemetry (+2 more))");
    expect(detail).not.toContain("class-not-root");
  });
});

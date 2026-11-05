import { describe, it, expect, afterEach } from "vitest";
import { dump } from "js-yaml";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, service, sidecarPod, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, authorizationPolicy, waypointPod, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const base: Obj[] = [ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];

async function run(resources: Obj[], files?: Record<string, string | null>) {
  const { findings, engine } = await runEngine({ resources, files }, ["ambient"]);
  return { f: finding(findings, "DIAG-012"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-012") };
}

describe("DIAG-012 waypoint referenced but unusable", () => {
  it("flags a namespace use-waypoint label naming a missing Gateway (warning while nothing targets it)", async () => {
    const { f } = await run([...base.slice(0, 1), namespace("shop", { ...AMBIENT_NS, "istio.io/use-waypoint": "wp" }), base[2]]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Namespace shop: istio.io\/use-waypoint=wp .*no Gateway shop\/wp/)]);
    expect(f?.issues?.[0].namespace).toBe("shop");
  });

  it("is critical when a policy targets a Service of the ambient namespace bound to the missing waypoint", async () => {
    const ap = authorizationPolicy("shop", "cart-l7", { targetRefs: [{ kind: "Service", group: "", name: "cart" }] });
    const { f } = await run([...base.slice(0, 1), namespace("shop", { ...AMBIENT_NS, "istio.io/use-waypoint": "wp" }), base[2], service("shop", "cart", { app: "cart" }), ap]);
    expect(f?.severity).toBe("critical");
    expect(f?.issues?.find((i) => i.detail.startsWith("Namespace shop:"))?.severity).toBe("critical");
  });

  it("reports objects in namespaces outside the mesh as info, grouped by namespace, waypoint and problem", async () => {
    const { f } = await run([
      ...base,
      namespace("tools"),
      service("tools", "a", { app: "a" }, { "istio.io/use-waypoint": "gone" }),
      service("tools", "b", { app: "b" }, { "istio.io/use-waypoint": "gone" }),
      service("tools", "c", { app: "c" }, { "istio.io/use-waypoint": "gone" }),
    ]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual(["3 Services in tools (a, b, c): istio.io/use-waypoint=gone does not take effect: no Gateway tools/gone"]);
    expect(f?.issues?.[0].namespace).toBe("tools");
  });

  it("hints at istio.io/use-waypoint-namespace when a Gateway of that name exists in another namespace", async () => {
    const { f } = await run([...base, namespace("mesh-gw"), waypoint("mesh-gw", "wp", { from: "All" }), waypointPod("mesh-gw", "wp"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })]);
    expect(f?.affectedResources).toContainEqual(expect.stringMatching(/no Gateway shop\/wp; a Gateway mesh-gw\/wp exists: set istio.io\/use-waypoint-namespace=mesh-gw/));
  });

  it("hints at a naming mismatch when a similarly named waypoint exists in the namespace", async () => {
    const { f } = await run([...base, waypoint("shop", "waypoint"), waypointPod("shop", "waypoint"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "waypont" })]);
    expect(f?.affectedResources).toContainEqual(expect.stringMatching(/no Gateway shop\/waypont; naming mismatch\? waypoint shop\/waypoint exists in the namespace/));
  });

  it("reports nothing for a binding whose waypoint namespace was not collected", async () => {
    const { f } = await run([...base, namespace("far"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp", "istio.io/use-waypoint-namespace": "far" })]);
    expect(f).toBeUndefined();
  });

  it("reports a ready waypoint nothing binds to, with its pods' requests (info)", async () => {
    const pod = waypointPod("shop", "spare") as { spec: { containers: Obj[] } };
    pod.spec.containers[0].resources = { requests: { cpu: "100m", memory: "128Mi" } };
    const { f } = await run([...base, waypoint("shop", "spare"), pod]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Waypoint shop\/spare: ready, but nothing binds to it .*1 pod requests 100m CPU, 128Mi memory/)]);
  });

  it("does not report an unbound waypoint in a namespace that was not collected", async () => {
    const shared = waypoint("mesh-gw", "shared", { from: "All" });
    const { f } = await run([...base, namespace("mesh-gw")], { "cluster/crs": dump({ apiVersion: "v1", kind: "List", items: [shared] }) });
    expect(f).toBeUndefined();
  });

  it("flags a Service bound to a waypoint that is not programmed", async () => {
    const { f } = await run([...base, waypoint("shop", "wp", { ready: false }), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart: .*no status.addresses/)]);
  });

  it("flags a use-waypoint label naming a Gateway that is not a waypoint", async () => {
    const { f } = await run([...base, waypoint("shop", "edge", { className: "istio" }), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "edge" })]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/class istio, not a waypoint class/)]);
  });

  it("flags a waypoint whose Programmed condition is False", async () => {
    const wp = waypoint("shop", "wp") as { status: Obj };
    wp.status.conditions = [{ type: "Programmed", status: "False", reason: "AddressNotUsable" }];
    const { f } = await run([...base, wp, waypointPod("shop", "wp"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/Programmed=False \(AddressNotUsable\)/)]);
  });

  it("flags a waypoint with no running pod when the pod dump covers its namespace", async () => {
    const { f } = await run([...base, waypoint("shop", "wp"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/no waypoint pod for Gateway shop\/wp/)]);
  });

  it("does not claim missing waypoint pods for a namespace the pod dump does not cover", async () => {
    // The Gateway lives in cluster/crs, as istioctl writes it; nothing of mesh-gw is in the pod
    // dump, though its Namespace object is (Namespace objects are always collected cluster-wide).
    const shared = waypoint("mesh-gw", "shared", { labels: { "istio.io/waypoint-for": "service" }, from: "All" });
    const { f } = await run(
      [...base, namespace("mesh-gw"), service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "shared", "istio.io/use-waypoint-namespace": "mesh-gw" })],
      { "cluster/crs": dump({ apiVersion: "v1", kind: "List", items: [shared] }) },
    );
    expect(f).toBeUndefined();
  });

  it("flags ingress-use-waypoint on a Service that has no waypoint", async () => {
    const { f } = await run([...base, service("shop", "cart", { app: "cart" }, { "istio.io/ingress-use-waypoint": "true" })]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service shop\/cart: istio.io\/ingress-use-waypoint=true has no effect/)]);
  });

  it("flags use-waypoint on a namespace that is not in ambient mode", async () => {
    const { f } = await run([
      ztunnelDaemonSet(),
      namespace("legacy", { "istio-injection": "enabled", "istio.io/use-waypoint": "wp" }),
      waypoint("legacy", "wp"),
      waypointPod("legacy", "wp"),
      sidecarPod("legacy", "api", "1.31.2"),
    ]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Namespace legacy: .*not in ambient mode/)]);
  });

  it("flags a targetRefs policy on a Service with no usable waypoint", async () => {
    const ap = authorizationPolicy("shop", "cart-l7", { targetRefs: [{ kind: "Service", group: "", name: "cart" }], rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const { f } = await run([...base, service("shop", "cart", { app: "cart" }), ap]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^AuthorizationPolicy shop\/cart-l7: targetRef Service cart has no waypoint, so the policy is not enforced today/)]);
  });

  it("notes a targetRefs policy on a sidecar Service as pre-staged when a selector policy of the kind covers its pods", async () => {
    const ap = authorizationPolicy("legacy", "api-l7", { targetRefs: [{ kind: "Service", group: "", name: "api" }] });
    const sel = authorizationPolicy("legacy", "api-sel", { selector: { matchLabels: { app: "api" } } });
    const { f } = await run([namespace("legacy", { "istio-injection": "enabled" }), sidecarPod("legacy", "api", "1.31.2"), service("legacy", "api", { app: "api" }), ap, sel]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^AuthorizationPolicy legacy\/api-l7: .*pre-staged for a waypoint; the selector policy legacy\/api-sel enforces today/)]);
  });

  it("warns that a targetRefs policy on a sidecar Service with no selector policy is not enforced today", async () => {
    const ap = authorizationPolicy("legacy", "api-l7", { targetRefs: [{ kind: "Service", group: "", name: "api" }] });
    const { f } = await run([namespace("legacy", { "istio-injection": "enabled" }), sidecarPod("legacy", "api", "1.31.2"), service("legacy", "api", { app: "api" }), ap]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^AuthorizationPolicy legacy\/api-l7: .*not enforced today: sidecars ignore Service targetRefs/)]);
  });

  it("does not fire for a Service bound to a ready waypoint with a running pod", async () => {
    const ap = authorizationPolicy("shop", "cart-l7", { targetRefs: [{ kind: "Service", group: "", name: "cart" }] });
    const { f } = await run([
      ...base,
      waypoint("shop", "wp"),
      waypointPod("shop", "wp"),
      service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp", "istio.io/ingress-use-waypoint": "true" }),
      ap,
    ]);
    expect(f).toBeUndefined();
  });

  it("still reports a dangling use-waypoint label on a mesh with no ambient workloads", async () => {
    const { f } = await run([namespace("legacy", { "istio-injection": "enabled" }), service("legacy", "api", { app: "api" }, { "istio.io/use-waypoint": "gone" })]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/no Gateway legacy\/gone/)]);
  });

  it("is not evaluated without cluster/crs", async () => {
    const { f, skipped } = await run(base, { "cluster/crs": null });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/cluster\/crs/);
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { f, skipped } = await run(base, { "cluster/k8s-resources": null });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/k8s-resources/);
  });
});

describe("DIAG-012 waypoint pods on older releases", () => {
  it("accepts a waypoint pod labelled istio.io/gateway-name", async () => {
    const old = waypointPod("shop", "wp") as { metadata: { labels: Obj } };
    old.metadata.labels = { "istio.io/gateway-name": "wp" };
    const { findings } = await runEngine(
      { resources: [ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" }), waypoint("shop", "wp"), old, service("shop", "cart", { app: "cart" }, { "istio.io/use-waypoint": "wp" })] },
      ["ambient"],
    );
    expect(finding(findings, "DIAG-012")).toBeUndefined();
  });
});

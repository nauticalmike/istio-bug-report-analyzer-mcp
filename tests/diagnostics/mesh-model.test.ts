import { describe, it, expect, afterEach } from "vitest";
import {
  ambientNamespaces,
  injectorWebhooks,
  migrationStage,
  namespaceMode,
  podMode,
  revisions,
  waypointFor,
} from "../../src/diagnostics/mesh-model.js";
import type { ParsedResource } from "../../src/types.js";
import { ambientPod, buildStore, cleanupArchives, deployment, namespace, pod, service, sidecarPod, waypoint, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

const asResource = (o: Obj) => o as unknown as ParsedResource;

describe("namespaceMode", () => {
  it("classifies ambient, sidecar, dual and none", async () => {
    const store = await buildStore({
      resources: [
        namespace("amb", { "istio.io/dataplane-mode": "ambient" }),
        namespace("inj", { "istio-injection": "enabled" }),
        namespace("rev", { "istio.io/rev": "1-27" }),
        namespace("both", { "istio.io/dataplane-mode": "ambient", "istio.io/rev": "1-27" }),
        namespace("off", { "istio.io/rev": "1-27", "istio-injection": "disabled" }),
        namespace("plain"),
      ],
    });
    expect(namespaceMode(store, "amb")).toBe("ambient");
    expect(namespaceMode(store, "inj")).toBe("sidecar");
    expect(namespaceMode(store, "rev")).toBe("sidecar");
    expect(namespaceMode(store, "both")).toBe("dual");
    // istio-injection present (any value) disables the revision webhooks.
    expect(namespaceMode(store, "off")).toBe("none");
    expect(namespaceMode(store, "plain")).toBe("none");
    expect(ambientNamespaces(store)).toEqual(["amb", "both"]);
  });
});

describe("podMode", () => {
  it("tells sidecar, ambient, opted-out, host-network and infra pods apart", async () => {
    const hostNet = { ...pod("amb", "node-agent", { app: "agent" }), spec: { hostNetwork: true, containers: [] } };
    const optOut = pod("amb", "batch", { app: "batch", "istio.io/dataplane-mode": "none" });
    const inherited = pod("amb", "web", { app: "web" });
    const wp = pod("amb", "waypoint-abc", { "gateway.networking.k8s.io/gateway-name": "waypoint" });
    const store = await buildStore({
      resources: [namespace("amb", { "istio.io/dataplane-mode": "ambient" }), sidecarPod("amb", "legacy", "1.27.1"), ambientPod("amb", "api"), hostNet, optOut, inherited, wp],
    });
    const mode = (o: Obj) => podMode(store, asResource(o));
    expect(mode(sidecarPod("amb", "legacy", "1.27.1"))).toBe("sidecar");
    expect(mode(ambientPod("amb", "api"))).toBe("ambient");
    expect(mode(inherited)).toBe("ambient");
    expect(mode(optOut)).toBe("none");
    expect(mode(hostNet)).toBe("none");
    expect(mode(wp)).toBe("infra");
  });
});

describe("waypointFor", () => {
  it("follows istiod: object label first, then namespace, none opts out", async () => {
    const resources = [
      namespace("shop", { "istio.io/dataplane-mode": "ambient", "istio.io/use-waypoint": "waypoint" }),
      waypoint("shop", "waypoint"),
      waypoint("shared", "egress", { labels: { "istio.io/waypoint-for": "all" }, from: "All" }),
      service("shop", "cart", { app: "cart" }),
      service("shop", "pay", { app: "pay" }, { "istio.io/use-waypoint": "egress", "istio.io/use-waypoint-namespace": "shared" }),
      service("shop", "probe", { app: "probe" }, { "istio.io/use-waypoint": "none" }),
    ];
    const store = await buildStore({ resources });
    const of = (i: number) => waypointFor(store, asResource(resources[i]), "service");
    expect(of(3)).toMatchObject({ ref: "shop/waypoint", via: "namespace" });
    expect(of(3)?.problem).toBeUndefined();
    expect(of(4)).toMatchObject({ ref: "shared/egress", via: "object" });
    expect(of(4)?.problem).toBeUndefined();
    expect(of(5)).toBeNull();
  });

  it("reports why a binding does not take effect", async () => {
    const resources = [
      namespace("a", { "istio.io/dataplane-mode": "ambient" }),
      waypoint("a", "notready", { ready: false }),
      waypoint("b", "same-only"),
      waypoint("a", "workload-only", { labels: { "istio.io/waypoint-for": "workload" } }),
      service("a", "s1", { app: "s1" }, { "istio.io/use-waypoint": "missing" }),
      service("a", "s2", { app: "s2" }, { "istio.io/use-waypoint": "notready" }),
      service("a", "s3", { app: "s3" }, { "istio.io/use-waypoint": "same-only", "istio.io/use-waypoint-namespace": "b" }),
      service("a", "s4", { app: "s4" }, { "istio.io/use-waypoint": "workload-only" }),
    ];
    const store = await buildStore({ resources });
    const problem = (i: number) => waypointFor(store, asResource(resources[i]), "service")?.problem;
    expect(problem(4)).toBe("no Gateway a/missing");
    expect(problem(5)).toMatch(/no status.addresses/);
    expect(problem(6)).toMatch(/does not allow attachment from namespace a/);
    expect(problem(7)).toMatch(/waypoint-for workload, not service/);
  });

  it("does not flag a workload inheriting a service-only waypoint from its namespace", async () => {
    const resources = [
      namespace("a", { "istio.io/dataplane-mode": "ambient", "istio.io/use-waypoint": "waypoint" }),
      waypoint("a", "waypoint"),
      ambientPod("a", "api"),
    ];
    const store = await buildStore({ resources });
    expect(waypointFor(store, asResource(resources[2]), "workload")?.problem).toBeUndefined();
  });
});

describe("revisions and injector webhooks", () => {
  it("lists istiod revisions with running pods and webhook targets", async () => {
    const mwc = {
      apiVersion: "admissionregistration.k8s.io/v1",
      kind: "MutatingWebhookConfiguration",
      metadata: { name: "istio-revision-tag-default", labels: { "istio.io/rev": "1-27", "istio.io/tag": "default" } },
      webhooks: [{ name: "rev.namespace.sidecar-injector.istio.io", clientConfig: { service: { name: "istiod-1-27", namespace: "istio-system" } } }],
    };
    const istiodPod = { ...pod("istio-system", "istiod-1-27-abc", { app: "istiod", "istio.io/rev": "1-27" }), status: { phase: "Running" } };
    const store = await buildStore({
      resources: [
        deployment("istio-system", "istiod-1-27", { labels: { app: "istiod", "istio.io/rev": "1-27" }, replicas: 2 }),
        deployment("istio-system", "istiod-1-26", { labels: { app: "istiod", "istio.io/rev": "1-26" }, replicas: 0 }),
        istiodPod,
        mwc,
      ],
    });
    const revs = revisions(store);
    expect(revs.get("1-27")).toMatchObject({ runningPods: 1, deployments: [{ name: "istiod-1-27", replicas: 2 }] });
    expect(revs.get("1-26")).toMatchObject({ runningPods: 0 });
    expect(injectorWebhooks(store)).toEqual([
      expect.objectContaining({ revision: "1-27", tag: "default", services: ["istio-system/istiod-1-27"], failurePolicyFail: true }),
    ]);
  });
});

describe("migrationStage", () => {
  it("is none for a sidecar mesh, planned with ztunnel and no ambient pods, partial and ambient after enrolment", async () => {
    const ztunnel = { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name: "ztunnel", namespace: "istio-system", labels: { app: "ztunnel" } }, spec: {} };
    const sidecarNs = namespace("legacy", { "istio-injection": "enabled" });
    const ambientNs = namespace("amb", { "istio.io/dataplane-mode": "ambient" });
    expect(migrationStage(await buildStore({ resources: [sidecarNs, sidecarPod("legacy", "a", "1.27.1")] }))).toBe("none");
    expect(migrationStage(await buildStore({ resources: [sidecarNs, sidecarPod("legacy", "a", "1.27.1"), ztunnel] }))).toBe("planned");
    expect(migrationStage(await buildStore({ resources: [sidecarNs, ambientNs, sidecarPod("legacy", "a", "1.27.1"), ambientPod("amb", "b"), ztunnel] }))).toBe("partial");
    // noPodDump drops the base fixture's cluster/pods, which holds a sidecar pod.
    expect(migrationStage(await buildStore({ resources: [ambientNs, ambientPod("amb", "b"), ztunnel], noPodDump: true }))).toBe("ambient");
  });
});

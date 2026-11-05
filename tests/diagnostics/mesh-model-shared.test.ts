import { describe, it, expect, afterEach } from "vitest";
import {
  labelSelectorMatches,
  livePods,
  migrationStage,
  namespaceCollected,
  namespaceMode,
  revisionLabelUnserved,
  namespaceObjects,
  observedMigrationStage,
  podDumpCovers,
  podMode,
  podsOfService,
  podsSelectedBy,
  resolveHost,
  serviceDataplane,
  servicesOfPod,
  waypointFor,
} from "../../src/diagnostics/mesh-model.js";
import type { ParsedResource } from "../../src/types.js";
import { injectorWebhook } from "./revision-fixtures.js";
import { ambientPod, buildStore, cleanupArchives, injectResources, namespace, pod, service, sidecarPod, waypoint, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

const asResource = (o: Obj) => o as unknown as ParsedResource;
const AMBIENT = { "istio.io/dataplane-mode": "ambient" };

/** kube-root-ca.crt sits in every namespace, so a collected namespace always has an object. */
function rootCa(ns: string): Obj {
  return { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "kube-root-ca.crt", namespace: ns }, data: { "ca.crt": "x" } };
}

function gateway(ns: string, name: string, listeners: Obj[]): Obj {
  return {
    apiVersion: "gateway.networking.k8s.io/v1",
    kind: "Gateway",
    metadata: { name, namespace: ns },
    spec: { gatewayClassName: "istio-waypoint", listeners },
    status: { addresses: [{ type: "IPAddress", value: "10.0.0.9" }] },
  };
}

describe("labelSelectorMatches", () => {
  it("matches matchLabels and matchExpressions; a missing selector selects everything", () => {
    const labels = { team: "a", env: "prod" };
    expect(labelSelectorMatches(undefined, labels)).toBe(true);
    expect(labelSelectorMatches({}, labels)).toBe(true);
    expect(labelSelectorMatches({ matchLabels: { team: "a" } }, labels)).toBe(true);
    expect(labelSelectorMatches({ matchExpressions: [{ key: "env", operator: "In", values: ["prod"] }] }, labels)).toBe(true);
    expect(labelSelectorMatches({ matchExpressions: [{ key: "env", operator: "NotIn", values: ["prod"] }] }, labels)).toBe(false);
    expect(labelSelectorMatches({ matchExpressions: [{ key: "x", operator: "DoesNotExist" }] }, labels)).toBe(true);
    expect(labelSelectorMatches({ matchExpressions: [{ key: "x", operator: "Bogus" }] }, labels)).toBe(false);
  });
});

describe("waypointFor", () => {
  it("resolves a Namespace object's use-waypoint label in the namespace itself", async () => {
    const shop = namespace("shop", { ...AMBIENT, "istio.io/use-waypoint": "wp" });
    const store = await buildStore({ resources: [shop, rootCa("shop"), waypoint("shop", "wp")] });
    const b = waypointFor(store, namespaceObjects(store).get("shop")!, "service");
    expect(b).toMatchObject({ ref: "shop/wp", via: "object" });
    expect(b?.problem).toBeUndefined();
  });

  it("reads allowedRoutes from the HBONE listener on 15008, else Same (makeAllowedRoutes)", async () => {
    const other = namespace("app", { "team": "a" });
    const svc = service("app", "api", { app: "api" }, { "istio.io/use-waypoint": "wp", "istio.io/use-waypoint-namespace": "infra" });
    const viaHbone = gateway("infra", "wp", [
      { name: "http", port: 80, protocol: "HTTP", allowedRoutes: { namespaces: { from: "Same" } } },
      { name: "mesh", port: 15008, protocol: "HBONE", allowedRoutes: { namespaces: { from: "All" } } },
    ]);
    let store = await buildStore({ resources: [other, namespace("infra"), rootCa("app"), rootCa("infra"), svc, viaHbone] });
    expect(waypointFor(store, asResource(svc), "service")?.problem).toBeUndefined();

    // No HBONE listener on 15008: Same, even though the first listener allows All.
    const noHbone = gateway("infra", "wp", [{ name: "http", port: 80, protocol: "HTTP", allowedRoutes: { namespaces: { from: "All" } } }]);
    store = await buildStore({ resources: [other, namespace("infra"), rootCa("app"), rootCa("infra"), svc, noHbone] });
    expect(waypointFor(store, asResource(svc), "service")?.problem).toMatch(/does not allow attachment from namespace app/);
  });

  it("admits namespaces by an allowedRoutes selector with matchExpressions", async () => {
    const svc = service("app", "api", { app: "api" }, { "istio.io/use-waypoint": "wp", "istio.io/use-waypoint-namespace": "infra" });
    const selector = { matchExpressions: [{ key: "team", operator: "In", values: ["a", "b"] }] };
    const gw = gateway("infra", "wp", [{ name: "mesh", port: 15008, protocol: "HBONE", allowedRoutes: { namespaces: { from: "Selector", selector } } }]);
    const base = [namespace("infra"), rootCa("app"), rootCa("infra"), svc, gw];
    let store = await buildStore({ resources: [namespace("app", { team: "b" }), ...base] });
    expect(waypointFor(store, asResource(svc), "service")?.problem).toBeUndefined();
    store = await buildStore({ resources: [namespace("app", { team: "c" }), ...base] });
    expect(waypointFor(store, asResource(svc), "service")?.problem).toMatch(/does not allow attachment/);
  });

  it("cannot judge a missing Gateway in a namespace the archive did not collect", async () => {
    const svc = service("app", "api", { app: "api" }, { "istio.io/use-waypoint": "wp", "istio.io/use-waypoint-namespace": "infra" });
    // infra exists (Namespace objects are cluster-wide) but has no object: left out by --include.
    const store = await buildStore({ resources: [namespace("app"), namespace("infra"), rootCa("app"), svc] });
    const b = waypointFor(store, asResource(svc), "service");
    expect(b).toMatchObject({ ref: "infra/wp", unknown: true });
    expect(b?.problem).toBeUndefined();

    const collected = await buildStore({ resources: [namespace("app"), namespace("infra"), rootCa("app"), rootCa("infra"), svc] });
    expect(waypointFor(collected, asResource(svc), "service")).toMatchObject({ problem: "no Gateway infra/wp" });
  });
});

describe("namespaceCollected and podDumpCovers", () => {
  it("is true for namespaces with objects, false for ones a namespace-scoped dump left out", async () => {
    const store = await buildStore({ resources: [namespace("a"), namespace("b"), rootCa("a"), pod("a", "p", {})] });
    expect(namespaceCollected(store, "a")).toBe(true);
    expect(namespaceCollected(store, "b")).toBe(false);
    expect(podDumpCovers(store, "a")).toBe(true);
    expect(podDumpCovers(store, "b")).toBe(false);
  });

  it("is true for every namespace of a whole-cluster dump, even one with no pods", async () => {
    const store = await buildStore({ resources: [namespace("a"), namespace("b"), namespace("istio-system"), rootCa("a"), rootCa("b"), rootCa("istio-system")] });
    expect(namespaceCollected(store, "b")).toBe(true);
    expect(podDumpCovers(store, "b")).toBe(true);
  });

  it("is unknown without the Kubernetes objects of cluster/k8s-resources", async () => {
    const store = await buildStore({ resources: [], noPodDump: true });
    expect(namespaceCollected(store, "a")).toBe("unknown");
    expect(podDumpCovers(store, "a")).toBe(false);
  });
});

describe("resolveHost", () => {
  it("takes a dotted host as a literal FQDN, like ResolveShortnameToFQDN", async () => {
    const cart = service("shop", "cart", { app: "cart" });
    const store = await buildStore({ resources: [namespace("shop"), cart] });
    const names = (h: string) => resolveHost(store, h, "shop").map((r) => `${r.metadata.namespace}/${r.metadata.name}`);
    expect(names("cart")).toEqual(["shop/cart"]);
    expect(names("cart.shop.svc.cluster.local")).toEqual(["shop/cart"]);
    expect(names("cart.shop.svc.corp.example")).toEqual(["shop/cart"]);
    expect(names("cart.shop.svc")).toEqual([]);
    expect(names("cart.shop")).toEqual([]);
    expect(names("*.shop.svc.cluster.local")).toEqual(["shop/cart"]);
  });
});

describe("migrationStage with a MeshContext", () => {
  it("assumes a planned migration only for the run that asks, never for the store", async () => {
    const store = await buildStore({ resources: [namespace("legacy", { "istio-injection": "enabled" }), sidecarPod("legacy", "a", "1.27.1")] });
    expect(migrationStage(store, { assumeMigration: true })).toBe("planned");
    expect(migrationStage(store)).toBe("none");
    expect(migrationStage(store, {})).toBe("none");
    expect(observedMigrationStage(store)).toBe("none");
  });
});

describe("mesh model on a large archive", () => {
  it("indexes pods and services so per-object lookups stay fast (20k pods, 5k services, 2k VS)", async () => {
    const store = await buildStore({ resources: [] });
    const items: Obj[] = [];
    const namespaces = 100;
    for (let n = 0; n < namespaces; n++) items.push(namespace(`ns-${n}`, n % 2 ? AMBIENT : { "istio-injection": "enabled" }), rootCa(`ns-${n}`));
    for (let i = 0; i < 20_000; i++) items.push(i % 2 ? ambientPod(`ns-${i % namespaces}`, `p-${i}`, { app: `app-${i % 5_000}` }) : pod(`ns-${i % namespaces}`, `p-${i}`, { app: `app-${i % 5_000}` }));
    for (let s = 0; s < 5_000; s++) items.push(service(`ns-${s % namespaces}`, `svc-${s}`, { app: `app-${s}` }));
    for (let v = 0; v < 2_000; v++) {
      items.push({ apiVersion: "networking.istio.io/v1", kind: "VirtualService", metadata: { name: `vs-${v}`, namespace: `ns-${v % namespaces}` }, spec: { hosts: [`svc-${v}`, `svc-${v + 1}.ns-${(v + 1) % namespaces}.svc.cluster.local`] } });
    }
    injectResources(store, items);

    const start = performance.now();
    let links = 0;
    for (const p of livePods(store)) {
      podMode(store, p);
      links += servicesOfPod(store, p).length;
    }
    for (const s of store.getClusterResources({ kind: "Service", group: "" })) {
      serviceDataplane(store, s);
      links += podsOfService(store, s).length;
    }
    for (const vs of store.getClusterResources({ kind: "VirtualService" })) {
      for (const h of vs.spec?.hosts as string[]) links += resolveHost(store, h, vs.metadata.namespace!).length;
    }
    for (let n = 0; n < namespaces; n++) links += podsSelectedBy(store, `ns-${n}`, undefined).length;
    expect(links).toBeGreaterThan(0);
    expect(performance.now() - start).toBeLessThan(3_000);
  });

  it("servicesOfPod and podsSelectedBy keep selector semantics", async () => {
    const resources = [namespace("a"), pod("a", "x", { app: "x", tier: "web" }), pod("a", "y", { app: "y" }), service("a", "both", { tier: "web" }), service("a", "x", { app: "x", tier: "web" }), service("a", "none", undefined), service("a", "other", { app: "x", tier: "db" })];
    const store = await buildStore({ resources });
    expect(servicesOfPod(store, asResource(resources[1])).map((s) => s.metadata.name)).toEqual(["both", "x"]);
    expect(podsSelectedBy(store, "a", { app: "x" }).map((p) => p.metadata.name)).toEqual(["x"]);
    expect(podsSelectedBy(store, "a", undefined).map((p) => p.metadata.name)).toEqual(["x", "y"]);
    expect(podsSelectedBy(store, "a", {}).map((p) => p.metadata.name)).toEqual(["x", "y"]);
  });
});

describe("namespaceMode by the injector webhooks", () => {
  const ambientRev = (rev: string) => namespace("shop", { ...AMBIENT, "istio.io/rev": rev });

  it("an istio.io/rev label no injector serves does not inject: the namespace stays ambient", async () => {
    const store = await buildStore({ resources: [injectorWebhook("1-30"), ambientRev("1-27"), ambientPod("shop", "cart")] });
    expect(namespaceMode(store, "shop")).toBe("ambient");
    expect(revisionLabelUnserved(store, "shop")).toBe(true);
    expect(podMode(store, livePods(store).find((p) => p.metadata.name === "cart")!)).toBe("ambient");
  });

  it("a revision an injector serves injects: dual", async () => {
    const store = await buildStore({ resources: [injectorWebhook("1-27"), ambientRev("1-27"), ambientPod("shop", "cart")] });
    expect(namespaceMode(store, "shop")).toBe("dual");
    expect(revisionLabelUnserved(store, "shop")).toBe(false);
  });

  it("istio-injection=enabled is injected by the default revision's webhook, and by nothing without one", async () => {
    const enabled = namespace("legacy", { "istio-injection": "enabled" });
    expect(namespaceMode(await buildStore({ resources: [injectorWebhook(""), enabled] }), "legacy")).toBe("sidecar");
    expect(namespaceMode(await buildStore({ resources: [injectorWebhook("1-30"), enabled] }), "legacy")).toBe("none");
  });

  it("falls back to the label rule when no MutatingWebhookConfiguration was collected", async () => {
    const store = await buildStore({ resources: [ambientRev("1-27"), ambientPod("shop", "cart")] });
    expect(namespaceMode(store, "shop")).toBe("dual");
    expect(revisionLabelUnserved(store, "shop")).toBe(false);
  });
});

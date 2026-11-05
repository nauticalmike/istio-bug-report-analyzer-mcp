import { describe, it, expect, afterEach } from "vitest";
import { istiodEnv, podDumpCovers, resolveHost, serviceDataplane } from "../../src/diagnostics/mesh-model.js";
import type { ParsedResource } from "../../src/types.js";
import { ambientPod, buildStore, cleanupArchives, namespace, service, sidecarPod, type Obj } from "./template-harness.js";
import { AMBIENT_NS, istiodDeployment, serviceEntry } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const ids = (rs: ParsedResource[]) => rs.map((r) => `${r.kind}:${r.metadata.namespace}/${r.metadata.name}`).sort();

describe("resolveHost", () => {
  const resources: Obj[] = [
    service("shop", "cart", { app: "cart" }),
    service("shop", "pay", { app: "pay" }),
    service("bank", "cart", { app: "cart" }),
    serviceEntry("shop", "ext", ["api.example.com", "*.partner.example.org"]),
  ];

  it("resolves short names against the referring namespace, as istiod does", async () => {
    const store = await buildStore({ resources });
    expect(ids(resolveHost(store, "cart", "shop"))).toEqual(["Service:shop/cart"]);
    expect(ids(resolveHost(store, "cart", "bank"))).toEqual(["Service:bank/cart"]);
    expect(resolveHost(store, "cart", "other")).toEqual([]);
  });

  it("resolves FQDNs, but not name.namespace or name.namespace.svc (istiod treats a dotted host as an FQDN)", async () => {
    const store = await buildStore({ resources });
    expect(ids(resolveHost(store, "cart.bank.svc.cluster.local", "shop"))).toEqual(["Service:bank/cart"]);
    expect(resolveHost(store, "cart.bank.svc", "shop")).toEqual([]);
    expect(resolveHost(store, "cart.bank", "shop")).toEqual([]);
  });

  it("resolves namespace wildcards and ServiceEntry hosts, and ignores the bare * host", async () => {
    const store = await buildStore({ resources });
    expect(ids(resolveHost(store, "*.shop.svc.cluster.local", "x"))).toEqual(["Service:shop/cart", "Service:shop/pay"]);
    expect(ids(resolveHost(store, "api.example.com", "x"))).toEqual(["ServiceEntry:shop/ext"]);
    expect(ids(resolveHost(store, "v1.partner.example.org", "x"))).toEqual(["ServiceEntry:shop/ext"]);
    expect(resolveHost(store, "*", "shop")).toEqual([]);
  });
});

describe("serviceDataplane", () => {
  it("uses the selected pods first, then the namespace mode", async () => {
    const resources: Obj[] = [
      namespace("amb", AMBIENT_NS),
      namespace("inj", { "istio-injection": "enabled" }),
      namespace("plain"),
      service("amb", "a", { app: "a" }),
      service("inj", "b", { app: "b" }),
      service("plain", "c", { app: "c" }),
      service("plain", "d", { app: "d" }),
      ambientPod("plain", "d", { app: "d" }),
      sidecarPod("inj", "b", "1.31.2", { app: "b" }),
    ];
    const store = await buildStore({ resources });
    const mode = (i: number) => serviceDataplane(store, resources[i] as unknown as ParsedResource);
    expect(mode(3)).toBe("ambient");
    expect(mode(4)).toBe("sidecar");
    expect(mode(5)).toBe("none");
    expect(mode(6)).toBe("ambient");
  });
});

describe("istiodEnv and podDumpCovers", () => {
  it("reads env values from istiod Deployments", async () => {
    const store = await buildStore({ resources: [istiodDeployment({ ENABLE_INGRESS_WAYPOINT_ROUTING: "false" })] });
    expect(istiodEnv(store, "ENABLE_INGRESS_WAYPOINT_ROUTING")).toEqual(["false"]);
    expect(istiodEnv(store, "UNSET")).toEqual([]);
  });

  it("covers namespaces with objects in the pod dump", async () => {
    const store = await buildStore({ resources: [namespace("amb", AMBIENT_NS), ambientPod("amb", "api")] });
    expect(podDumpCovers(store, "amb")).toBe(true);
    // Every Namespace object has objects in the dump: a whole-cluster dump, so a namespace
    // with no objects has no pods to miss.
    expect(podDumpCovers(store, "elsewhere")).toBe(true);
    const scoped = await buildStore({ resources: [namespace("amb", AMBIENT_NS), namespace("left-out"), ambientPod("amb", "api")] });
    expect(podDumpCovers(scoped, "left-out")).toBe(false);
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, namespace, sidecarPod, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, INJECTED_NS, crs, istioResource, runCheck, runCheckAssumed, ztunnelDaemonSet } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

const run = (resources: Obj[], files: Record<string, string | null>, meshDebug?: Obj) => runCheck("DIAG-010", "security", { resources, files, meshDebug });

const ambientShop = [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];
const registryOnly = { rootNamespace: "istio-system", outboundTrafficPolicy: { mode: "REGISTRY_ONLY" } };
const vs = istioResource("networking.istio.io/v1", "VirtualService", "shop", "vs", { hosts: ["cart"] });

const sidecarCr = (ns: string, name: string, spec: Obj) => istioResource("networking.istio.io/v1", "Sidecar", ns, name, spec);
const serviceEntry = (ns: string, name: string, spec: Obj, status?: Obj) => istioResource("networking.istio.io/v1", "ServiceEntry", ns, name, spec, status);

describe("DIAG-010 egress lockdown and Sidecar scoping lost in ambient", () => {
  it("flags a mesh-wide REGISTRY_ONLY that ambient workloads ignore", async () => {
    const { f } = await run(ambientShop, crs(vs), registryOnly);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/^meshConfig outboundTrafficPolicy REGISTRY_ONLY .*not enforced.*shop/);
  });

  it("reads REGISTRY_ONLY from protojson debug/mesh, which omits the zero enum (outboundTrafficPolicy: {})", async () => {
    const { f } = await run(ambientShop, crs(vs), { rootNamespace: "istio-system", outboundTrafficPolicy: {} });
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/^meshConfig outboundTrafficPolicy REGISTRY_ONLY/);
  });

  it("is a migration-blocker warning when no workload is ambient yet", async () => {
    const resources = [ztunnelDaemonSet(), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")];
    const { f } = await run(resources, crs(vs), registryOnly);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toMatch(/migrat/);
  });

  it("flags a Sidecar with REGISTRY_ONLY in an ambient namespace as critical", async () => {
    const sc = sidecarCr("shop", "lockdown", { outboundTrafficPolicy: { mode: "REGISTRY_ONLY" }, egress: [{ hosts: ["./*"] }] });
    const { f } = await run(ambientShop, crs(sc));
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/^shop\/lockdown: Sidecar .*REGISTRY_ONLY/);
  });

  it("reports a plain scoping Sidecar selecting ambient pods as info (ignored, no lockdown lost)", async () => {
    const sc = sidecarCr("shop", "scope", { egress: [{ hosts: ["./*", "istio-system/*"] }] });
    const { f } = await run(ambientShop, crs(sc));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^shop\/scope: Sidecar .*ignored/);
  });

  it("flags ServiceEntry exportTo, which ambient does not honor", async () => {
    const se = serviceEntry("shop", "partner-api", { hosts: ["api.partner.example"], exportTo: ["."], ports: [{ number: 443, name: "tls", protocol: "TLS" }], resolution: "DNS" });
    const { f } = await run(ambientShop, crs(se));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^1 ServiceEntry with exportTo \[\.\] \(shop\/partner-api\): exportTo is not honored/);
  });

  it("groups ServiceEntries by exportTo value", async () => {
    const ses = ["a", "b", "c", "d", "e", "f"].map((n) => serviceEntry("shop", `se-${n}`, { hosts: [`${n}.example`], exportTo: ["."], resolution: "DNS" }));
    const { f } = await run(ambientShop, crs(...ses));
    expect(f?.affectedResources).toHaveLength(1);
    expect(f?.affectedResources[0]).toMatch(/^6 ServiceEntries with exportTo \[\.\] \(shop\/se-a, .*shop\/se-e, \+1 more\)/);
  });

  it("flags ServiceEntry exportTo when a migration is assumed for a sidecar-only mesh", async () => {
    const se = serviceEntry("legacy", "partner-api", { hosts: ["api.partner.example"], exportTo: ["."], resolution: "DNS" });
    const { f } = await runCheckAssumed("DIAG-010", "security", { resources: [namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")], files: crs(se) });
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^1 ServiceEntry with exportTo \[\.\] \(legacy\/partner-api\)/);
  });

  it("groups one Sidecar copied into several ambient namespaces into one line", async () => {
    const lock = { outboundTrafficPolicy: { mode: "REGISTRY_ONLY" }, egress: [{ hosts: ["./*"] }] };
    const names = ["a1", "a2"];
    const resources = names.flatMap((n) => [namespace(n, AMBIENT_NS), ambientPod(n, "cart", { app: "cart" })]);
    const { f } = await run(resources, crs(...names.map((n) => sidecarCr(n, "default", lock))));
    expect(f?.affectedResources).toHaveLength(1);
    expect(f?.affectedResources[0]).toMatch(/^Sidecar default in 2 namespaces \(a1, a2\): Sidecar with outboundTrafficPolicy REGISTRY_ONLY/);
  });

  it("flags a wildcard ServiceEntry that is not bound to a waypoint", async () => {
    const se = serviceEntry("shop", "any-partner", { hosts: ["*.partner.example"], ports: [{ number: 443, name: "tls", protocol: "TLS" }], resolution: "DYNAMIC_DNS" });
    const { f } = await run(ambientShop, crs(se));
    expect(f?.affectedResources[0]).toMatch(/^shop\/any-partner: wildcard host/);
  });

  describe("does not fire on correct configurations", () => {
    it("REGISTRY_ONLY in a sidecar-only mesh", async () => {
      const { f, skipped } = await run([namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")], crs(vs), registryOnly);
      expect(f).toBeUndefined();
      expect(skipped).toBeUndefined();
    });

    it("a scoping Sidecar in a sidecar namespace of a partly ambient mesh", async () => {
      const sc = sidecarCr("legacy", "scope", { egress: [{ hosts: ["./*"] }] });
      const resources = [...ambientShop, namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")];
      const { f } = await run(resources, crs(sc));
      expect(f).toBeUndefined();
    });

    it("a catch-all Sidecar (egress */*, no ingress, no outboundTrafficPolicy): nothing is lost", async () => {
      const sc = sidecarCr("shop", "default", { egress: [{ hosts: ["*/*"] }] });
      const { f } = await run(ambientShop, crs(sc), registryOnly);
      const details = f?.affectedResources.join("\n") ?? "";
      expect(details).toMatch(/^meshConfig outboundTrafficPolicy REGISTRY_ONLY/);
      expect(details).not.toMatch(/shop\/default/);
    });

    it("ServiceEntry exportTo while ztunnel is installed but no workload is ambient (nothing consumes it in ambient)", async () => {
      const se = serviceEntry("legacy", "partner-api", { hosts: ["api.partner.example"], exportTo: ["."], resolution: "DNS" });
      const { f } = await run([ztunnelDaemonSet(), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")], crs(se));
      expect(f).toBeUndefined();
    });

    it("a workload-scoped Sidecar in the root namespace (it is not mesh-wide)", async () => {
      const sc = sidecarCr("istio-system", "gw-scope", { workloadSelector: { labels: { app: "cart" } }, outboundTrafficPolicy: { mode: "REGISTRY_ONLY" } });
      const { f } = await run(ambientShop, crs(sc));
      expect(f).toBeUndefined();
    });

    it("exportTo when meshConfig.serviceEntryVisibility governs ambient visibility", async () => {
      const se = serviceEntry("shop", "partner-api", { hosts: ["api.partner.example"], exportTo: ["."], resolution: "DNS" });
      const { f } = await run(ambientShop, crs(se), { rootNamespace: "istio-system", serviceEntryVisibility: { defaultVisibility: "NAMESPACE" } });
      expect(f).toBeUndefined();
    });

    it("a wildcard ServiceEntry bound to an egress waypoint", async () => {
      const se = { ...serviceEntry("egress", "any-partner", { hosts: ["*.partner.example"], resolution: "DYNAMIC_DNS" }), metadata: { name: "any-partner", namespace: "egress", labels: { "istio.io/use-waypoint": "egress-waypoint" } } };
      const { f } = await run([...ambientShop, namespace("egress", AMBIENT_NS)], crs(waypoint("egress", "egress-waypoint"), se));
      expect(f).toBeUndefined();
    });
  });

  describe("missing input", () => {
    it("is not evaluated without cluster/crs", async () => {
      const { f, skipped } = await run(ambientShop, { "cluster/crs": null }, registryOnly);
      expect(f).toBeUndefined();
      expect(skipped?.reason).toBe("not evaluated: cluster/crs missing (data completeness: crs)");
    });

    it("is not evaluated without cluster/k8s-resources", async () => {
      const { f, skipped } = await run([], { ...crs(vs), "cluster/k8s-resources": null }, registryOnly);
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/^not evaluated: cluster\/k8s-resources missing/);
    });
  });
});

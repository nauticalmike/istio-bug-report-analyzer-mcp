import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, pod, runEngine, sidecarPod, type Obj } from "./template-harness.js";
import { AMBIENT_NS, peerAuthentication, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

function annotated(p: Obj, annotations: Record<string, string>): Obj {
  const meta = p.metadata as { annotations?: Record<string, string> };
  return { ...p, metadata: { ...meta, annotations: { ...(meta.annotations ?? {}), ...annotations } } };
}

/** What the injector writes with istio-cni and the default values. */
const INJECTOR_DEFAULTS = {
  "sidecar.istio.io/status": '{"containers":["istio-proxy"]}',
  "sidecar.istio.io/interceptionMode": "REDIRECT",
  "traffic.sidecar.istio.io/includeOutboundIPRanges": "*",
  "traffic.sidecar.istio.io/includeInboundPorts": "*",
  "traffic.sidecar.istio.io/excludeInboundPorts": "15020",
};

async function run(resources: Obj[], files?: Record<string, string | null>, meshDebug?: Obj) {
  const { findings, engine } = await runEngine({ resources, files, meshDebug }, ["sidecar-to-ambient"]);
  return { f: finding(findings, "DIAG-016"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-016") };
}

describe("DIAG-016 capture customizations ambient ignores", () => {
  it("reports outbound exclusions on ambient pods as info, grouped by value", async () => {
    const excl = { "traffic.sidecar.istio.io/excludeOutboundIPRanges": "10.96.0.0/12" };
    const { f } = await run([
      ztunnelDaemonSet(),
      namespace("shop", AMBIENT_NS),
      annotated(ambientPod("shop", "cart"), excl),
      annotated(ambientPod("shop", "pay"), excl),
    ]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([
      expect.stringMatching(/^traffic.sidecar.istio.io\/excludeOutboundIPRanges="10.96.0.0\/12" on 2 ambient pods \(shop: cart, pay\): ignored by ztunnel; .*passthrough/),
    ]);
    expect(f?.issues?.[0].namespace).toBe("shop");
  });

  it("reports non-default outbound capture annotations on sidecar pods once ztunnel is installed (info)", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), { ...INJECTOR_DEFAULTS, "traffic.sidecar.istio.io/includeOutboundIPRanges": "10.0.0.0/8" });
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), p]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^traffic.sidecar.istio.io\/includeOutboundIPRanges="10.0.0.0\/8" on 1 sidecar pod \(legacy: api\): .*move to ambient/)]);
  });

  it("does not flag the injector's default capture annotations", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), INJECTOR_DEFAULTS);
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), p]);
    expect(f).toBeUndefined();
  });

  it("warns on TPROXY interception and notes lifecycle-only proxy.istio.io/config as no longer needed", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), { ...INJECTOR_DEFAULTS, "sidecar.istio.io/interceptionMode": "TPROXY", "proxy.istio.io/config": "concurrency: 4" });
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), p]);
    expect(f?.issues?.map((i) => [i.severity, i.detail])).toEqual([
      ["warning", expect.stringMatching(/^sidecar.istio.io\/interceptionMode="TPROXY"/)],
      ["info", expect.stringMatching(/^proxy.istio.io\/config="concurrency: 4" .*only lifecycle settings; no longer needed/)],
    ]);
  });

  it("warns on proxy.istio.io/config keys that change traffic", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), { ...INJECTOR_DEFAULTS, "proxy.istio.io/config": "concurrency: 2\nproxyMetadata:\n  ISTIO_META_DNS_CAPTURE: \"true\"" });
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), p]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/sets proxyMetadata.ISTIO_META_DNS_CAPTURE/)]);
  });

  it("notes proxy.istio.io/config equal to meshConfig.defaultConfig as no longer needed", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), { ...INJECTOR_DEFAULTS, "proxy.istio.io/config": "tracing:\n  sampling: 1" });
    const mesh = { rootNamespace: "istio-system", defaultConfig: { discoveryAddress: "istiod.istio-system.svc:15012", tracing: { sampling: 1 } } };
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), p], undefined, mesh);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/equals meshConfig.defaultConfig; no longer needed/)]);
  });

  it("judges inbound exclusions on ambient pods by the effective PeerAuthentication", async () => {
    const excl = annotated(ambientPod("shop", "cart"), { "traffic.sidecar.istio.io/excludeInboundPorts": "8080" });
    const base = [ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), excl];
    const permissive = await run(base);
    expect(permissive.f?.severity).toBe("warning");
    expect(permissive.f?.affectedResources).toEqual([expect.stringMatching(/PERMISSIVE: plaintext still accepted/)]);

    const strictMesh = peerAuthentication("istio-system", "default", { mtls: { mode: "STRICT" } });
    const strict = await run([...base, strictMesh]);
    expect(strict.f?.severity).toBe("critical");
    expect(strict.f?.affectedResources).toEqual([expect.stringMatching(/STRICT PeerAuthentication .*port 8080/)]);

    const exempt = peerAuthentication("shop", "cart-8080", { selector: { matchLabels: { app: "cart" } }, mtls: { mode: "STRICT" }, portLevelMtls: { "8080": { mode: "PERMISSIVE" } } });
    const exempted = await run([...base, strictMesh, exempt]);
    expect(exempted.f?.severity).toBe("info");
    expect(exempted.f?.affectedResources).toEqual([expect.stringMatching(/port-level PeerAuthentication exemption/)]);
  });

  it("says when PeerAuthentication cannot be read (no cluster/crs) instead of guessing the mode", async () => {
    const excl = annotated(ambientPod("shop", "cart"), { "traffic.sidecar.istio.io/excludeInboundPorts": "8080" });
    const { f } = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), excl], { "cluster/crs": null });
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/PeerAuthentication not collected/)]);
  });

  it("namespace PeerAuthentication overrides the mesh-wide one", async () => {
    const excl = annotated(ambientPod("shop", "cart"), { "traffic.sidecar.istio.io/excludeInboundPorts": "8080" });
    const { f } = await run([
      ztunnelDaemonSet(),
      namespace("shop", AMBIENT_NS),
      excl,
      peerAuthentication("istio-system", "default", { mtls: { mode: "PERMISSIVE" } }),
      peerAuthentication("shop", "strict", { mtls: { mode: "STRICT" } }),
    ]);
    expect(f?.severity).toBe("critical");
  });

  it("does not count the pod's own status port (status.sidecar.istio.io/port) as an exclusion", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), { ...INJECTOR_DEFAULTS, "status.sidecar.istio.io/port": "16021", "traffic.sidecar.istio.io/excludeInboundPorts": "16021" });
    const { f } = await run([ztunnelDaemonSet(), namespace("legacy", { "istio-injection": "enabled" }), p]);
    expect(f).toBeUndefined();
  });

  it("reports deliberate sidecars (sidecar.istio.io/inject=true) in ambient namespaces as info", async () => {
    const p = annotated(sidecarPod("shop", "legacy-api", "1.31.2", { app: "legacy-api", "sidecar.istio.io/inject": "true" }), { "traffic.sidecar.istio.io/excludeInboundPorts": "8080" });
    const { f } = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart"), p, peerAuthentication("istio-system", "default", { mtls: { mode: "STRICT" } })]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/deliberate sidecar/)]);
  });

  it("reports host-network pods in ambient namespaces as info, grouped by owner", async () => {
    const hostNet = (name: string, owner?: Obj) => ({
      ...pod("shop", name, { app: "agent" }),
      metadata: { name, namespace: "shop", labels: { app: "agent" }, ...(owner ? { ownerReferences: [owner] } : {}) },
      spec: { hostNetwork: true, containers: [{ name: "agent" }] },
    });
    const ds = { apiVersion: "apps/v1", kind: "DaemonSet", name: "node-agent" };
    const rs = { apiVersion: "apps/v1", kind: "ReplicaSet", name: "edge-proxy-6f7d8c9b5" };
    const { f } = await run([
      ztunnelDaemonSet(),
      namespace("shop", AMBIENT_NS),
      ambientPod("shop", "cart"),
      hostNet("node-agent-a1", ds),
      hostNet("node-agent-b2", ds),
      hostNet("edge-proxy-6f7d8c9b5-x1", rs),
      hostNet("standalone"),
    ]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([
      expect.stringMatching(/^hostNetwork: true on DaemonSet shop\/node-agent \(2 pods\): never captured/),
      expect.stringMatching(/^hostNetwork: true on Deployment shop\/edge-proxy \(1 pod\)/),
      expect.stringMatching(/^hostNetwork: true on Pod shop\/standalone \(1 pod\)/),
    ]);
  });

  it("does not run on a mesh with no ambient footprint", async () => {
    const p = annotated(sidecarPod("legacy", "api", "1.31.2"), { ...INJECTOR_DEFAULTS, "traffic.sidecar.istio.io/includeOutboundIPRanges": "10.0.0.0/8" });
    const { f } = await run([namespace("legacy", { "istio-injection": "enabled" }), p]);
    expect(f).toBeUndefined();
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { f, skipped } = await run([ztunnelDaemonSet()], { "cluster/k8s-resources": null });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/k8s-resources/);
  });
});

describe("DIAG-016 aggregation", () => {
  it("lists every group (the tools cap what they print)", async () => {
    const pods = Array.from({ length: 25 }, (_, i) => annotated(ambientPod("shop", `app-${i}`), { "traffic.sidecar.istio.io/excludeOutboundPorts": String(9000 + i) }));
    const { f } = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ...pods]);
    expect(f?.affectedResources).toHaveLength(25);
    expect(f?.affectedResources.some((d) => d.includes("more)"))).toBe(false);
  });
});

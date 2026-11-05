import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, deployment, namespace, pod, sidecarPod, type Obj } from "./template-harness.js";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { AMBIENT_NS, INJECTED_NS, crs, istioResource, node, nodes, runCheck, runCheckAssumed, workloadEntry, ztunnelDaemonSet } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

const run = (resources: Obj[], files: Record<string, string | null>) => runCheck("DIAG-011", "sidecar-to-ambient", { resources, files });

const ambientShop = [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];
const vs = istioResource("networking.istio.io/v1", "VirtualService", "shop", "vs", { hosts: ["cart"] });
const peerAuth = (ns: string, name: string, spec: Obj) => istioResource("security.istio.io/v1", "PeerAuthentication", ns, name, spec);

describe("DIAG-011 hard migration blockers", () => {
  it("reports top-level mtls.mode DISABLE as info: ztunnel treats it as PERMISSIVE", async () => {
    const { f } = await run(ambientShop, crs(peerAuth("shop", "plain", { mtls: { mode: "DISABLE" } })));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^shop\/plain: PeerAuthentication mtls.mode DISABLE behaves as PERMISSIVE/);
    expect(f?.issues?.[0].namespace).toBe("shop");
  });

  it("reports a selector STRICT policy with a port-level DISABLE as an honored port exemption (info)", async () => {
    // convertPeerAuthentication (pilot/pkg/serviceregistry/ambient/authorization.go) turns it into a port exemption.
    const port = peerAuth("shop", "metrics-port", { selector: { matchLabels: { app: "cart" } }, mtls: { mode: "STRICT" }, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const { f } = await run(ambientShop, crs(port));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^shop\/metrics-port: .*portLevelMtls 9090 DISABLE is honored as a port exemption/);
  });

  // Never honored with sidecars either, so it is reported as info, not as a migration blocker.
  it("notes port-level settings on a namespace-wide policy, which no data plane honors", async () => {
    const nsWide = peerAuth("shop", "ns-ports", { mtls: { mode: "STRICT" }, portLevelMtls: { "9090": { mode: "PERMISSIVE" } } });
    const { f } = await run(ambientShop, crs(nsWide));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^shop\/ns-ports: portLevelMtls .*without a selector is dropped/);
  });

  it("notes port-level settings on a root-namespace selector policy (sidecar pods, ztunnel installed)", async () => {
    const root = peerAuth("istio-system", "gw-ports", { selector: { matchLabels: { app: "gw" } }, mtls: { mode: "STRICT" }, portLevelMtls: { "8443": { mode: "DISABLE" } } });
    const resources = [ztunnelDaemonSet(), namespace("istio-system"), sidecarPod("istio-system", "gw", "1.31.2", { app: "gw" })];
    const { f } = await run(resources, crs(root));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^istio-system\/gw-ports: .*root namespace/);
  });

  it("flags WorkloadGroups and the WorkloadEntries auto-registered from them (VM workloads)", async () => {
    const auto = workloadEntry("vms", "legacy-10.1.0.5", { annotations: { "istio.io/autoRegistrationGroup": "legacy", "istio.io/workloadController": "istiod-1" } });
    const owned = workloadEntry("vms", "legacy-10.1.0.6", { ownerKind: "WorkloadGroup" });
    const wg = istioResource("networking.istio.io/v1", "WorkloadGroup", "vms", "legacy", { template: { serviceAccount: "legacy" } });
    const { f } = await run(ambientShop, crs(auto, owned, wg));
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toMatch(/^WorkloadEntry\/WorkloadGroup: vms: legacy, legacy-10.1.0.5, legacy-10.1.0.6: VM workloads/);
    expect(f?.issues?.[0].namespace).toBe("vms");
  });

  it("reports a hand-written WorkloadEntry as info: ambient supports it as an endpoint without HBONE", async () => {
    const { f } = await run(ambientShop, crs(workloadEntry("ext", "db-1")));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^WorkloadEntry: ext: db-1: /);
  });

  it("skips WorkloadEntries that are ambient or multicluster peering entries", async () => {
    const hbone = workloadEntry("ext", "hbone", { labels: { "networking.istio.io/tunnel": "http" } });
    const redirected = workloadEntry("ext", "captured", { annotations: { "ambient.istio.io/redirection": "enabled" } });
    const peer = workloadEntry("istio-system", "autogen.remote.cart");
    const flat = workloadEntry("istio-system", "autogenflat.cluster-2.shop.cart-5d8f");
    const { f, skipped } = await run(ambientShop, crs(hbone, redirected, peer, flat));
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("flags SPIRE agents and pods mounting the SPIFFE CSI driver", async () => {
    const agent = { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name: "spire-agent", namespace: "spire" }, spec: { template: { spec: { containers: [{ name: "agent", image: "ghcr.io/spiffe/spire-agent:1.9.0" }] } } } };
    const csiPod = { ...pod("legacy", "api", { app: "api" }), spec: { containers: [{ name: "app" }], volumes: [{ name: "spiffe", csi: { driver: "csi.spiffe.io", readOnly: true } }] } };
    const { f } = await run([...ambientShop, agent, csiPod], crs(vs));
    const details = f?.affectedResources.join("\n") ?? "";
    expect(details).toMatch(/SPIRE: .*spire\/spire-agent/);
    expect(details).toMatch(/legacy\/api/);
  });

  it("reports SPIRE only as info on Solo builds, which support it in ambient", async () => {
    const agent = { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name: "spire-agent", namespace: "spire" }, spec: { template: { spec: { containers: [{ name: "agent", image: "ghcr.io/spiffe/spire-agent:1.9.0" }] } } } };
    const { f } = await runCheck("DIAG-011", "sidecar-to-ambient", { resources: [...ambientShop, agent], files: crs(vs), versions: bugReportVersions("1.30.2-solo") });
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/spire.enabled/);
  });

  it("flags a primary-remote topology (EXTERNAL_ISTIOD, or an injector webhook served by URL)", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", env: [{ name: "EXTERNAL_ISTIOD", value: "true" }] }] });
    const mwc = {
      apiVersion: "admissionregistration.k8s.io/v1",
      kind: "MutatingWebhookConfiguration",
      metadata: { name: "istio-sidecar-injector", labels: { app: "sidecar-injector" } },
      webhooks: [{ name: "namespace.sidecar-injector.istio.io", clientConfig: { url: "https://istiod.remote.example:15017/inject" } }],
    };
    const { f } = await run([...ambientShop, istiod, mwc], crs(vs));
    const details = f?.affectedResources.join("\n") ?? "";
    expect(details).toMatch(/istio-system\/istiod: EXTERNAL_ISTIOD=true/);
    expect(details).toMatch(/istio-sidecar-injector: .*url/);
  });

  it("flags nodes ztunnel cannot run on: untolerated taints, Windows, serverless", async () => {
    const ds = ztunnelDaemonSet([{ key: "CriticalAddonsOnly", operator: "Exists" }]);
    const cartOnGpu = { ...ambientPod("shop", "cart", { app: "cart" }), spec: { nodeName: "gpu-1", containers: [{ name: "app" }] } };
    const files = {
      ...crs(vs),
      ...nodes(
        node("worker-1"),
        node("gpu-1", {}, [{ key: "nvidia.com/gpu", value: "present", effect: "NoSchedule" }]),
        node("win-1", { "kubernetes.io/os": "windows" }),
        node("fargate-ip-1", { "eks.amazonaws.com/compute-type": "fargate" }),
      ),
    };
    const { f } = await run([namespace("shop", AMBIENT_NS), cartOnGpu, ds], files);
    const details = f?.affectedResources.join("\n") ?? "";
    expect(details).toMatch(/gpu-1: taint nvidia.com\/gpu=present:NoSchedule not tolerated by ztunnel; 1 ambient pod runs there/);
    expect(details).toMatch(/win-1: Windows node/);
    expect(details).toMatch(/fargate-ip-1: serverless/);
    expect(details).not.toMatch(/worker-1/);
    // An ambient pod on a node without ztunnel is not captured: critical.
    expect(f?.severity).toBe("critical");
  });

  it("reports Windows and serverless nodes with no ztunnel DaemonSet yet, assuming the chart's default tolerations", async () => {
    const files = {
      ...crs(vs),
      ...nodes(node("worker-1"), node("win-1", { "kubernetes.io/os": "windows" }), node("fargate-ip-1", { "eks.amazonaws.com/compute-type": "fargate" }), node("gpu-1", {}, [{ key: "nvidia.com/gpu", value: "present", effect: "NoSchedule" }])),
    };
    const { f } = await runCheckAssumed("DIAG-011", "sidecar-to-ambient", { resources: [namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")], files });
    const details = f?.affectedResources.join("\n") ?? "";
    expect(f?.severity).toBe("warning");
    expect(details).toMatch(/win-1: Windows node/);
    expect(details).toMatch(/fargate-ip-1: serverless/);
    expect(details).toMatch(/default tolerations/);
    expect(details).not.toMatch(/gpu-1|worker-1/);
  });

  it("groups nodes with the same blocker and no ambient pods into one line", async () => {
    const files = { ...crs(vs), ...nodes(node("win-1", { "kubernetes.io/os": "windows" }), node("win-2", { "kubernetes.io/os": "windows" })) };
    const { f } = await run([...ambientShop, ztunnelDaemonSet()], files);
    expect(f?.affectedResources).toHaveLength(1);
    expect(f?.affectedResources[0]).toMatch(/^2 nodes \(win-1, win-2\): Windows node/);
  });

  describe("does not fire on correct configurations", () => {
    it("STRICT and PERMISSIVE PeerAuthentication on ambient pods", async () => {
      const { f, skipped } = await run(ambientShop, crs(peerAuth("shop", "strict", { mtls: { mode: "STRICT" } }), peerAuth("istio-system", "mesh", { mtls: { mode: "PERMISSIVE" } })));
      expect(f).toBeUndefined();
      expect(skipped).toBeUndefined();
    });

    it("PeerAuthentication DISABLE in a sidecar-only mesh", async () => {
      const { f, skipped } = await run([namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2")], crs(peerAuth("legacy", "plain", { mtls: { mode: "DISABLE" } })));
      expect(f).toBeUndefined();
      expect(skipped).toBeUndefined();
    });

    it("tainted nodes the default ztunnel tolerations cover", async () => {
      const files = { ...crs(vs), ...nodes(node("gpu-1", {}, [{ key: "nvidia.com/gpu", value: "present", effect: "NoSchedule" }])) };
      const { f } = await run([...ambientShop, ztunnelDaemonSet()], files);
      expect(f).toBeUndefined();
    });
  });

  describe("missing input", () => {
    it("is not evaluated without cluster/crs", async () => {
      const { f, skipped } = await run(ambientShop, { "cluster/crs": null });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toBe("not evaluated: cluster/crs missing (data completeness: crs)");
    });

    it("still runs the node, SPIRE and primary-remote rules without cluster/crs, and says what was left out", async () => {
      const files = { "cluster/crs": null, ...nodes(node("win-1", { "kubernetes.io/os": "windows" })) };
      const { f, skipped } = await run([...ambientShop, ztunnelDaemonSet()], files);
      expect(skipped).toBeUndefined();
      const details = f?.affectedResources.join("\n") ?? "";
      expect(details).toMatch(/win-1: Windows node/);
      expect(details).toMatch(/PeerAuthentication and WorkloadEntry\/WorkloadGroup rules not evaluated: cluster\/crs missing/);
    });

    it("is not evaluated without cluster/k8s-resources", async () => {
      const { f, skipped } = await run([], { ...crs(peerAuth("shop", "plain", { mtls: { mode: "DISABLE" } })), "cluster/k8s-resources": null });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/^not evaluated: cluster\/k8s-resources missing/);
    });
  });
});

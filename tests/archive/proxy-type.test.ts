import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BugReportStore } from "../../src/archive/store.js";

// Envoy config_dump: the BootstrapConfigDump comes first and carries the node id `<type>~<ip>~<pod>.<ns>~<domain>`.
function envoyDump(nodeType: string, pod: string, ns: string): string {
  return JSON.stringify(
    {
      configs: [
        {
          "@type": "type.googleapis.com/envoy.admin.v3.BootstrapConfigDump",
          bootstrap: { node: { id: `${nodeType}~10.0.0.1~${pod}.${ns}~${ns}.svc.cluster.local`, cluster: `${pod}.${ns}` } },
        },
        { "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump", dynamic_listeners: [] },
      ],
    },
    null,
    2,
  );
}

const ZTUNNEL_DUMP = JSON.stringify({ certificates: [], config: {}, policies: [], services: [], workloads: [] }, null, 2);

async function addProxy(archiveDir: string, ns: string, pod: string, files: Record<string, string>): Promise<void> {
  const dir = join(archiveDir, "proxies", ns, pod);
  await mkdir(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) await writeFile(join(dir, name), content);
}

function typeOf(store: BugReportStore, ns: string, pod: string): string | undefined {
  return store.getProxyPods(ns).find((p) => p.podName === pod)?.proxyType;
}

describe("proxy type classification", () => {
  let tempDir: string;
  let store: BugReportStore;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "proxy-type-test-"));
    const a = join(tempDir, "bug-report");
    await mkdir(a, { recursive: true });
    await writeFile(join(a, "versions"), "client version: 1.31.2\n");
    const dump = "config_dump?include_eds";
    await addProxy(a, "istio-ingress", "istio-ingressgateway-7d9-abcde", { [dump]: envoyDump("router", "istio-ingressgateway-7d9-abcde", "istio-ingress") });
    await addProxy(a, "web", "public-gw-istio-6f7-xyz12", { [dump]: envoyDump("router", "public-gw-istio-6f7-xyz12", "web") });
    await addProxy(a, "shop", "reviews-wp-5c4-qwert", { [dump]: envoyDump("waypoint", "reviews-wp-5c4-qwert", "shop") });
    await addProxy(a, "shop", "waypoint-5c4-legacy", { [dump]: envoyDump("router", "waypoint-5c4-legacy", "shop") });
    await addProxy(a, "shop", "gateway-api-client-8b7-zxcvb", { [dump]: envoyDump("sidecar", "gateway-api-client-8b7-zxcvb", "shop") });
    await addProxy(a, "istio-eastwest", "istio-eastwest-687-nsmnh", { config_dump: ZTUNNEL_DUMP, "istio-proxy.log": "info\taccess\tconnection complete\n" });
    await addProxy(a, "istio-system", "ztunnel-c77st", { config_dump: ZTUNNEL_DUMP });
    await addProxy(a, "edge", "edge-proxy-1a2-logonly", {
      "istio-proxy.log": "2026-10-20T20:22:24Z\tinfo\tProxy role\tips=[10.0.0.9] type=router id=edge-proxy-1a2-logonly.edge domain=edge.svc.cluster.local\n",
    });
    await addProxy(a, "istio-egress", "istio-egressgateway-9f8-noinfo", { "istio-proxy.log": "info\tsome line\n" });
    await addProxy(a, "app", "orders-7c6-noinfo", { "istio-proxy.log": "info\tsome line\n" });
    store = await BugReportStore.fromDirectory(a);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("classifies ingress gateways and Gateway API gateways from the bootstrap node type", () => {
    expect(typeOf(store, "istio-ingress", "istio-ingressgateway-7d9-abcde")).toBe("gateway");
    expect(typeOf(store, "web", "public-gw-istio-6f7-xyz12")).toBe("gateway");
  });

  it("keeps waypoints distinct, including pre-1.22 waypoints that report as router", () => {
    expect(typeOf(store, "shop", "reviews-wp-5c4-qwert")).toBe("waypoint");
    expect(typeOf(store, "shop", "waypoint-5c4-legacy")).toBe("waypoint");
  });

  it("trusts the node type over the pod name", () => {
    expect(typeOf(store, "shop", "gateway-api-client-8b7-zxcvb")).toBe("sidecar");
  });

  it("classifies ztunnel-based gateways that are not the ztunnel DaemonSet as gateways", () => {
    expect(typeOf(store, "istio-eastwest", "istio-eastwest-687-nsmnh")).toBe("gateway");
    expect(typeOf(store, "istio-system", "ztunnel-c77st")).toBe("ztunnel");
  });

  it("falls back to the proxy role in the log, then to the pod name", () => {
    expect(typeOf(store, "edge", "edge-proxy-1a2-logonly")).toBe("gateway");
    expect(typeOf(store, "istio-egress", "istio-egressgateway-9f8-noinfo")).toBe("gateway");
    expect(typeOf(store, "app", "orders-7c6-noinfo")).toBe("sidecar");
  });

  it("does not count gateways as sidecars for data plane mode", () => {
    const info = store.detectDataPlaneMode();
    expect(info.hasSidecars).toBe(true);
    expect(info.sidecarNamespaces.sort()).toEqual(["app", "shop"]);
  });
});

describe("proxy type evidence edge cases", () => {
  let tempDir: string;
  let store: BugReportStore;
  const noEvidence = { "istio-proxy.log": "info\tsome line\n" };

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "proxy-type-edge-test-"));
    const a = join(tempDir, "bug-report");
    await mkdir(a, { recursive: true });
    await writeFile(join(a, "versions"), "client version: 1.31.2\n");
    const jsonRole = (type: string, pod: string, ns: string) =>
      `{"level":"info","time":"2026-10-20T07:04:13.740381Z","msg":"Proxy role","ips":["10.0.0.9"],"type":"${type}","id":"${pod}.${ns}","domain":"${ns}.svc.cluster.local"}\n`;
    await addProxy(a, "edge", "edge-proxy-1a2-json", { "istio-proxy.log": `{"level":"info","msg":"starting"}\n${jsonRole("router", "edge-proxy-1a2-json", "edge")}` });
    await addProxy(a, "edge", "edge-proxy-1a2-jsonorder", {
      "istio-proxy.log": `{"type":"router","msg":"Proxy role","level":"info","id":"edge-proxy-1a2-jsonorder.edge"}\n`,
    });
    await addProxy(a, "app", "orders-7c6-json", { "istio-proxy.log": jsonRole("sidecar", "orders-7c6-json", "app") });
    for (const pod of [
      "istio-ingressgateway-7d9-abcde",
      "istio-egressgateway-9f8-fghij",
      "istio-eastwestgateway-5b6-klmno",
      "public-ingressgateway-7d9-pqrst",
      "cross-network-eastwest-6c7-uvwxy",
      "public-gw-istio-6f7c8d9b-z1x2c",
    ]) {
      await addProxy(a, "gw", pod, noEvidence);
    }
    for (const pod of ["api-gateway-svc-7c6-abcde", "payment-gateway-5d4-fghij", "gateway-7c6-klmno"]) {
      await addProxy(a, "app", pod, noEvidence);
    }
    await addProxy(a, "istio-system", "istio-ztunnel-c77st", { config_dump: ZTUNNEL_DUMP });
    store = await BugReportStore.fromDirectory(a);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("reads the proxy role from JSON-formatted logs, in any field order", () => {
    expect(typeOf(store, "edge", "edge-proxy-1a2-json")).toBe("gateway");
    expect(typeOf(store, "edge", "edge-proxy-1a2-jsonorder")).toBe("gateway");
    expect(typeOf(store, "app", "orders-7c6-json")).toBe("sidecar");
  });

  it("only names that follow Istio gateway conventions become gateways without evidence", () => {
    for (const pod of [
      "istio-ingressgateway-7d9-abcde",
      "istio-egressgateway-9f8-fghij",
      "istio-eastwestgateway-5b6-klmno",
      "public-ingressgateway-7d9-pqrst",
      "cross-network-eastwest-6c7-uvwxy",
      "public-gw-istio-6f7c8d9b-z1x2c",
    ]) {
      expect(typeOf(store, "gw", pod), pod).toBe("gateway");
    }
    for (const pod of ["api-gateway-svc-7c6-abcde", "payment-gateway-5d4-fghij", "gateway-7c6-klmno"]) {
      expect(typeOf(store, "app", pod), pod).toBe("sidecar");
    }
  });

  it("treats a ztunnel-format dump on a pod named *ztunnel* (not ztunnel-*) as ztunnel", () => {
    expect(typeOf(store, "istio-system", "istio-ztunnel-c77st")).toBe("ztunnel");
  });
});

describe("data plane mode with only gateways and ztunnel", () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "proxy-type-ambient-test-"));
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("is ambient, not interop", async () => {
    const a = join(tempDir, "bug-report");
    await mkdir(a, { recursive: true });
    await writeFile(join(a, "versions"), "client version: 1.31.2\n");
    await addProxy(a, "istio-ingress", "istio-ingressgateway-7d9-abcde", {
      "config_dump?include_eds": envoyDump("router", "istio-ingressgateway-7d9-abcde", "istio-ingress"),
    });
    await addProxy(a, "istio-system", "ztunnel-c77st", { config_dump: ZTUNNEL_DUMP });
    const store = await BugReportStore.fromDirectory(a);
    const info = store.detectDataPlaneMode();
    expect(info.mode).toBe("ambient");
    expect(info.hasSidecars).toBe(false);
  });
});

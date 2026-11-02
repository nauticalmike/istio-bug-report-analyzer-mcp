import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { collectableByIstioctl, scanPodInventory } from "../../src/archive/pod-inventory.js";

type Obj = Record<string, unknown>;

const pod = (namespace: string, name: string, containers: Obj[], phase = "Running"): Obj => ({
  apiVersion: "v1",
  kind: "Pod",
  metadata: { name, namespace, labels: { app: name } },
  spec: { containers },
  status: { phase },
});

const items: Obj[] = [
  pod("shop", "cart-7d9f8b6c4d-x2k9p", [{ name: "app", image: "app:1" }, { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "sidecar"] }]),
  pod("shop", "batch-job-q8z4w", [{ name: "app", image: "app:1" }, { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "sidecar"] }], "Succeeded"),
  pod("istio-system", "ztunnel-x7k2p", [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.31.2", args: ["proxy", "ztunnel"] }]),
  pod("kube-system", "istio-cni-node-q9w8z", [{ name: "install-cni", image: "docker.io/istio/install-cni:1.31.2" }]),
  pod("web", "plain-5b6c7d8f9g-h2j4k", [{ name: "app", image: "app:1" }]),
  // Not pods: an Event about a deleted ztunnel pod and a ControllerRevision whose names look like DaemonSet pods.
  { apiVersion: "v1", kind: "Event", metadata: { name: "ztunnel-b4c5d", namespace: "istio-system" }, involvedObject: { kind: "Pod", name: "ztunnel-b4c5d" } },
  { apiVersion: "apps/v1", kind: "ControllerRevision", metadata: { name: "istio-cni-node-z9x8w", namespace: "kube-system" } },
  { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "settings", namespace: "billing" }, data: { "kind: Pod": "name: istio-proxy" } },
  { apiVersion: "v1", kind: "Namespace", metadata: { name: "empty-ns" } },
];

describe("scanPodInventory", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "pod-inventory-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const scan = async (content: string, relativePath = "cluster/k8s-resources") => {
    const absolutePath = join(dir, "dump");
    await writeFile(absolutePath, content);
    return scanPodInventory([{ relativePath, absolutePath }]);
  };

  for (const [format, content] of [
    ["a YAML List (item scan)", () => dump({ apiVersion: "v1", kind: "List", items })],
    ["plain YAML documents", () => items.map((i) => dump(i)).join("---\n")],
    ["a JSON List (full-parse fallback)", () => JSON.stringify({ apiVersion: "v1", kind: "List", items }, null, 2)],
  ] as const) {
    it(`reads pods, roles and namespaces from ${format}`, async () => {
      const inv = await scan(content());
      expect(inv.available).toBe(true);
      expect(inv.wholeCluster).toBe(true);
      expect([...inv.pods.keys()].sort()).toEqual([
        "istio-system/ztunnel-x7k2p",
        "kube-system/istio-cni-node-q9w8z",
        "shop/batch-job-q8z4w",
        "shop/cart-7d9f8b6c4d-x2k9p",
        "web/plain-5b6c7d8f9g-h2j4k",
      ]);
      expect(inv.pods.get("shop/cart-7d9f8b6c4d-x2k9p")).toMatchObject({ namespace: "shop", name: "cart-7d9f8b6c4d-x2k9p", phase: "Running", injected: true, daemon: null });
      expect(inv.pods.get("shop/batch-job-q8z4w")?.phase).toBe("Succeeded");
      expect(inv.pods.get("istio-system/ztunnel-x7k2p")).toMatchObject({ injected: false, daemon: "ztunnel" });
      expect(inv.pods.get("kube-system/istio-cni-node-q9w8z")).toMatchObject({ injected: false, daemon: "cni" });
      expect(inv.pods.get("web/plain-5b6c7d8f9g-h2j4k")?.injected).toBe(false);
      // Namespaced objects of any kind count; a Namespace object does not.
      expect([...inv.namespaces].sort()).toEqual(["billing", "istio-system", "kube-system", "shop", "web"]);
    });
  }

  it("marks a pod list from cluster/pods alone as not the whole cluster", async () => {
    const inv = await scan(dump({ apiVersion: "v1", kind: "List", items: items.slice(2, 3) }), "cluster/pods");
    expect(inv.wholeCluster).toBe(false);
    expect([...inv.namespaces]).toEqual(["istio-system"]);
  });

  it("is unavailable when the dumps hold no Pod", async () => {
    const inv = await scan(dump({ apiVersion: "v1", kind: "List", items: items.slice(5) }));
    expect(inv.available).toBe(false);
  });
});

const owned = (o: Obj, kind: string, name: string): Obj => ({ ...o, metadata: { ...(o.metadata as Obj), ownerReferences: [{ apiVersion: "apps/v1", kind, name, controller: true, uid: "u-1" }] } });
const proxy = (args: string[], image = "docker.io/istio/proxyv2:1.31.2"): Obj[] => [{ name: "istio-proxy", image, args }];
const replicaSet = (namespace: string, name: string, ownerKind: string): Obj =>
  owned({ apiVersion: "apps/v1", kind: "ReplicaSet", metadata: { name, namespace } }, ownerKind, name.replace(/-[^-]+$/, ""));

const roleItems: Obj[] = [
  owned(pod("shop", "cart-7d9f8b6c4d-x2k9p", proxy(["proxy", "sidecar"])), "ReplicaSet", "cart-7d9f8b6c4d"),
  owned(pod("istio-ingress", "istio-ingressgateway-5b6c7d8f9g-h2j4k", proxy(["proxy", "router"])), "ReplicaSet", "istio-ingressgateway-5b6c7d8f9g"),
  owned(
    { ...pod("shop", "waypoint-6c7d8f9b5d-q8z4w", proxy(["proxy", "router"])), metadata: { name: "waypoint-6c7d8f9b5d-q8z4w", namespace: "shop", labels: { "gateway.istio.io/managed": "istio.io-mesh-controller" } } },
    "ReplicaSet",
    "waypoint-6c7d8f9b5d",
  ),
  owned(pod("istio-system", "ztunnel-x7k2p", proxy(["proxy", "ztunnel"], "docker.io/istio/ztunnel:1.31.2")), "DaemonSet", "ztunnel"),
  // An east-west gateway that runs the ztunnel image: istioctl collects it, so it is a gateway.
  owned(pod("istio-eastwest", "istio-eastwest-7d9f8b6c4d-z9x8w", proxy([], "docker.io/istio/ztunnel:1.31.2")), "ReplicaSet", "istio-eastwest-7d9f8b6c4d"),
  owned(pod("shop", "db-0", proxy(["proxy", "sidecar"])), "StatefulSet", "db"),
  owned(pod("shop", "canary-5f6d7c8b9d-k2j4h", proxy(["proxy", "sidecar"])), "ReplicaSet", "canary-5f6d7c8b9d"),
  owned(pod("kube-system", "dns-7d9f8b6c4d-m2n4p", proxy(["proxy", "sidecar"])), "ReplicaSet", "dns-7d9f8b6c4d"),
  pod("shop", "bare", proxy(["proxy", "sidecar"])),
  replicaSet("shop", "cart-7d9f8b6c4d", "Deployment"),
  replicaSet("shop", "canary-5f6d7c8b9d", "Rollout"),
];

describe("scanPodInventory owners and proxy roles", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "pod-inventory-roles-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  for (const [format, content] of [
    ["a YAML List (item scan)", () => dump({ apiVersion: "v1", kind: "List", items: roleItems })],
    ["a JSON List (full-parse fallback)", () => JSON.stringify({ apiVersion: "v1", kind: "List", items: roleItems }, null, 2)],
  ] as const) {
    it(`reads owners, ReplicaSet owners and roles from ${format}`, async () => {
      const absolutePath = join(dir, "dump");
      await writeFile(absolutePath, content());
      const inv = scanPodInventory([{ relativePath: "cluster/k8s-resources", absolutePath }]);
      const get = (k: string) => inv.pods.get(k)!;
      expect(get("shop/cart-7d9f8b6c4d-x2k9p")).toMatchObject({ ownerKind: "ReplicaSet", ownerName: "cart-7d9f8b6c4d", role: "sidecar" });
      expect(get("istio-ingress/istio-ingressgateway-5b6c7d8f9g-h2j4k").role).toBe("gateway");
      expect(get("shop/waypoint-6c7d8f9b5d-q8z4w").role).toBe("waypoint");
      expect(get("istio-system/ztunnel-x7k2p")).toMatchObject({ ownerKind: "DaemonSet", role: "ztunnel", injected: false });
      expect(get("istio-eastwest/istio-eastwest-7d9f8b6c4d-z9x8w").role).toBe("gateway");
      expect(get("shop/bare")).toMatchObject({ ownerKind: null, ownerName: null });
      expect(inv.rsOwners.get("shop/cart-7d9f8b6c4d")).toBe("Deployment");
      expect(inv.rsOwners.get("shop/canary-5f6d7c8b9d")).toBe("Rollout");

      const collectable = (k: string) => collectableByIstioctl(get(k), inv);
      expect(collectable("shop/cart-7d9f8b6c4d-x2k9p")).toBe(true);
      expect(collectable("istio-system/ztunnel-x7k2p")).toBe(true);
      // A ReplicaSet that was not dumped counts as Deployment-owned (unknown is collectable).
      expect(collectable("istio-ingress/istio-ingressgateway-5b6c7d8f9g-h2j4k")).toBe(true);
      expect(collectable("shop/canary-5f6d7c8b9d-k2j4h")).toBe(false); // Argo Rollout
      expect(collectable("shop/db-0")).toBe(false); // StatefulSet
      expect(collectable("shop/bare")).toBe(false);
      expect(collectable("kube-system/dns-7d9f8b6c4d-m2n4p")).toBe(false); // ignored namespace
    });
  }
});

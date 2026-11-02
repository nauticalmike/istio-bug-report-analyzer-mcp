import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { scanPodInventory } from "../../src/archive/pod-inventory.js";

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
      expect(inv.pods.get("shop/cart-7d9f8b6c4d-x2k9p")).toEqual({ namespace: "shop", name: "cart-7d9f8b6c4d-x2k9p", phase: "Running", injected: true, daemon: null });
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

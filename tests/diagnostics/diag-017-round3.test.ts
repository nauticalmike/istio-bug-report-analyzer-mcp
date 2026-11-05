import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

/** A namespace object plus an object inside it (so the dump shows it was collected). */
function ns(name: string, labels: Obj = {}): Obj[] {
  return [namespace(name, labels), { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "kube-root-ca.crt", namespace: name }, data: { "ca.crt": "x" } }];
}

function istiod(): Obj[] {
  const labels = { app: "istiod", "istio.io/rev": "default" };
  return [
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { name: "istiod", namespace: "istio-system", labels },
      spec: {
        replicas: 1,
        selector: { matchLabels: labels },
        template: { metadata: { labels }, spec: { containers: [{ name: "discovery", image: "registry.example.com/pilot:1.31.2", env: [{ name: "PILOT_ENABLE_AMBIENT", value: "true" }] }] } },
      },
    },
    { apiVersion: "v1", kind: "Service", metadata: { name: "istiod", namespace: "istio-system" }, spec: { selector: labels, ports: [{ name: "grpc-xds", port: 15012 }] } },
  ];
}

const AMBIENT = { "istio.io/dataplane-mode": "ambient" };

async function issues(resources: Obj[]) {
  const { findings } = await runEngine({ resources, noPodDump: true }, ["ambient"]);
  return finding(findings, "DIAG-017")?.issues ?? [];
}

describe("DIAG-017 round 3: lines spanning namespaces", () => {
  it("sets Issue.namespaces to the ambient namespaces on the missing-DaemonSet lines", async () => {
    const resources = [...ns("istio-system"), ...ns("shop", AMBIENT), ...ns("orders", AMBIENT), ...istiod(), ambientPod("shop", "cart"), ambientPod("orders", "api")];
    const out = await issues(resources);
    const missing = out.filter((i) => /^no (ztunnel|istio-cni) DaemonSet/.test(i.detail));
    expect(missing).toHaveLength(2);
    for (const line of missing) {
      expect(line.namespaces).toEqual(["orders", "shop"]);
      expect(line.namespace).toBeUndefined();
    }
  });

  it("leaves a line naming one ambient namespace unattributed", async () => {
    const resources = [...ns("istio-system"), ...ns("shop", AMBIENT), ...istiod(), ambientPod("shop", "cart")];
    const line = (await issues(resources)).find((i) => i.detail.startsWith("no ztunnel DaemonSet"));
    expect(line?.detail).toContain("(shop)");
    expect(line?.namespace).toBeUndefined();
    expect(line?.namespaces).toBeUndefined();
  });
});

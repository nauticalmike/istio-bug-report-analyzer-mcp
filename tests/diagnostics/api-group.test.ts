import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, envoyFilter, finding, pod, runTemplates } from "./template-harness.js";

afterEach(cleanupArchives);

// A third-party CRD may reuse an Istio kind name in its own API group; Istio checks must
// read only the Istio (and Gateway API) groups.
describe("Istio checks filter resources by API group", () => {
  it("DIAG-005 ignores an EnvoyFilter kind from another API group", async () => {
    const foreign = { ...envoyFilter("default", "foreign", { workloadSelector: { labels: { app: "gone" } } }), apiVersion: "example.com/v1" };
    const findings = await runTemplates({ resources: [pod("default", "reviews-abc", { app: "reviews" }), foreign] }, ["envoyfilter"]);
    expect(finding(findings, "DIAG-005")).toBeUndefined();
  });

  it("DIAG-005 resolves a Gateway targetRef against Gateway API Gateways, not Istio Gateways", async () => {
    const istioGateway = { apiVersion: "networking.istio.io/v1", kind: "Gateway", metadata: { name: "edge", namespace: "default" }, spec: {} };
    const ef = envoyFilter("default", "edge-lua", { targetRefs: [{ group: "gateway.networking.k8s.io", kind: "Gateway", name: "edge" }] });
    const k8sGateway = { apiVersion: "gateway.networking.k8s.io/v1", kind: "Gateway", metadata: { name: "other", namespace: "default" }, spec: {} };
    const f = finding(await runTemplates({ resources: [istioGateway, k8sGateway, ef] }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual(["default/edge-lua: targetRef Gateway/edge does not exist"]);
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, deployment, finding, requests, runTemplates, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

function istiod(cpu: string, memory: string, env: Obj[] = []): Obj {
  return deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", ...requests(cpu, memory), env }] });
}

const egress = deployment("istio-system", "istio-egressgateway", { labels: { app: "istio-egressgateway" } });

describe("DIAG-002 demo profile template", () => {
  it("does not fire on access logging to stdout alone", async () => {
    const findings = await runTemplates({ resources: [istiod("500m", "2048Mi")], meshDebug: { accessLogFile: "/dev/stdout" } }, ["config"]);
    expect(finding(findings, "DIAG-002")).toBeUndefined();
  });

  it("does not fire on supporting signals without demo istiod resources", async () => {
    const prod = istiod("500m", "2048Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "100" }]);
    const findings = await runTemplates({ resources: [prod, egress], meshDebug: { accessLogFile: "/dev/stdout" } }, ["config"]);
    expect(finding(findings, "DIAG-002")).toBeUndefined();
  });

  it("does not fire on demo istiod resources with no supporting signal", async () => {
    expect(finding(await runTemplates({ resources: [istiod("10m", "100Mi")], meshDebug: {} }, ["config"]), "DIAG-002")).toBeUndefined();
  });

  it("fires on demo istiod resources combined with demo-only settings", async () => {
    const demo = istiod("10m", "100Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "100" }]);
    const f = finding(await runTemplates({ resources: [demo, egress], meshDebug: { accessLogFile: "/dev/stdout" } }, ["config"]), "DIAG-002");
    expect(f?.affectedResources).toEqual([
      expect.stringContaining("istiod requests cpu=10m memory=100Mi"),
      expect.stringContaining("PILOT_TRACE_SAMPLING=100"),
      expect.stringContaining("istio-egressgateway deployed"),
      expect.stringContaining("accessLogFile=/dev/stdout"),
    ]);
  });

  it("treats equivalent quantities as the demo values", async () => {
    const demo = istiod("0.01", "104857600");
    const f = finding(await runTemplates({ resources: [demo, egress], meshDebug: {} }, ["config"]), "DIAG-002");
    expect(f).toBeDefined();
  });

  it("reads meshConfig from the istio ConfigMap when istiod debug/mesh was not collected", async () => {
    const cm = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "istio", namespace: "istio-system" }, data: { mesh: "accessLogFile: /dev/stdout\n" } };
    const f = finding(await runTemplates({ resources: [istiod("10m", "100Mi"), cm], meshDebug: null }, ["config"]), "DIAG-002");
    expect(f?.affectedResources).toEqual([expect.stringContaining("istiod requests"), expect.stringContaining("accessLogFile=/dev/stdout")]);
  });
});

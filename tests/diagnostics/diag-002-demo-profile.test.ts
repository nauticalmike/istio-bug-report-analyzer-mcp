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

  it("does not report demo-profile evidence without demo istiod resources", async () => {
    const prod = istiod("500m", "2048Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "1" }]);
    const findings = await runTemplates({ resources: [prod, egress], meshDebug: { accessLogFile: "/dev/stdout" } }, ["config"]);
    expect(finding(findings, "DIAG-002")).toBeUndefined();
  });

  it("leaves trace sampling without demo evidence to DIAG-033, at warning", async () => {
    const prod = istiod("500m", "2048Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "100" }]);
    const findings = await runTemplates({ resources: [prod, egress], meshDebug: { accessLogFile: "/dev/stdout" } }, ["config"]);
    expect(finding(findings, "DIAG-002")).toBeUndefined();
    const f = finding(findings, "DIAG-033");
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual(["mesh-wide trace sampling 100% from PILOT_TRACE_SAMPLING=100 on istio-system/istiod (production rates are about 1%)"]);
  });

  it("ignores trace sampling below 50%", async () => {
    const prod = istiod("500m", "2048Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "10" }]);
    const findings = await runTemplates({ resources: [prod], meshDebug: {} }, ["config"]);
    expect(finding(findings, "DIAG-002")).toBeUndefined();
    expect(finding(findings, "DIAG-033")).toBeUndefined();
  });

  it("flags meshConfig sampling overriding a different PILOT_TRACE_SAMPLING (meshConfig wins)", async () => {
    const prod = istiod("500m", "2048Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "1" }]);
    const f = finding(await runTemplates({ resources: [prod], meshDebug: { defaultConfig: { tracing: { sampling: 100 } } } }, ["config"]), "DIAG-033");
    expect(f?.severity).toBe("warning");
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^mesh-wide trace sampling 100% from meshConfig\.defaultConfig\.tracing\.sampling=100/), severity: "warning" },
      { detail: "meshConfig.defaultConfig.tracing.sampling=100 overrides PILOT_TRACE_SAMPLING=1 on istio-system/istiod (the env value is ignored)", severity: "info" },
    ]);
  });

  it("reports a disagreement alone at info when both rates are low", async () => {
    const prod = istiod("500m", "2048Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "1" }]);
    const f = finding(await runTemplates({ resources: [prod], meshDebug: { defaultConfig: { tracing: { sampling: 5 } } } }, ["config"]), "DIAG-033");
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringContaining("sampling=5 overrides PILOT_TRACE_SAMPLING=1")]);
  });

  it("reports Telemetry randomSamplingPercentage at 50% or more with its scope", async () => {
    const telemetry = (ns: string, name: string, spec: Obj): Obj => ({ apiVersion: "telemetry.istio.io/v1", kind: "Telemetry", metadata: { name, namespace: ns }, spec });
    const resources = [
      istiod("500m", "2048Mi"),
      telemetry("istio-system", "mesh-default", { tracing: [{ randomSamplingPercentage: 100 }] }),
      telemetry("shop", "cart", { selector: { matchLabels: { app: "cart" } }, tracing: [{ randomSamplingPercentage: 50 }] }),
      telemetry("pay", "low", { tracing: [{ randomSamplingPercentage: 1 }] }),
    ];
    const f = finding(await runTemplates({ resources, meshDebug: {} }, ["config"]), "DIAG-033");
    expect(f?.issues).toEqual([
      { detail: "Telemetry istio-system/mesh-default: tracing randomSamplingPercentage 100 (mesh-wide; overrides meshConfig and PILOT_TRACE_SAMPLING)", severity: "warning" },
      { detail: "Telemetry shop/cart: tracing randomSamplingPercentage 50 (selected workloads in shop; overrides meshConfig and PILOT_TRACE_SAMPLING)", severity: "warning", namespace: "shop" },
    ]);
  });

  it("keeps the demo finding identical and appends only new sampling signals", async () => {
    const demo = istiod("10m", "100Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "100" }]);
    const telemetry = { apiVersion: "telemetry.istio.io/v1", kind: "Telemetry", metadata: { name: "t", namespace: "shop" }, spec: { tracing: [{ randomSamplingPercentage: 80 }] } };
    const f = finding(await runTemplates({ resources: [demo, egress, telemetry], meshDebug: {} }, ["config"]), "DIAG-002");
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([
      expect.stringContaining("istiod requests cpu=10m memory=100Mi"),
      "PILOT_TRACE_SAMPLING=100 (100% trace sampling)",
      expect.stringContaining("istio-egressgateway deployed"),
      expect.stringContaining("Telemetry shop/t: tracing randomSamplingPercentage 80"),
    ]);
  });

  it("qualifies a line saying the demo's PILOT_TRACE_SAMPLING=100 is not in effect, keeping the demo line", async () => {
    const demo = istiod("10m", "100Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "100" }]);
    const f = finding(await runTemplates({ resources: [demo, egress], meshDebug: { defaultConfig: { tracing: { sampling: 1 } } } }, ["config"]), "DIAG-002");
    expect(f?.affectedResources).toEqual([
      expect.stringContaining("istiod requests cpu=10m memory=100Mi"),
      "PILOT_TRACE_SAMPLING=100 (100% trace sampling)",
      expect.stringContaining("istio-egressgateway deployed"),
      "meshConfig.defaultConfig.tracing.sampling=1 overrides PILOT_TRACE_SAMPLING=100 on istio-system/istiod (the env value is ignored; the 100% trace sampling above is not in effect)",
    ]);
  });

  it("qualifies a mesh-wide Telemetry rate that replaces the demo's 100%", async () => {
    const demo = istiod("10m", "100Mi", [{ name: "PILOT_TRACE_SAMPLING", value: "100" }]);
    const telemetry = { apiVersion: "telemetry.istio.io/v1", kind: "Telemetry", metadata: { name: "mesh-default", namespace: "istio-system" }, spec: { tracing: [{ randomSamplingPercentage: 60 }] } };
    const f = finding(await runTemplates({ resources: [demo, egress, telemetry], meshDebug: {} }, ["config"]), "DIAG-002");
    expect(f?.affectedResources).toContain("PILOT_TRACE_SAMPLING=100 (100% trace sampling)");
    expect(f?.affectedResources).toContain(
      "Telemetry istio-system/mesh-default: tracing randomSamplingPercentage 60 (mesh-wide; overrides meshConfig and PILOT_TRACE_SAMPLING; the 100% trace sampling above is not in effect)",
    );
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

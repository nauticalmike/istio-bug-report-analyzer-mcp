import { describe, it, expect, afterEach } from "vitest";
import { traceSamplingIssues } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives, deployment, requests, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

function istiod(env: Obj[]): Obj {
  return deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", ...requests("500m", "2048Mi"), env }] });
}

function istiodPod(name: string, env: Obj[], owner?: string): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: "istio-system", labels: { app: "istiod" }, ...(owner ? { ownerReferences: [{ kind: "ReplicaSet", name: owner }] } : {}) },
    spec: { containers: [{ name: "discovery", env }] },
    status: { phase: "Running" },
  };
}

const telemetry = (ns: string, name: string, spec: Obj): Obj => ({ apiVersion: "telemetry.istio.io/v1", kind: "Telemetry", metadata: { name, namespace: ns }, spec });

const details = async (resources: Obj[], meshDebug: Obj = {}) => traceSamplingIssues(await buildStore({ resources, meshDebug })).map((i) => i.issue.detail);

describe("traceSamplingIssues", () => {
  it("treats an empty or unparsable PILOT_TRACE_SAMPLING as unset (istiod keeps its default of 1)", async () => {
    expect(await details([istiod([{ name: "PILOT_TRACE_SAMPLING", value: "" }])], { defaultConfig: { tracing: { sampling: 5 } } })).toEqual([]);
    expect(await details([istiod([{ name: "PILOT_TRACE_SAMPLING", value: " 100" }])])).toEqual([]);
  });

  it("reads PILOT_TRACE_SAMPLING from the istiod pods when the dump has no Deployments, once per owner", async () => {
    const env = [{ name: "PILOT_TRACE_SAMPLING", value: "100" }];
    const out = await details([istiodPod("istiod-6b7c8d9f5-abcde", env, "istiod-6b7c8d9f5"), istiodPod("istiod-6b7c8d9f5-fghjk", env, "istiod-6b7c8d9f5")]);
    expect(out).toEqual(["mesh-wide trace sampling 100% from PILOT_TRACE_SAMPLING=100 on istio-system/istiod (production rates are about 1%)"]);
  });

  it("leaves out meshConfig and env rates when a mesh-wide Telemetry sets the rate (Telemetry wins)", async () => {
    const resources = [istiod([{ name: "PILOT_TRACE_SAMPLING", value: "1" }]), telemetry("istio-system", "mesh-default", { tracing: [{ randomSamplingPercentage: 1 }] })];
    expect(await details(resources, { defaultConfig: { tracing: { sampling: 100 } } })).toEqual([]);
  });

  it("keeps meshConfig and env lines when the Telemetry is scoped or sets no rate", async () => {
    const resources = [
      istiod([{ name: "PILOT_TRACE_SAMPLING", value: "1" }]),
      telemetry("istio-system", "providers-only", { tracing: [{ providers: [{ name: "otel" }] }] }),
      telemetry("shop", "cart", { tracing: [{ randomSamplingPercentage: 1 }] }),
    ];
    const out = await details(resources, { defaultConfig: { tracing: { sampling: 100 } } });
    expect(out).toEqual([
      expect.stringMatching(/^mesh-wide trace sampling 100% from meshConfig/),
      expect.stringContaining("overrides PILOT_TRACE_SAMPLING=1 on istio-system/istiod"),
    ]);
  });
});

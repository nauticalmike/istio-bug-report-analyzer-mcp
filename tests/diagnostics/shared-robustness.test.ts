import { describe, it, expect, afterEach, beforeAll, afterAll } from "vitest";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import { waypointFor } from "../../src/diagnostics/mesh-model.js";
import { ambientReadinessReport } from "../../src/tools/ambient-readiness.js";
import type { DiagnosticTemplate, ParsedResource } from "../../src/types.js";
import { ambientPod, buildStore, cleanupArchives, namespace, service, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, crs } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

const template = (check: string): DiagnosticTemplate => ({
  id: `TEST-${check}`,
  name: check,
  category: "config",
  severity: "warning",
  signals: [{ source: { type: "mesh_check", check }, check: { op: "exists" } }],
  description: "",
  rootCause: "",
  impact: "",
  remediation: [],
  references: [],
});

beforeAll(() => {
  MESH_CHECKS.test_throws = () => {
    throw new Error("boom");
  };
  MESH_CHECKS.test_merged = () => [{ detail: "AuthorizationPolicy allow-nothing in 2 namespaces (a, b): no rule can match", severity: "warning", namespaces: ["a", "b"] }];
});
afterAll(() => {
  delete MESH_CHECKS.test_throws;
  delete MESH_CHECKS.test_merged;
});

describe("mesh checks on unexpected archives", () => {
  it("reports a check that throws as not evaluated instead of ending the run", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template("test_throws"));
    expect(await engine.run(store)).toEqual([]);
    expect(engine.getNotEvaluated()).toEqual([expect.objectContaining({ templateId: "TEST-test_throws", reason: expect.stringMatching(/check failed on this archive \(boom\)/) })]);
  });

  it("drops cluster dump items without metadata", async () => {
    const store = await buildStore({ resources: [{ apiVersion: "v1", kind: "Pod", spec: {} }, namespace("shop")] });
    expect(store.getClusterResources({ kind: "Pod" }).every((p) => p.metadata)).toBe(true);
    const engine = new DiagnosticEngine();
    await engine.loadTemplates(new URL("../../templates", import.meta.url).pathname);
    await expect(engine.run(store, { assumeMigration: true })).resolves.toBeDefined();
  });
});

describe("waypointFor", () => {
  it("never binds a waypoint's or east-west gateway's own Service", async () => {
    const resources = [
      namespace("shop", { ...AMBIENT_NS, "istio.io/use-waypoint": "waypoint" }),
      waypoint("shop", "waypoint"),
      service("shop", "waypoint", { "gateway.networking.k8s.io/gateway-name": "waypoint" }, { "gateway.istio.io/managed": "istio.io-mesh-controller" }),
      service("shop", "eastwest", { app: "eastwest" }, { "gateway.istio.io/managed": "istio.io-eastwest-controller" }),
      service("shop", "cart", { app: "cart" }),
    ];
    const store = await buildStore({ resources });
    const of = (i: number) => waypointFor(store, resources[i] as unknown as ParsedResource, "service");
    expect(of(2)).toBeNull();
    expect(of(3)).toBeNull();
    expect(of(4)?.ref).toBe("shop/waypoint");
  });
});

describe("ambient_readiness_report", () => {
  const textOf = (r: { content: { text: string }[] }) => r.content[0].text;

  it("filters and counts a merged line under each namespace it names", async () => {
    const store = await buildStore({ resources: [namespace("a", AMBIENT_NS), namespace("b", AMBIENT_NS), ambientPod("a", "x"), ambientPod("b", "y")], files: crs() });
    // Swap the shipped templates for the probe by running the report on a store whose engine sees it:
    // the report loads templates from disk, so register the probe under a shipped check id instead.
    const original = MESH_CHECKS.l7_authz_ztunnel;
    MESH_CHECKS.l7_authz_ztunnel = MESH_CHECKS.test_merged;
    try {
      const forB = textOf(await ambientReadinessReport(store, { namespace: "b" }));
      expect(forB).toMatch(/allow-nothing in 2 namespaces/);
      const all = textOf(await ambientReadinessReport(store, {}));
      expect(all).toMatch(/^a\s+ambient\s.*\s1\s+0$/m);
      expect(all).toMatch(/^b\s+ambient\s.*\s1\s+0$/m);
    } finally {
      MESH_CHECKS.l7_authz_ztunnel = original;
    }
  });

  it("keeps mesh-wide issues, labelled, under a namespace filter", async () => {
    const original = MESH_CHECKS.l7_authz_ztunnel;
    MESH_CHECKS.l7_authz_ztunnel = () => [
      { detail: "istiod lacks PILOT_ENABLE_AMBIENT", severity: "critical" },
      { detail: "x/p: only x", severity: "warning", namespace: "x" },
    ];
    try {
      const store = await buildStore({ resources: [namespace("a", AMBIENT_NS), ambientPod("a", "x")], files: crs() });
      const text = textOf(await ambientReadinessReport(store, { namespace: "a" }));
      expect(text).toMatch(/\[CRITICAL\] \(mesh-wide\) istiod lacks PILOT_ENABLE_AMBIENT/);
      expect(text).not.toMatch(/only x/);
    } finally {
      MESH_CHECKS.l7_authz_ztunnel = original;
    }
  });

  it("shows a namespace bound to a waypoint-for none waypoint as unusable, and a workload-only one as usable", async () => {
    const store = await buildStore({
      resources: [
        namespace("a", { ...AMBIENT_NS, "istio.io/use-waypoint": "wp" }), waypoint("a", "wp", { labels: { "istio.io/waypoint-for": "none" } }), ambientPod("a", "x"),
        namespace("b", { ...AMBIENT_NS, "istio.io/use-waypoint": "wp" }), waypoint("b", "wp", { labels: { "istio.io/waypoint-for": "workload" } }), ambientPod("b", "y"),
      ],
      files: crs(),
    });
    const text = textOf(await ambientReadinessReport(store, {}));
    expect(text).toMatch(/^a\s+ambient\s+0\s+1\s+0\s+a\/wp \(unusable\)/m);
    expect(text).toMatch(/^b\s+ambient\s+0\s+1\s+0\s+b\/wp\s/m);
  });

  it("treats an issue with namespaces: [] as mesh-wide even when its text starts with ns/name", async () => {
    const original = MESH_CHECKS.l7_authz_ztunnel;
    MESH_CHECKS.l7_authz_ztunnel = () => [{ detail: "istio-system/ztunnel: 2 of 3 pods ready", severity: "critical", namespaces: [] }];
    try {
      const store = await buildStore({ resources: [namespace("a", AMBIENT_NS), ambientPod("a", "x")], files: crs() });
      expect(textOf(await ambientReadinessReport(store, { namespace: "a" }))).toMatch(/\(mesh-wide\) istio-system\/ztunnel: 2 of 3 pods ready/);
    } finally {
      MESH_CHECKS.l7_authz_ztunnel = original;
    }
  });

  it("returns an empty page for an offset past the end", async () => {
    const store = await buildStore({ resources: [namespace("a", AMBIENT_NS), ambientPod("a", "x")] });
    expect(textOf(await ambientReadinessReport(store, { offset: 100_000 }))).toMatch(/^offset 100000 is past the end of the report/);
  });

  it("cuts a single entry larger than the output budget", async () => {
    const huge = "x".repeat(150_000);
    const original = MESH_CHECKS.l7_authz_ztunnel;
    MESH_CHECKS.l7_authz_ztunnel = () => [{ detail: `a/p: ${huge}`, severity: "warning", namespace: "a" }];
    try {
      const store = await buildStore({ resources: [namespace("a", AMBIENT_NS), ambientPod("a", "x")], files: crs() });
      let offset = 0;
      for (let page = 0; page < 10; page++) {
        const text = textOf(await ambientReadinessReport(store, { offset }));
        expect(text.length).toBeLessThan(100_000);
        const next = /Pass offset=(\d+)/.exec(text);
        if (!next) break;
        offset = Number(next[1]);
      }
    } finally {
      MESH_CHECKS.l7_authz_ztunnel = original;
    }
  });
});

void ({} as Obj);

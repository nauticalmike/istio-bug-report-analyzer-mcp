import { describe, it, expect, afterEach } from "vitest";
import { affectedText, runDiagnostics } from "../../src/tools/diagnostics.js";
import type { DiagnosticFinding, DiagnosticTemplate } from "../../src/types.js";
import { ambientPod, buildStore, cleanupArchives, namespace, sidecarPod } from "../diagnostics/template-harness.js";
import { AMBIENT_NS, INJECTED_NS, authz, crs } from "../diagnostics/ambient-fixtures.js";

afterEach(cleanupArchives);

describe("run_diagnostics affected list", () => {
  it("shows at most 25 affected lines per finding, most severe first, and says where the rest are", async () => {
    // 30 L7 policies on sidecar workloads (warning), 5 on ambient ones (critical, listed last in the dump).
    const legacy = Array.from({ length: 30 }, (_, i) => authz("legacy", `p-${String(i).padStart(2, "0")}`, { selector: { matchLabels: { app: "api" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] }));
    const shop = Array.from({ length: 5 }, (_, i) => authz("shop", `p-${i}`, { selector: { matchLabels: { app: "cart" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] }));
    const store = await buildStore({
      resources: [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" }), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.27.1")],
      files: crs(...legacy, ...shop),
    });
    const text = (await runDiagnostics(store, { categories: "security" })).content[0].text;
    const block = text.slice(text.indexOf("DIAG-009"));
    const affected = /  Affected: (.*)\n/.exec(block)![1];
    const items = [...affected.matchAll(/(shop|legacy)\/p-\d+:/g)].map((m) => m[1]);
    expect(items).toHaveLength(25);
    expect(items.slice(0, 5)).toEqual(["shop", "shop", "shop", "shop", "shop"]);
    expect(affected).toMatch(/\(\+10 more; ambient_readiness_report lists every issue of this check\)$/);
  });

  it("keeps every affected item for templates outside the readiness report (no listing elsewhere)", async () => {
    const pods = Array.from({ length: 30 }, (_, i) => ({ apiVersion: "v1", kind: "Pod", metadata: { name: `p-${i}`, namespace: "shop", labels: { app: `gone-${i}` } }, spec: {} }));
    const efs = Array.from({ length: 30 }, (_, i) => ({ apiVersion: "networking.istio.io/v1alpha3", kind: "EnvoyFilter", metadata: { name: `ef-${i}`, namespace: "shop" }, spec: { workloadSelector: { labels: { app: `none-${i}` } } } }));
    const store = await buildStore({ resources: pods, files: crs(...efs) });
    const text = (await runDiagnostics(store, { categories: "envoyfilter" })).content[0].text;
    const block = text.slice(text.indexOf("DIAG-005"));
    const affected = /  Affected: (.*)\n/.exec(block)![1];
    expect([...affected.matchAll(/shop\/ef-\d+:/g)]).toHaveLength(30);
    expect(affected).not.toMatch(/more/);
  });

  it("keeps every item for mesh checks outside the readiness report (DIAG-019+), which has no listing of them", () => {
    const issues = Array.from({ length: 40 }, (_, i) => ({ detail: `shop/cart-${i}: LDS rejected`, severity: "warning" as const }));
    const f = { severity: "warning", affectedResources: issues.map((i) => i.detail), issues } as unknown as DiagnosticFinding;
    const template = (check: string) => ({ signals: [{ source: { type: "mesh_check", check } }] }) as unknown as DiagnosticTemplate;
    const nonReadiness = affectedText(f, template("xds_rejected"));
    expect(nonReadiness.split(", ")).toHaveLength(40);
    expect(nonReadiness).not.toMatch(/ambient_readiness_report|more/);
  });
});

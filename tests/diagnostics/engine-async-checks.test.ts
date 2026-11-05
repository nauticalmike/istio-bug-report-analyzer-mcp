import { describe, it, expect, afterEach, beforeAll, afterAll } from "vitest";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import type { DiagnosticTemplate } from "../../src/types.js";
import { buildStore, cleanupArchives } from "./template-harness.js";

afterEach(cleanupArchives);

const template = (check: string, severity: DiagnosticTemplate["severity"] = "critical"): DiagnosticTemplate => ({
  id: `TEST-${check}`,
  name: check,
  category: "config",
  severity,
  signals: [{ source: { type: "mesh_check", check }, check: { op: "exists" } }],
  description: "",
  rootCause: "",
  impact: "",
  remediation: [],
  references: [],
});

let calls = 0;

beforeAll(() => {
  MESH_CHECKS.test_async = async () => {
    calls++;
    await new Promise((r) => setTimeout(r, 5));
    return [{ detail: "shop/cart: found later", severity: "warning", namespace: "shop" }];
  };
  MESH_CHECKS.test_async_empty = async () => [];
  MESH_CHECKS.test_async_gap = async () => ({ notEvaluated: "not evaluated: no ztunnel logs were collected" });
  MESH_CHECKS.test_joined_gaps = () => ({ notEvaluated: "not evaluated: no istiod logs were collected; not evaluated: cluster/crs missing" });
  MESH_CHECKS.test_async_rejects = async () => {
    throw new Error("async boom");
  };
  MESH_CHECKS.test_sync = () => [{ detail: "still sync" }];
});
afterAll(() => {
  for (const id of ["test_async", "test_async_empty", "test_async_gap", "test_async_rejects", "test_sync", "test_joined_gaps"]) delete MESH_CHECKS[id];
});

describe("async mesh checks", () => {
  it("says \"not evaluated:\" once when a check joins several reasons", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template("test_joined_gaps"));
    expect(await engine.run(store)).toEqual([]);
    expect(engine.getNotEvaluated()).toEqual([
      { templateId: "TEST-test_joined_gaps", templateName: "test_joined_gaps", reason: "not evaluated: no istiod logs were collected; cluster/crs missing" },
    ]);
  });

  it("awaits a check that returns a Promise and reports its issues with severity", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template("test_async"));
    const [finding] = await engine.run(store);
    expect(finding.issues).toEqual([{ detail: "shop/cart: found later", severity: "warning", namespace: "shop" }]);
    expect(finding.affectedResources).toEqual(["shop/cart: found later"]);
    // Lowered to the most severe issue, as for sync checks.
    expect(finding.severity).toBe("warning");
  });

  it("runs an async check once per run when several templates share it", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template("test_async"));
    engine.addTemplate({ ...template("test_async"), id: "TEST-test_async-2" });
    calls = 0;
    expect(await engine.run(store)).toHaveLength(2);
    expect(calls).toBe(1);
  });

  it("passes on an empty async result and lists an async NotEvaluated as not evaluated", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template("test_async_empty"));
    engine.addTemplate(template("test_async_gap"));
    expect(await engine.run(store)).toEqual([]);
    expect(engine.getNotEvaluated()).toEqual([
      { templateId: "TEST-test_async_gap", templateName: "test_async_gap", reason: "not evaluated: no ztunnel logs were collected" },
    ]);
  });

  it("reports a rejected check as not evaluated and keeps running the others", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template("test_async_rejects"));
    engine.addTemplate(template("test_sync"));
    const findings = await engine.run(store);
    expect(findings.map((f) => f.templateId)).toEqual(["TEST-test_sync"]);
    expect(engine.getNotEvaluated()).toEqual([
      expect.objectContaining({ templateId: "TEST-test_async_rejects", reason: expect.stringMatching(/check failed on this archive \(async boom\)/) }),
    ]);
  });
});

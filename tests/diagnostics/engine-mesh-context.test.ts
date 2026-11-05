import { describe, it, expect, afterEach, beforeAll, afterAll } from "vitest";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import { migrationStage, type MeshContext } from "../../src/diagnostics/mesh-model.js";
import type { DiagnosticTemplate } from "../../src/types.js";
import { buildStore, cleanupArchives } from "./template-harness.js";

afterEach(cleanupArchives);

const seen: (MeshContext | undefined)[] = [];

beforeAll(() => {
  MESH_CHECKS.test_probe = (store, ctx) => {
    seen.push(ctx);
    return [
      { detail: "shop/a: first", severity: "warning", namespace: "shop" },
      { detail: "mesh-wide item", severity: "info" },
      { detail: `stage ${migrationStage(store, ctx)}`, severity: "critical", namespace: "istio-system" },
    ];
  };
});
afterAll(() => {
  delete MESH_CHECKS.test_probe;
});

const template: DiagnosticTemplate = {
  id: "TEST-MESH",
  name: "mesh probe",
  category: "config",
  severity: "critical",
  signals: [{ source: { type: "mesh_check", check: "test_probe" }, check: { op: "exists" } }],
  description: "",
  rootCause: "",
  impact: "",
  remediation: [],
  references: [],
};

describe("engine mesh_check context and issue list", () => {
  it("passes the run's MeshContext to the check and keeps every issue with severity and namespace", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template);
    seen.length = 0;
    const [assumed] = await engine.run(store, { assumeMigration: true });
    expect(seen[0]).toEqual({ assumeMigration: true });
    expect(assumed.issues).toEqual([
      { detail: "shop/a: first", severity: "warning", namespace: "shop" },
      { detail: "mesh-wide item", severity: "info" },
      { detail: "stage planned", severity: "critical", namespace: "istio-system" },
    ]);
    expect(assumed.affectedResources).toEqual(["shop/a: first", "mesh-wide item", "stage planned"]);

    // A later run without the option on the same store sees the observed stage.
    const [plain] = await engine.run(store);
    expect(plain.issues?.at(-1)?.detail).toBe("stage none");
  });

  it("keeps the positional categories form", async () => {
    const store = await buildStore({ resources: [] });
    const engine = new DiagnosticEngine();
    engine.addTemplate(template);
    expect(await engine.run(store, ["other"])).toEqual([]);
    expect(await engine.run(store, { categories: ["config"] })).toHaveLength(1);
  });
});

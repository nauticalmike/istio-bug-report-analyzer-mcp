import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, buildStore, cleanupArchives, finding, namespace, runEngine, waypoint, type ArchiveSpec, type Obj } from "./template-harness.js";
import { controlPlane, injectedPod, injectorWebhook } from "./revision-fixtures.js";
import { dualModeNamespaces } from "../../src/diagnostics/mesh-checks/revisions.js";
import type { Issue } from "../../src/diagnostics/checks.js";

afterEach(cleanupArchives);

async function run(spec: ArchiveSpec) {
  const { findings } = await runEngine({ mode: "interop", ...spec }, ["sidecar-to-ambient"]);
  return finding(findings, "DIAG-008");
}

async function issues(spec: ArchiveSpec): Promise<Issue[]> {
  const out = dualModeNamespaces(await buildStore(spec), {});
  if (!Array.isArray(out)) throw new Error(out.notEvaluated);
  return out;
}

const AMBIENT = { "istio.io/dataplane-mode": "ambient" };

function mixed(): Obj[] {
  return [
    namespace("istio-system"),
    namespace("shop", { ...AMBIENT, "istio.io/use-waypoint": "waypoint" }),
    ...controlPlane(""),
    ...controlPlane("1-28"),
    injectorWebhook(""),
    injectorWebhook("1-28"),
    waypoint("shop", "waypoint"),
    ambientPod("shop", "cart"),
  ];
}

describe("DIAG-008 round 2 (served-revision aware namespace mode)", () => {
  it("is a warning (injection wins) when an injector serves the rev label", async () => {
    const out = await issues({ resources: [...mixed(), namespace("orders", { ...AMBIENT, "istio.io/rev": "1-28" })] });
    expect(out).toContainEqual(expect.objectContaining({ severity: "warning", namespace: "orders", detail: expect.stringMatching(/^namespace orders: istio.io\/dataplane-mode=ambient with istio.io\/rev=1-28 \(IST0123\): injection wins/) }));
  });

  it("is info (stale label) when no injector serves the rev label", async () => {
    const f = await run({ resources: [...mixed(), namespace("orders", { ...AMBIENT, "istio.io/rev": "1-20" }), ambientPod("orders", "api")] });
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([
      "namespace orders: istio.io/dataplane-mode=ambient with istio.io/rev=1-20, which no injector webhook serves (stale label): the pods stay in ambient; remove the label",
    ]);
  });

  it("is info for istio-injection=enabled when there is no default injector", async () => {
    const resources = mixed().filter((r) => (r.metadata as Obj).name !== "istio-sidecar-injector");
    const f = await run({ resources: [...resources, namespace("orders", { ...AMBIENT, "istio-injection": "enabled" })] });
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^namespace orders: .*istio-injection=enabled, which no injector webhook serves \(stale label\)/));
  });

  it("falls back to the label rule (warning) when the webhooks were not collected", async () => {
    const resources = mixed().filter((r) => r.kind !== "MutatingWebhookConfiguration");
    const f = await run({ resources: [...resources, namespace("orders", { ...AMBIENT, "istio.io/rev": "1-20" })] });
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^namespace orders: .*istio.io\/rev=1-20 \(IST0123\): injection wins/));
  });

  it("groups namespaces with the same conflict into one line", async () => {
    const resources = [...mixed(), namespace("a", { ...AMBIENT, "istio-injection": "enabled" }), namespace("b", { ...AMBIENT, "istio-injection": "enabled" }), injectedPod("a", "x", "default"), ambientPod("b", "y")];
    const out = await issues({ resources });
    const lines = out.filter((i) => i.detail.includes("IST0123"));
    expect(lines).toEqual([
      {
        detail: "namespaces a, b: istio.io/dataplane-mode=ambient with istio-injection=enabled (IST0123): injection wins, new pods get sidecars and ztunnel skips them; 1 of 2 pods run a sidecar",
        severity: "warning",
        namespaces: ["a", "b"],
      },
    ]);
  });

  it("sets the namespace on pod lines confined to one namespace", async () => {
    const out = await issues({ resources: [...mixed(), injectedPod("shop", "old", "default")] });
    expect(out).toContainEqual(expect.objectContaining({ namespace: "shop", detail: expect.stringMatching(/restart pending/) }));
  });
});

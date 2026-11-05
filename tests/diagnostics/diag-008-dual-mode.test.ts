import { describe, it, expect, afterEach } from "vitest";
import { dump } from "js-yaml";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, waypoint, type ArchiveSpec, type Obj } from "./template-harness.js";
import { controlPlane, injectedPod, injectorWebhook, plainPod } from "./revision-fixtures.js";

afterEach(cleanupArchives);

async function run(spec: ArchiveSpec) {
  const { findings, engine } = await runEngine({ mode: "interop", ...spec }, ["sidecar-to-ambient"]);
  return { f: finding(findings, "DIAG-008"), skipped: engine.getNotEvaluated().find((s) => s.templateId === "DIAG-008") };
}

const AMBIENT = { "istio.io/dataplane-mode": "ambient" };

/** A correctly split mesh: an ambient namespace with a waypoint, and a sidecar namespace. */
function mixed(): Obj[] {
  return [
    namespace("istio-system"),
    namespace("shop", { ...AMBIENT, "istio.io/use-waypoint": "waypoint" }),
    namespace("legacy", { "istio-injection": "enabled" }),
    ...controlPlane(""),
    injectorWebhook(""),
    waypoint("shop", "waypoint"),
    ambientPod("shop", "cart"),
    plainPod("shop", "batch", { app: "batch", "istio.io/dataplane-mode": "none" }),
    injectedPod("legacy", "web", "default"),
  ];
}

describe("DIAG-008 dual-mode namespaces and injection conflicts", () => {
  it("does not fire on a correctly split ambient and sidecar mesh", async () => {
    const { f, skipped } = await run({ resources: mixed() });
    expect(skipped).toBeUndefined();
    expect(f).toBeUndefined();
  });

  it("returns nothing (and is not listed as not evaluated) without ambient namespaces", async () => {
    const resources = mixed().filter((r) => (r.metadata as Obj).namespace !== "shop" && (r.metadata as Obj).name !== "shop");
    const { f, skipped } = await run({ resources, mode: "sidecar" });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("is not evaluated without Namespace objects", async () => {
    const resources = mixed().filter((r) => r.kind !== "Namespace");
    const { f, skipped } = await run({ resources });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/^not evaluated: no Namespace objects/);
  });

  describe("ambient namespace with an injection label (IST0123)", () => {
    it("flags istio-injection=enabled and counts the pods that run sidecars", async () => {
      const resources = [...mixed(), namespace("orders", { ...AMBIENT, "istio-injection": "enabled" }), injectedPod("orders", "api", "default"), ambientPod("orders", "worker")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContain(
        "namespace orders: istio.io/dataplane-mode=ambient with istio-injection=enabled (IST0123): injection wins, new pods get sidecars and ztunnel skips them; 1 of 2 pods run a sidecar",
      );
    });

    it("flags istio.io/rev on an ambient namespace without istio-injection when an injector serves it", async () => {
      const resources = [...mixed(), injectorWebhook("1-28"), namespace("orders", { ...AMBIENT, "istio.io/rev": "1-28" })];
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^namespace orders: istio.io\/dataplane-mode=ambient with istio.io\/rev=1-28 \(IST0123\)/));
    });

    it("does not flag istio-injection=disabled next to the ambient label", async () => {
      const resources = [...mixed(), namespace("orders", { ...AMBIENT, "istio-injection": "disabled", "istio.io/rev": "1-28" })];
      const { f } = await run({ resources });
      expect(f).toBeUndefined();
    });

    it("still reports the labels when the pod dump does not cover the namespace", async () => {
      const namespaces = [...mixed().filter((r) => r.kind === "Namespace"), namespace("orders", { ...AMBIENT, "istio-injection": "enabled" })];
      const { f } = await run({ files: { "cluster/k8s-resources": null, "cluster/k8s-cluster-resources": dump({ apiVersion: "v1", kind: "List", items: namespaces }) } });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^namespace orders: .*\(IST0123\).*; pods not in the dump$/));
    });
  });

  describe("sidecars left in ambient namespaces", () => {
    it("flags pods injected before the namespace moved to ambient (restart pending)", async () => {
      const resources = [...mixed(), injectedPod("shop", "old-1", "default"), injectedPod("shop", "old-2", "default")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContain("2 pods in ambient namespaces still run a sidecar, so ztunnel skips them (restart pending): shop: old-1, old-2");
    });

    it("reports pods kept on a sidecar with sidecar.istio.io/inject=true as info", async () => {
      const resources = [...mixed(), injectedPod("shop", "keep", "default", { app: "keep", "sidecar.istio.io/inject": "true" })];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toContain("1 pod in ambient namespaces opted into a sidecar by pod label (sidecar.istio.io/inject=true or istio.io/rev), so ztunnel skips it: shop: keep");
    });

    it("is not evaluated when the pod dump covers no ambient namespace", async () => {
      const namespaces = mixed().filter((r) => r.kind === "Namespace");
      const { f, skipped } = await run({ files: { "cluster/k8s-resources": null, "cluster/k8s-cluster-resources": dump({ apiVersion: "v1", kind: "List", items: namespaces }) } });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/^not evaluated: ambient pods: the pod dump does not cover the ambient namespaces/);
    });
  });

  describe("pods opted out of ambient with a waypoint label", () => {
    it("flags dataplane-mode=none pods that carry istio.io/use-waypoint", async () => {
      const resources = [...mixed(), plainPod("shop", "cron", { app: "cron", "istio.io/dataplane-mode": "none", "istio.io/use-waypoint": "waypoint" })];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContain("1 pod opted out of ambient (istio.io/dataplane-mode=none) carries istio.io/use-waypoint, which has no effect: shop: cron");
    });
  });
});

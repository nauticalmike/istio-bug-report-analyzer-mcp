import { describe, it, expect, afterEach } from "vitest";
import { dump } from "js-yaml";
import { buildStore, cleanupArchives, finding, namespace, runEngine, type ArchiveSpec, type Obj } from "./template-harness.js";
import {
  configMap,
  controlPlane,
  crashingIstiodPod,
  defaultValidator,
  injectedPod,
  injectorWebhook,
  istiodHpa,
  plainPod,
  revisionValidator,
  tagService,
  workload,
} from "./revision-fixtures.js";
import { orphanedRevisions } from "../../src/diagnostics/mesh-checks/revisions.js";
import type { Issue } from "../../src/diagnostics/checks.js";

afterEach(cleanupArchives);

async function run(spec: ArchiveSpec) {
  const { findings, engine } = await runEngine(spec, ["config"]);
  return { f: finding(findings, "DIAG-007"), skipped: engine.getNotEvaluated().find((s) => s.templateId === "DIAG-007") };
}

async function issues(spec: ArchiveSpec): Promise<Issue[]> {
  const out = orphanedRevisions(await buildStore(spec), {});
  if (!Array.isArray(out)) throw new Error(out.notEvaluated);
  return out;
}

const list = (items: Obj[]) => dump({ apiVersion: "v1", kind: "List", items });

/** One healthy revision 1-27 serving the default tag and a revision-labelled namespace. */
function base(): Obj[] {
  return [
    namespace("istio-system"),
    namespace("shop", { "istio.io/rev": "1-27" }),
    namespace("legacy", { "istio-injection": "enabled" }),
    ...controlPlane("1-27"),
    injectorWebhook("1-27"),
    injectorWebhook("1-27", { tag: "default" }),
    defaultValidator("1-27"),
    revisionValidator("1-27"),
    injectedPod("shop", "cart", "1-27"),
    injectedPod("legacy", "web", "1-27"),
  ];
}

describe("DIAG-007 round 2", () => {
  it("does not fire on a healthy single-revision install with its validators", async () => {
    const { f, skipped } = await run({ resources: base() });
    expect(skipped).toBeUndefined();
    expect(f).toBeUndefined();
  });

  describe("item 1: a Fail injector with no istiod is critical only when it matches something", () => {
    it("is a warning when it matches no namespace or workload", async () => {
      const { f } = await run({ resources: [...base(), injectorWebhook("1-26", { tag: "old" })] });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContainEqual(
        expect.stringMatching(/^webhook istio-revision-tag-old: calls Service istio-system\/istiod-1-26, which is not in the dump \(failurePolicy Fail, but it matches no namespace or workload today; any pod later labelled for this revision would be rejected\)$/),
      );
    });

    it("is critical when it matches a namespace with a live pod", async () => {
      const resources = [...base(), injectorWebhook("1-26", { tag: "old" }), namespace("orders", { "istio.io/rev": "old" }), plainPod("orders", "api")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-revision-tag-old: .*failurePolicy Fail: creating a pod it matches is rejected; namespaces orders/));
    });

    it("is critical when only a workload pod template matches (no live pod)", async () => {
      for (const kind of ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"] as const) {
        const resources = [...base(), injectorWebhook("1-26", { tag: "old" }), namespace("orders"), workload(kind, "orders", "api", { app: "api", "istio.io/rev": "old" })];
        const { f } = await run({ resources });
        expect(f?.severity, kind).toBe("critical");
      }
    });

    it("does not count a namespace with no pods and no workloads", async () => {
      // The namespace was collected (kube-root-ca.crt), it simply runs nothing.
      const resources = [...base(), injectorWebhook("1-26", { tag: "old" }), namespace("orders", { "istio.io/rev": "old" }), configMap("orders", "kube-root-ca.crt", undefined, { "ca.crt": "PEM" })];
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/istio-revision-tag-old.*matches no namespace or workload today/));
    });

    it("stays critical when a matching namespace was not collected (cannot tell)", async () => {
      const resources = [...base(), injectorWebhook("1-26", { tag: "old" }), namespace("orders", { "istio.io/rev": "old" })];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/istio-revision-tag-old: .*it may match namespaces the dump did not collect\)$/));
    });

    it("is info for an Ignore injector that matches nothing", async () => {
      const { f } = await run({ resources: [...base(), injectorWebhook("1-26", { failurePolicy: "Ignore" })] });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-sidecar-injector-1-26: .*failurePolicy Ignore, but it matches no namespace or workload today/));
    });
  });

  describe("item 2: validating webhooks whose istiod is gone", () => {
    it("is critical for istiod-default-validator with failurePolicy Fail and a missing Service", async () => {
      const resources = base().map((r) => ((r.metadata as Obj).name === "istiod-default-validator" ? defaultValidator("1-26") : r));
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContainEqual(
        "validating webhook istiod-default-validator: calls Service istio-system/istiod-1-26, which is not in the dump (failurePolicy Fail: creating or updating Istio config is rejected)",
      );
    });

    it("is a warning when the failurePolicy is Ignore (validation silently skipped)", async () => {
      const resources = base().map((r) => ((r.metadata as Obj).name === "istiod-default-validator" ? defaultValidator("1-26", { failurePolicy: "Ignore" }) : r));
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(
        "validating webhook istiod-default-validator: calls Service istio-system/istiod-1-26, which is not in the dump (failurePolicy Ignore: Istio config validation silently skipped)",
      );
    });

    it("flags a revision validator whose istiod has no running pod", async () => {
      const resources = [...base(), ...controlPlane("1-26", { replicas: 0 }), revisionValidator("1-26")];
      const vs = { apiVersion: "networking.istio.io/v1", kind: "VirtualService", metadata: { name: "pinned", namespace: "shop", labels: { "istio.io/rev": "1-26" } }, spec: { hosts: ["a"] } };
      const { f } = await run({ resources: [...resources, vs] });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^validating webhook istio-validator-1-26-istio-system: Service istio-system\/istiod-1-26 has no running istiod pod \(failurePolicy Fail: creating or updating Istio config it selects is rejected; 1 object now\)/));
    });

    it("is a warning, not critical, for a revision validator when cluster/crs was not collected", async () => {
      const resources = [...base(), ...controlPlane("1-26", { replicas: 0 }), revisionValidator("1-26")];
      const all = await issues({ resources, files: { "cluster/crs": null } });
      const line = all.find((i) => i.detail.startsWith("validating webhook istio-validator-1-26-istio-system"));
      expect(line?.severity).toBe("warning");
      expect(line?.detail).toMatch(/cluster\/crs was not collected, so whether it selects any config today is unknown/);
    });

    it("is a warning for a revision validator that selects no Istio config today", async () => {
      const resources = [...base(), ...controlPlane("1-26", { replicas: 0 }), revisionValidator("1-26")];
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^validating webhook istio-validator-1-26-istio-system: .*failurePolicy Fail, but it selects no Istio config today; config later labelled for this revision would be rejected\)$/));
      expect(f?.severity).toBe("warning");
    });

    it("says when the default validator's Service is missing on a default-tag mismatch", async () => {
      const resources = base().map((r) => ((r.metadata as Obj).name === "istiod-default-validator" ? defaultValidator("1-28") : r));
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^default revision is 1-28 \(istiod-default-validator\), but the "default" tag .* points to revision 1-27: .*; the validator's Service istio-system\/istiod-1-28 is not in the dump$/));
    });

    it("is skipped (not evaluated) without cluster/k8s-resources", async () => {
      const clusterScoped = [...base().filter((r) => r.kind === "MutatingWebhookConfiguration" || r.kind === "ValidatingWebhookConfiguration" || r.kind === "Namespace")];
      const { f, skipped } = await run({ files: { "cluster/k8s-resources": null, "cluster/k8s-cluster-resources": list(clusterScoped) } });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/webhook Services.*cluster\/k8s-resources missing/);
    });
  });

  describe("item 3: leftovers of a revision with no live istiod", () => {
    it("treats a Deployment scaled to 0 with no running pod as absent and lists all leftovers", async () => {
      const resources = [...base(), ...controlPlane("1-26", { replicas: 0 }), istiodHpa("1-26"), revisionValidator("1-26")];
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContain(
        "revision 1-26 has no running istiod (Deployment istio-system/istiod-1-26 scaled to 0), leftovers: ConfigMaps istio-system/istio-1-26, istio-system/istio-sidecar-injector-1-26; Service istio-system/istiod-1-26; HorizontalPodAutoscaler istio-system/istiod-1-26; ValidatingWebhookConfiguration istio-validator-1-26-istio-system",
      );
    });

    it("keeps a Deployment scaled to 0 whose pod still runs", async () => {
      const cp = controlPlane("1-26", { replicas: 0 });
      const runningPod = { ...(controlPlane("1-26")[4] as Obj) };
      const { f } = await run({ resources: [...base(), ...cp, runningPod] });
      expect(f?.affectedResources ?? []).not.toContainEqual(expect.stringMatching(/^revision 1-26 has no/));
    });
  });

  describe("item 4: a pod istio.io/rev label no injector serves", () => {
    it("warns when the pod has no sidecar (new replicas start outside the mesh)", async () => {
      const resources = [...base(), namespace("orders"), plainPod("orders", "a", { app: "a", "istio.io/rev": "1-20" }), plainPod("orders", "b", { app: "b", "istio.io/rev": "1-20" })];
      const out = await issues({ resources });
      expect(out).toContainEqual({
        detail: "pod label istio.io/rev=1-20 selects no injector webhook (no revision or tag named 1-20): 2 pods without a sidecar, new replicas start outside the mesh: orders: a, b",
        severity: "warning",
        namespace: "orders",
      });
    });

    it("does not flag a pod whose rev label an injector serves, or a pod opted out with inject=false", async () => {
      const resources = [...base(), namespace("orders"), plainPod("orders", "a", { app: "a", "istio.io/rev": "1-20", "sidecar.istio.io/inject": "false" })];
      const { f } = await run({ resources });
      expect(f).toBeUndefined();
    });
  });

  describe("item 5: unserved namespaces", () => {
    it("reports a stale rev label on an ambient namespace as info", async () => {
      const resources = [...base(), namespace("mesh", { "istio.io/rev": "1-26", "istio.io/dataplane-mode": "ambient" })];
      const out = await issues({ resources });
      expect(out).toContainEqual(expect.objectContaining({ severity: "info", namespace: "mesh", detail: expect.stringMatching(/^istio.io\/rev=1-26 selects no injector webhook \(no revision or tag named 1-26\): ambient namespaces mesh \(stale label, the pods stay in ambient\)/) }));
    });

    it("is info when every pod of the namespace is consistently without a proxy", async () => {
      const resources = [...base(), namespace("orders", { "istio.io/rev": "1-26" }), plainPod("orders", "a")];
      const out = await issues({ resources });
      expect(out).toContainEqual({ detail: "istio.io/rev=1-26 selects no injector webhook (no revision or tag named 1-26): namespaces orders; 1 of 1 pod has no istio-proxy", severity: "info", namespace: "orders" });
    });

    it("is a warning when some pods still have a proxy (injected before, new ones will not be)", async () => {
      const resources = [...base(), namespace("orders", { "istio.io/rev": "1-26" }), plainPod("orders", "a"), injectedPod("orders", "b", "1-27")];
      const out = await issues({ resources });
      expect(out).toContainEqual(expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/^istio.io\/rev=1-26 selects no injector webhook .*1 of 2 pods has no istio-proxy$/) }));
    });

    it("stays a warning when the pods were not dumped", async () => {
      const resources = [...base(), namespace("orders", { "istio.io/rev": "1-26" })];
      const out = await issues({ resources });
      expect(out).toContainEqual(expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/namespaces orders; pods not in the dump$/) }));
    });
  });

  describe("item 7: a crash-looping istiod is not running", () => {
    it("strands the pods of a revision whose only istiod pod is not ready", async () => {
      const resources = [namespace("istio-system"), namespace("shop", { "istio.io/rev": "1-27" }), ...controlPlane("1-27", { crashing: true }), injectorWebhook("1-27"), injectedPod("shop", "cart", "1-27")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContain("revision 1-27 has no running istiod: 1 injected pod still on it (shop: cart)");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-sidecar-injector-1-27: Service istio-system\/istiod-1-27 has no running istiod pod/));
    });

    it("still counts a ready istiod next to a crashing one", async () => {
      const resources = [...base(), crashingIstiodPod("1-27")];
      const { f } = await run({ resources });
      expect(f).toBeUndefined();
    });
  });

  describe("general: order and namespaces", () => {
    it("lists the most severe issue first", async () => {
      // The leftover ConfigMap (info) is found before the webhook (critical).
      const resources = [...base(), configMap("istio-system", "istio-1-20", "1-20", { mesh: "x: 1\n" }), injectorWebhook("1-26", { tag: "old" }), namespace("orders", { "istio.io/rev": "old" }), plainPod("orders", "api")];
      const { f } = await run({ resources });
      expect(f?.affectedResources[0]).toMatch(/^webhook istio-revision-tag-old: /);
      expect(f?.affectedResources.at(-1)).toMatch(/^revision 1-20 has no istiod Deployment/);
    });

    it("sets the namespace on per-namespace issues and leaves it unset across namespaces", async () => {
      const resources = [...base(), namespace("a", { "istio.io/rev": "9" }), namespace("b", { "istio.io/rev": "9" }), injectedPod("shop", "old", "1-25")];
      const out = await issues({ resources });
      expect(out.find((i) => i.detail.startsWith("istio.io/rev=9"))?.namespace).toBeUndefined();
      expect(out.find((i) => i.detail.startsWith("revision 1-25"))?.namespace).toBe("shop");
    });

    it("keeps a tag Service pointing at a live revision out of the leftovers", async () => {
      const { f } = await run({ resources: [...base(), tagService("prod", "1-27"), injectorWebhook("1-27", { tag: "prod" })] });
      expect(f).toBeUndefined();
    });
  });
});

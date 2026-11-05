import { describe, it, expect, afterEach } from "vitest";
import { dump } from "js-yaml";
import { cleanupArchives, finding, namespace, runEngine, type ArchiveSpec, type Obj } from "./template-harness.js";
import { configMap, controlPlane, defaultValidator, injectedPod, injectorWebhook, plainPod, tagService, workload } from "./revision-fixtures.js";

afterEach(cleanupArchives);

async function run(spec: ArchiveSpec) {
  const { findings, engine } = await runEngine(spec, ["config"]);
  return { f: finding(findings, "DIAG-007"), skipped: engine.getNotEvaluated().find((s) => s.templateId === "DIAG-007") };
}

const list = (items: Obj[]) => dump({ apiVersion: "v1", kind: "List", items });

/**
 * A correct canary upgrade with stable revision tags: revisions 1-27 and 1-28 both run, tag
 * prod and the default tag point at 1-27 (the old default injector is gone), namespaces are
 * labelled with a tag, a revision or istio-injection, and every pod runs the revision its
 * namespace selects.
 */
function canary(): Obj[] {
  return [
    namespace("istio-system"),
    namespace("shop", { "istio.io/rev": "prod" }),
    namespace("payments", { "istio.io/rev": "1-28" }),
    namespace("legacy", { "istio-injection": "enabled" }),
    namespace("tools", { "istio-injection": "disabled" }),
    ...controlPlane("1-27"),
    ...controlPlane("1-28"),
    injectorWebhook("1-27"),
    injectorWebhook("1-28"),
    injectorWebhook("1-27", { tag: "prod" }),
    injectorWebhook("1-27", { tag: "default" }),
    tagService("prod", "1-27"),
    defaultValidator("1-27"),
    injectedPod("shop", "cart", "1-27"),
    injectedPod("payments", "ledger", "1-28"),
    injectedPod("legacy", "web", "1-27"),
    plainPod("tools", "debug"),
    configMap("shop", "istio-ca-root-cert", undefined, { "root-cert.pem": "PEM" }),
  ];
}

describe("DIAG-007 orphaned revisions, webhooks and tags", () => {
  describe("negative: correct setups do not fire", () => {
    it("a canary upgrade with two running revisions and revision tags", async () => {
      const { f, skipped } = await run({ resources: canary() });
      expect(skipped).toBeUndefined();
      expect(f).toBeUndefined();
    });

    it("a default-revision install plus a revisioned canary, no tags", async () => {
      const resources = [
        namespace("istio-system"),
        namespace("legacy", { "istio-injection": "enabled" }),
        namespace("canary", { "istio.io/rev": "1-28" }),
        ...controlPlane(""),
        ...controlPlane("1-28"),
        injectorWebhook(""),
        injectorWebhook("1-28"),
        defaultValidator("default"),
        injectedPod("legacy", "web", "default"),
        injectedPod("canary", "api", "1-28"),
      ];
      const { f, skipped } = await run({ resources });
      expect(skipped).toBeUndefined();
      expect(f).toBeUndefined();
    });

    it("a default injector deactivated by `istioctl tag set default` next to the default tag", async () => {
      const resources = [...canary(), injectorWebhook("", { deactivated: true, service: "istiod-1-27" })];
      const { f } = await run({ resources });
      expect(f).toBeUndefined();
    });
  });

  describe("rule a: injector webhook whose Service or istiod is gone", () => {
    it("is critical when the Service is missing, failurePolicy is Fail and it matches a workload", async () => {
      const resources = [...canary(), injectorWebhook("1-26", { tag: "old" }), namespace("orders", { "istio.io/rev": "old" }), plainPod("orders", "api")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-revision-tag-old: calls Service istio-system\/istiod-1-26, which is not in the dump \(failurePolicy Fail/));
    });

    it("reads webhooks from cluster/k8s-cluster-resources (istioctl 1.30+)", async () => {
      const resources = canary().filter((r) => r.kind !== "MutatingWebhookConfiguration" && r.kind !== "ValidatingWebhookConfiguration" && r.kind !== "Namespace");
      const clusterScoped = [...canary().filter((r) => r.kind === "MutatingWebhookConfiguration" || r.kind === "ValidatingWebhookConfiguration" || r.kind === "Namespace"), injectorWebhook("1-26", { tag: "old" })];
      const { f } = await run({ resources, files: { "cluster/k8s-cluster-resources": list(clusterScoped) } });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-revision-tag-old: calls Service istio-system\/istiod-1-26/));
    });

    it("is critical when the Service exists but no istiod pod runs behind it", async () => {
      const resources = [...canary(), ...controlPlane("1-26", { replicas: 0 }), injectorWebhook("1-26"), namespace("orders", { "istio.io/rev": "1-26" }), workload("Deployment", "orders", "api")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-sidecar-injector-1-26: Service istio-system\/istiod-1-26 has no running istiod pod/));
    });

    it("is a warning with failurePolicy Ignore (pods start without a sidecar)", async () => {
      const resources = [...canary(), injectorWebhook("1-26", { failurePolicy: "Ignore" }), namespace("orders", { "istio.io/rev": "1-26" }), plainPod("orders", "api")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/istio-sidecar-injector-1-26.*failurePolicy Ignore/));
    });

    it("is info for a deactivated webhook whose Service is gone", async () => {
      const { f } = await run({ resources: [...canary(), injectorWebhook("", { deactivated: true })] });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^webhook istio-sidecar-injector: deactivated .*istio-system\/istiod/));
    });

    it("is not evaluated when no webhook was collected (no MWC, no cluster-scoped dump)", async () => {
      // Pods and control plane only: Namespaces and webhooks were never collected.
      const { f, skipped } = await run({ resources: [...controlPlane("1-27"), injectedPod("shop", "cart", "1-27")] });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/^not evaluated: .*webhook.*cluster\/k8s-cluster-resources is missing/);
    });

    it("is not evaluated when cluster/k8s-cluster-resources is empty", async () => {
      const resources = canary().filter((r) => r.kind !== "MutatingWebhookConfiguration" && r.kind !== "ValidatingWebhookConfiguration" && r.kind !== "Namespace");
      const { skipped } = await run({ resources, files: { "cluster/k8s-cluster-resources": list([]) } });
      expect(skipped?.reason).toMatch(/cluster\/k8s-cluster-resources is empty/);
    });
  });

  describe("rules b and f: namespace injection labels no webhook serves", () => {
    it("flags istio.io/rev values with no revision or tag and counts pods without a proxy (info: consistently unmeshed)", async () => {
      const resources = [...canary(), namespace("orders", { "istio.io/rev": "1-26" }), plainPod("orders", "a"), plainPod("orders", "b")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toContain("istio.io/rev=1-26 selects no injector webhook (no revision or tag named 1-26): namespaces orders; 2 of 2 pods have no istio-proxy");
    });

    it("says when the revision has an istiod Deployment but no webhook", async () => {
      const resources = [...canary(), ...controlPlane("1-29"), namespace("orders", { "istio.io/rev": "1-29" })];
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^istio.io\/rev=1-29 selects no injector webhook \(revision 1-29 has an istiod Deployment but no injector webhook\)/));
    });

    it("flags istio-injection=enabled without a default revision or default tag (rule f)", async () => {
      const resources = canary().filter((r) => (r.metadata as Obj).name !== "istio-revision-tag-default");
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^istio-injection=enabled selects no injector webhook \(no default-revision injector and no "default" revision tag\): namespaces legacy/));
    });

    it("reports a stale label on an ambient namespace as info, and does not judge istio-injection=disabled", async () => {
      const resources = [...canary(), namespace("mesh", { "istio.io/rev": "1-26", "istio.io/dataplane-mode": "ambient" })];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toEqual(["istio.io/rev=1-26 selects no injector webhook (no revision or tag named 1-26): ambient namespaces mesh (stale label, the pods stay in ambient)"]);
    });

    it("is not evaluated without Namespace objects even when webhooks were collected", async () => {
      const resources = canary().filter((r) => r.kind !== "Namespace" && r.kind !== "MutatingWebhookConfiguration" && r.kind !== "ValidatingWebhookConfiguration");
      const webhooks = canary().filter((r) => r.kind === "MutatingWebhookConfiguration" || r.kind === "ValidatingWebhookConfiguration");
      const { skipped } = await run({ resources, files: { "cluster/k8s-cluster-resources": list(webhooks) } });
      expect(skipped?.reason).toMatch(/no Namespace objects/);
    });
  });

  describe("rule c: pods on a revision with no running istiod", () => {
    it("is critical and groups the pods by namespace", async () => {
      const resources = [...canary(), injectedPod("shop", "old-1", "1-25"), injectedPod("shop", "old-2", "1-25")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources).toContain("revision 1-25 has no running istiod: 2 injected pods still on it (shop: old-1, old-2)");
    });

    it("flags a revision whose Deployment was scaled to 0", async () => {
      const resources = [...canary(), ...controlPlane("1-26", { replicas: 0 }), injectedPod("payments", "batch", "1-26")];
      const { f } = await run({ resources });
      expect(f?.affectedResources).toContain("revision 1-26 has no running istiod: 1 injected pod still on it (payments: batch)");
    });

    it("is not evaluated without cluster/k8s-resources (istiod Deployments unknown)", async () => {
      const clusterScoped = canary().filter((r) => r.kind === "MutatingWebhookConfiguration" || r.kind === "ValidatingWebhookConfiguration" || r.kind === "Namespace");
      const { f, skipped } = await run({ files: { "cluster/k8s-resources": null, "cluster/k8s-cluster-resources": list(clusterScoped) } });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/cluster\/k8s-resources missing/);
    });

    it("is not evaluated with no istiod Deployment in the dump (remote or external control plane)", async () => {
      const resources = [namespace("shop", { "istio.io/rev": "1-27" }), injectorWebhook("1-27", { service: "istiod-remote" }), { apiVersion: "v1", kind: "Service", metadata: { name: "istiod-remote", namespace: "istio-system" }, spec: { ports: [{ port: 443 }] } }, injectedPod("shop", "cart", "1-27")];
      const { f, skipped } = await run({ resources });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/no istiod Deployment in the dump/);
    });
  });

  describe("rule d: leftover revision ConfigMaps", () => {
    it("is info and names the ConfigMaps of a revision with no istiod Deployment", async () => {
      const resources = [
        ...canary(),
        configMap("istio-system", "istio-1-25", "1-25", { mesh: "rootNamespace: istio-system\n" }),
        configMap("istio-system", "istio-sidecar-injector-1-25", "1-25", { config: "policy: enabled\n" }),
      ];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toEqual(["revision 1-25 has no istiod Deployment, leftovers: ConfigMaps istio-system/istio-1-25, istio-system/istio-sidecar-injector-1-25"]);
    });
  });

  describe("rule e: default revision and default tag disagree", () => {
    it("flags istiod-default-validator and the default tag on different revisions", async () => {
      const resources = canary().map((r) => ((r.metadata as Obj).name === "istiod-default-validator" ? defaultValidator("1-28") : r));
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^default revision is 1-28 \(istiod-default-validator\), but the "default" tag \(istio-revision-tag-default\) points to revision 1-27/));
    });
  });

  describe("pod revision labels and restarts (catalog NEW-07)", () => {
    it("flags a pod istio.io/rev label that the namespace label overrides", async () => {
      const resources = [...canary(), injectedPod("shop", "pinned", "1-27", { app: "pinned", "istio.io/rev": "1-28" })];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContain("pod label istio.io/rev=1-28 is ignored, the namespace labels select revision 1-27: shop: pinned");
    });

    it("reports pods still on an older revision than their namespace selects as restart pending (info)", async () => {
      const resources = [...canary(), injectedPod("payments", "slow", "1-27")];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources).toContain("1 pod on revision 1-27 where injection now selects 1-28 (restart pending): payments: slow");
    });

    it("flags namespaces two injector webhooks both match", async () => {
      // An active default-revision injector next to the default tag: both serve istio-injection=enabled.
      const resources = [...canary(), injectorWebhook("", { service: "istiod-1-27" })];
      const { f } = await run({ resources });
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^2 injector webhooks match the same pods \(istio-revision-tag-default, istio-sidecar-injector\).*: namespaces legacy/));
    });

    it("does not flag two webhooks that inject the same revision", async () => {
      const copy = injectorWebhook("1-27", { tag: "default" });
      const resources = [...canary(), { ...copy, metadata: { ...(copy.metadata as Obj), name: "istio-revision-tag-default-copy" } }];
      const { f } = await run({ resources });
      expect(f).toBeUndefined();
    });
  });

  it("lists rules it could not evaluate next to the findings of the others", async () => {
    // Webhooks in the cluster-scoped dump show a problem; cluster/k8s-resources is missing.
    const clusterScoped = [...canary().filter((r) => r.kind === "MutatingWebhookConfiguration" || r.kind === "Namespace"), defaultValidator("1-28")];
    const { f } = await run({ files: { "cluster/k8s-resources": null, "cluster/k8s-cluster-resources": list(clusterScoped) } });
    expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^default revision is 1-28/));
    expect(f?.affectedResources).toContainEqual(expect.stringMatching(/^not evaluated here: .*cluster\/k8s-resources missing/));
    expect(f?.severity).toBe("warning");
  });
});

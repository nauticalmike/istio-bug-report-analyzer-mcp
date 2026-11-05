import { describe, it, expect, afterEach } from "vitest";
import { ambientReadinessReport, issueNamespace } from "../../src/tools/ambient-readiness.js";
import { ambientPod, buildStore, cleanupArchives, namespace, sidecarPod } from "../diagnostics/template-harness.js";
import { AMBIENT_NS, INJECTED_NS, authz, crs } from "../diagnostics/ambient-fixtures.js";
import { controlPlane, injectorWebhook } from "../diagnostics/revision-fixtures.js";

afterEach(cleanupArchives);

const textOf = (r: { content: { text: string }[] }) => r.content[0].text;

const l7Allow = authz("shop", "cart-get", {
  selector: { matchLabels: { app: "cart" } },
  rules: [{ to: [{ operation: { methods: ["GET"] } }] }],
});

describe("issueNamespace", () => {
  it("reads the namespace an issue line names", () => {
    expect(issueNamespace("shop/cart-get: rules use methods")).toBe("shop");
    expect(issueNamespace("VirtualService shop/reviews: retries")).toBe("shop");
    expect(issueNamespace("namespace payments: 3 sidecar pods")).toBe("payments");
    expect(issueNamespace("Namespace shop: istio.io/use-waypoint=wp does not take effect")).toBe("shop");
    expect(issueNamespace("meshConfig outboundTrafficPolicy REGISTRY_ONLY")).toBeNull();
  });

  it("never reads a label key or a name in the middle of a line as a namespace", () => {
    expect(issueNamespace("istio.io/rev=1-27 on 3 namespaces")).toBeNull();
    expect(issueNamespace("traffic.sidecar.istio.io/excludeOutboundPorts on Pod shop/api")).toBeNull();
    expect(issueNamespace("webhook calls Service istio-system/istiod-1-27")).toBeNull();
  });
});

describe("ambient_readiness_report", () => {
  it("shows the stage, a namespace table, blockers with fixes and the cutover checklist", async () => {
    const store = await buildStore({
      resources: [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" }), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.27.1")],
      files: crs(l7Allow),
    });
    const text = textOf(await ambientReadinessReport(store, {}));
    expect(text).toMatch(/Migration stage: partial/);
    expect(text).toMatch(/^namespace\s+mode\s+sidecar\s+ambient/m);
    expect(text).toMatch(/^shop\s+ambient\s+0\s+1\s+0\s+-\s+1\s+0\s+0$/m);
    expect(text).toMatch(/^legacy\s+sidecar\s+1\s+0/m);
    expect(text).toMatch(/\[CRITICAL\] DIAG-009: .*\(1\)\n  - \[CRITICAL\] shop\/cart-get: /);
    expect(text).toMatch(/    fix: /);
    expect(text).toMatch(/Cutover checklist:/);
  });

  it("filters rows and issues to one namespace", async () => {
    const other = authz("blog", "post-get", { selector: { matchLabels: { app: "post" } }, rules: [{ to: [{ operation: { paths: ["/x"] } }] }] });
    const store = await buildStore({
      resources: [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" }), namespace("blog", AMBIENT_NS), ambientPod("blog", "post", { app: "post" })],
      files: crs(l7Allow, other),
    });
    const text = textOf(await ambientReadinessReport(store, { namespace: "blog" }));
    expect(text).toMatch(/blog\/post-get/);
    expect(text).not.toMatch(/shop\/cart-get/);
    expect(text).not.toMatch(/^shop\s/m);
  });

  it("lists checks that could not run when cluster/crs is missing", async () => {
    const store = await buildStore({ resources: [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart")], files: { "cluster/crs": null } });
    const text = textOf(await ambientReadinessReport(store, {}));
    expect(text).toMatch(/Not evaluated or skipped:\n(.*\n)*  - DIAG-009 .*not evaluated/);
  });

  it("judges a sidecar-only mesh as if the migration were planned", async () => {
    const l7Legacy = authz("legacy", "api-get", { selector: { matchLabels: { app: "api" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const store = await buildStore({ resources: [...controlPlane(""), injectorWebhook(""), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.27.1")], files: crs(l7Legacy) });
    const text = textOf(await ambientReadinessReport(store, {}));
    expect(text).toMatch(/Migration stage: none: .*as if a migration were planned/);
    expect(text).toMatch(/\[WARNING\] legacy\/api-get: /);
    expect(text).not.toMatch(/\[CRITICAL\] legacy\//);
  });

  it("counts every issue per namespace by Issue.namespace and pages long sections under the budget", async () => {
    // 3000 L7 policies in one namespace: one section far over the output budget.
    const policies = Array.from({ length: 3000 }, (_, i) =>
      authz("shop", `policy-with-a-rather-long-name-${i}`, { selector: { matchLabels: { app: "cart" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] }));
    const store = await buildStore({ resources: [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })], files: crs(...policies) });
    const first = textOf(await ambientReadinessReport(store, {}));
    expect(first.length).toBeLessThan(100_000);
    expect(first).toMatch(/^shop\s+ambient\s+0\s+1\s+0\s+-\s+3000\s+0\s+0$/m);
    expect(first).toMatch(/DIAG-009: .*\(3000\)/);
    const next = /Pass offset=(\d+) for more/.exec(first);
    expect(next).not.toBeNull();
    const second = textOf(await ambientReadinessReport(store, { offset: Number(next![1]) }));
    expect(second.length).toBeLessThan(100_000);
    expect(second).toMatch(/DIAG-009: .*\(continued\)/);
    expect(second).toMatch(/  - \[CRITICAL\] shop\/policy-with-a-rather-long-name-/);
  });

  it("leaves out the mesh checks that are not about ambient readiness (security pack)", async () => {
    const store = await buildStore({ resources: [namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.27.1")] });
    const text = textOf(await ambientReadinessReport(store, {}));
    expect(text).not.toMatch(/DIAG-02[3-9]/);
  });

  it("says when nothing blocks a migration", async () => {
    const store = await buildStore({ resources: [...controlPlane(""), injectorWebhook(""), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.27.1")] });
    const text = textOf(await ambientReadinessReport(store, {}));
    expect(text).toMatch(/Migration stage: none/);
    expect(text).toMatch(/No readiness blockers found/);
  });
});

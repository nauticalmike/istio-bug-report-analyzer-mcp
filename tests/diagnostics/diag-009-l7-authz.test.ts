import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, namespace, sidecarPod, waypoint, type Obj } from "./template-harness.js";
import { AMBIENT_NS, INJECTED_NS, authz, crs, istioResource, runCheck, ztunnelDaemonSet } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

function rootCa(ns: string): Obj {
  return { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "kube-root-ca.crt", namespace: ns }, data: { "ca.crt": "x" } };
}

const run = (resources: Obj[], files: Record<string, string | null>) => runCheck("DIAG-009", "security", { resources, files });

// An ambient namespace with one ambient workload, plus the fixture's sidecar pod: stage partial.
const ambientShop = [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];

const l7Allow = authz("shop", "cart-get", {
  selector: { matchLabels: { app: "cart" } },
  action: "ALLOW",
  rules: [{ from: [{ source: { namespaces: ["front"] } }], to: [{ operation: { methods: ["GET"] } }] }],
});

describe("DIAG-009 L7 AuthorizationPolicy enforced by ztunnel", () => {
  it("flags an ALLOW selector policy whose every rule uses HTTP attributes (deny-all at ztunnel)", async () => {
    const { f } = await run(ambientShop, crs(l7Allow));
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toHaveLength(1);
    expect(f?.affectedResources[0]).toMatch(/^shop\/cart-get: /);
    expect(f?.affectedResources[0]).toMatch(/methods/);
    expect(f?.affectedResources[0]).toMatch(/deny all traffic/);
    expect(f?.affectedResources[0]).toMatch(/1 ambient pod/);
  });

  it("reports an ALLOW policy where only some rules use HTTP attributes", async () => {
    const pol = authz("shop", "cart-mixed", {
      selector: { matchLabels: { app: "cart" } },
      rules: [{ from: [{ source: { namespaces: ["front"] } }] }, { to: [{ operation: { paths: ["/admin"] } }] }],
    });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/1 of 2 rules can never match/);
  });

  it("explains that a DENY on HTTP-only attributes has no effect at ztunnel", async () => {
    const pol = authz("shop", "deny-admin", { selector: { matchLabels: { app: "cart" } }, action: "DENY", rules: [{ to: [{ operation: { paths: ["/admin*"] } }] }] });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/no effect at ztunnel/);
  });

  it("explains that a DENY mixing L4 and HTTP attributes denies more than intended", async () => {
    const pol = authz("shop", "deny-post", { action: "DENY", rules: [{ to: [{ operation: { ports: ["8080"], methods: ["POST"] } }] }] });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/without its HTTP conditions/);
  });

  it("explains that a DENY with HTTP-only alternatives beside L4 ones stops denying those alternatives", async () => {
    // Separate elements: istiod keeps the port element and drops the HTTP-only one, so POST on other ports is no longer denied.
    const pol = authz("shop", "deny-split", { action: "DENY", rules: [{ to: [{ operation: { ports: ["8080"] } }, { operation: { methods: ["POST"] } }] }] });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/alternatives that use only HTTP attributes are dropped/);
    expect(f?.affectedResources[0]).not.toMatch(/more than intended/);
  });

  it("flags CUSTOM actions and request.* conditions", async () => {
    const custom = authz("shop", "ext-authz", { selector: { matchLabels: { app: "cart" } }, action: "CUSTOM", provider: { name: "opa" }, rules: [{}] });
    const when = authz("shop", "jwt-claim", { selector: { matchLabels: { app: "cart" } }, rules: [{ when: [{ key: "request.auth.claims[group]", values: ["admin"] }] }] });
    const { f } = await run(ambientShop, crs(custom, when));
    const details = f?.affectedResources.join("\n") ?? "";
    expect(details).toMatch(/shop\/ext-authz: action CUSTOM is not supported by ztunnel/);
    expect(details).toMatch(/shop\/jwt-claim: .*request\.auth\.claims\[group\]/);
  });

  it("includes the istiod ZtunnelAccepted status when it reports UnsupportedValue for the current generation", async () => {
    const status = { conditions: [{ type: "ZtunnelAccepted", status: "True", reason: "UnsupportedValue", observedGeneration: 2, message: "ztunnel does not support HTTP attributes (found: methods)." }] };
    const pol = authz("shop", "cart-get", l7Allow.spec as Obj, { status });
    (pol.metadata as Obj).generation = 2;
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/istiod status ZtunnelAccepted: UnsupportedValue/);
  });

  it("does not cite a ZtunnelAccepted status written for an older generation of the policy", async () => {
    const status = { conditions: [{ type: "ZtunnelAccepted", status: "True", reason: "UnsupportedValue", observedGeneration: 1 }] };
    const pol = authz("shop", "cart-get", l7Allow.spec as Obj, { status });
    (pol.metadata as Obj).generation = 3;
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/^shop\/cart-get: /);
    expect(f?.affectedResources[0]).not.toMatch(/ZtunnelAccepted/);
  });

  it("sets the policy's namespace on its issue, and none on a mesh-wide root-namespace policy", async () => {
    const mesh = authz("istio-system", "mesh-get-only", { rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const { f } = await run(ambientShop, crs(l7Allow, mesh));
    const byDetail = new Map(f?.issues?.map((i) => [i.detail.split(":")[0], i.namespace]));
    expect(byDetail.get("shop/cart-get")).toBe("shop");
    expect(byDetail.has("istio-system/mesh-get-only")).toBe(true);
    expect(byDetail.get("istio-system/mesh-get-only")).toBeUndefined();
  });

  it("describes a mesh-wide scope holding ambient and sidecar pods with both counts", async () => {
    const pol = authz("istio-system", "mesh-get-only", { rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/1 ambient pod \(shop\) and 1 sidecar pod \(default\)/);
  });

  it("groups one policy copied into several namespaces into one line with example namespaces", async () => {
    const copies = ["a1", "a2", "a3"].map((n) => authz(n, "cart-get", { ...(l7Allow.spec as Obj) }));
    const resources = ["a1", "a2", "a3"].flatMap((n) => [namespace(n, AMBIENT_NS), ambientPod(n, "cart", { app: "cart" })]);
    const { f } = await run(resources, crs(...copies));
    expect(f?.affectedResources).toHaveLength(1);
    expect(f?.affectedResources[0]).toMatch(/^AuthorizationPolicy cart-get in 3 namespaces \(a1, a2, a3\): no rule can match/);
    expect(f?.affectedResources[0]).toMatch(/3 ambient pods/);
    expect(f?.issues?.[0].namespace).toBeUndefined();
  });

  it("applies root-namespace policies without a selector to ambient workloads mesh-wide", async () => {
    const pol = authz("istio-system", "mesh-get-only", { rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/^istio-system\/mesh-get-only: /);
    expect(f?.affectedResources[0]).toMatch(/1 ambient pod/);
  });

  it("notes from.source.trustDomains, which ztunnel ignores without a status condition", async () => {
    const pol = authz("shop", "td", { selector: { matchLabels: { app: "cart" } }, rules: [{ from: [{ source: { namespaces: ["front"], trustDomains: ["old.example"] } }] }] });
    const { f } = await run(ambientShop, crs(pol));
    expect(f?.affectedResources[0]).toMatch(/trustDomains .*ignored/);
  });

  it("is a migration-blocker warning while the selected workloads are still sidecars (ztunnel installed)", async () => {
    const pol = authz("legacy", "legacy-get", { selector: { matchLabels: { app: "api" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const resources = [ztunnelDaemonSet(), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2", { app: "api" })];
    const { f } = await run(resources, crs(pol));
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toMatch(/1 sidecar pod .*migration/);
  });

  it("flags selector-based RequestAuthentication, WasmPlugin and Telemetry on ambient pods", async () => {
    const sel = { selector: { matchLabels: { app: "cart" } } };
    const ra = istioResource("security.istio.io/v1", "RequestAuthentication", "shop", "jwt", { ...sel, jwtRules: [{ issuer: "https://issuer.example" }] });
    const wasm = istioResource("extensions.istio.io/v1alpha1", "WasmPlugin", "shop", "filter", { ...sel, url: "oci://registry.example/filter:1" });
    const tel = istioResource("telemetry.istio.io/v1", "Telemetry", "shop", "logs", { ...sel, accessLogging: [{ providers: [{ name: "envoy" }] }] });
    const { f } = await run(ambientShop, crs(ra, wasm, tel));
    const details = f?.affectedResources.join("\n") ?? "";
    expect(details).toMatch(/shop\/jwt: RequestAuthentication with a selector/);
    expect(details).toMatch(/shop\/filter: WasmPlugin with a selector/);
    expect(details).toMatch(/shop\/logs: Telemetry with a selector/);
    expect(f?.severity).toBe("critical");
  });

  it("reports a selector Telemetry on ambient pods as info: it is not a security control", async () => {
    const tel = istioResource("telemetry.istio.io/v1", "Telemetry", "shop", "logs", { selector: { matchLabels: { app: "cart" } }, accessLogging: [{ providers: [{ name: "envoy" }] }] });
    const { f } = await run(ambientShop, crs(tel));
    expect(f?.severity).toBe("info");
    expect(f?.issues?.[0]).toMatchObject({ severity: "info", namespace: "shop" });
  });

  it("flags targetRefs that resolve to nothing: a Gateway in another namespace, or more than 16 refs", async () => {
    const cross = authz("shop", "via-shared-waypoint", { targetRefs: [{ kind: "Gateway", group: "gateway.networking.k8s.io", name: "shared" }], rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const many = authz("shop", "many-refs", {
      targetRefs: Array.from({ length: 17 }, (_, i) => ({ kind: "Service", group: "", name: `svc-${i}` })),
      rules: [{ to: [{ operation: { methods: ["GET"] } }] }],
    });
    const { f } = await run(ambientShop, crs(waypoint("mesh-infra", "shared"), cross, many));
    const details = f?.affectedResources.join("\n") ?? "";
    expect(details).toMatch(/shop\/via-shared-waypoint: targetRefs Gateway "shared" .*mesh-infra/);
    expect(details).toMatch(/shop\/many-refs: 17 targetRefs/);
  });

  it("flags a targetRef with a namespace on a selector-free RequestAuthentication too", async () => {
    const ra = istioResource("security.istio.io/v1", "RequestAuthentication", "shop", "jwt", { targetRefs: [{ kind: "Service", group: "", name: "cart", namespace: "other" }], jwtRules: [{ issuer: "https://issuer.example" }] });
    const { f } = await run(ambientShop, crs(ra));
    expect(f?.affectedResources[0]).toMatch(/^shop\/jwt: targetRefs Service\/cart sets namespace other/);
  });

  it("leaves policies targeting a Service with no waypoint to DIAG-012 (reported once)", async () => {
    const pol = authz("shop", "svc-ref", { targetRefs: [{ kind: "Service", group: "", name: "cart" }], rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
    const { f, skipped } = await run(ambientShop, crs(pol));
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("lists every issue (the tools cap what they print)", async () => {
    const policies = Array.from({ length: 25 }, (_, i) => authz("shop", `p-${String(i).padStart(2, "0")}`, l7Allow.spec as Obj));
    const { f } = await run(ambientShop, crs(...policies));
    expect(f?.affectedResources).toHaveLength(25);
    expect(f?.affectedResources.some((d) => d.includes("more)"))).toBe(false);
  });

  describe("does not fire on correct configurations", () => {
    it("an L4-only selector policy on ambient pods", async () => {
      const pol = authz("shop", "l4", { selector: { matchLabels: { app: "cart" } }, rules: [{ from: [{ source: { principals: ["cluster.local/ns/front/sa/web"] } }], to: [{ operation: { ports: ["8080"] } }] }] });
      const { f, skipped } = await run(ambientShop, crs(pol));
      expect(f).toBeUndefined();
      expect(skipped).toBeUndefined();
    });

    it("an L7 policy attached with targetRefs to a ready waypoint", async () => {
      const pol = authz("shop", "at-waypoint", { targetRefs: [{ kind: "Gateway", group: "gateway.networking.k8s.io", name: "waypoint" }], rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
      const { f } = await run([...ambientShop, namespace("shop", { ...AMBIENT_NS, "istio.io/use-waypoint": "waypoint" })], crs(waypoint("shop", "waypoint"), pol));
      expect(f).toBeUndefined();
    });

    it("an L7 selector policy on sidecar pods in a sidecar-only mesh", async () => {
      const pol = authz("legacy", "legacy-get", { selector: { matchLabels: { app: "api" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
      const { f, skipped } = await run([namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2", { app: "api" })], crs(pol));
      expect(f).toBeUndefined();
      expect(skipped).toBeUndefined();
    });

    it("an L7 selector policy whose selector matches no ambient pod", async () => {
      const pol = authz("shop", "other", { selector: { matchLabels: { app: "nothing-here" } }, rules: [{ to: [{ operation: { methods: ["GET"] } }] }] });
      const { f } = await run(ambientShop, crs(pol));
      expect(f).toBeUndefined();
    });

    it("a dry-run policy", async () => {
      const pol = authz("shop", "dry", l7Allow.spec as Obj, { annotations: { "istio.io/dry-run": "true" } });
      const { f } = await run(ambientShop, crs(pol));
      expect(f).toBeUndefined();
    });
  });

  describe("missing input", () => {
    it("is not evaluated without cluster/crs", async () => {
      const { f, skipped } = await run(ambientShop, { "cluster/crs": null });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toBe("not evaluated: cluster/crs missing (data completeness: crs)");
    });

    it("is not evaluated without cluster/k8s-resources", async () => {
      const { f, skipped } = await run([], { ...crs(l7Allow), "cluster/k8s-resources": null });
      expect(f).toBeUndefined();
      expect(skipped?.reason).toMatch(/^not evaluated: cluster\/k8s-resources missing/);
    });

    it("judges a namespace the pod dump does not cover by its label, never as \"selects no pods\"", async () => {
      // shop has no object at all while istio-system has: a namespace-scoped dump (--include) left it out.
      const { f } = await run([namespace("shop", AMBIENT_NS), namespace("istio-system"), rootCa("istio-system"), ztunnelDaemonSet()], crs(l7Allow));
      expect(f?.affectedResources[0]).toMatch(/^shop\/cart-get: /);
    });

    it("does not fire for a namespace whose pods are all absent from a complete dump", async () => {
      // Every namespace has kube-root-ca.crt, so a complete dump shows an object in each.
      const { f, skipped } = await run([namespace("shop", AMBIENT_NS), rootCa("shop"), namespace("istio-system"), rootCa("istio-system"), ztunnelDaemonSet()], crs(l7Allow));
      expect(f).toBeUndefined();
      expect(skipped).toBeUndefined();
    });
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, deployment, namespace, service, sidecarPod } from "./template-harness.js";
import { AMBIENT_NS, INJECTED_NS, authz, crs, istioResource, runCheck } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

const ID = "DIAG-029";

type Obj = Record<string, unknown>;

const pa = (ns: string, name: string, spec: Obj, created = "2026-01-01T00:00:00Z") => {
  const r = istioResource("security.istio.io/v1", "PeerAuthentication", ns, name, spec);
  (r.metadata as Obj).creationTimestamp = created;
  return r;
};
const meshStrict = pa("istio-system", "default", { mtls: { mode: "STRICT" } });
const meshAuthz = authz("istio-system", "allow-in-mesh", { rules: [{ from: [{ source: { principals: ["cluster.local/*"] } }] }] });

const withPorts = (p: Obj, ports: number[]): Obj => {
  const spec = p.spec as { containers: Obj[] };
  spec.containers[0].ports = ports.map((containerPort) => ({ containerPort }));
  return p;
};

const shopNs = namespace("shop", INJECTED_NS);
const cart = withPorts(sidecarPod("shop", "cart", "1.31.2", { app: "cart" }), [8080]);
const cartSvc = service("shop", "cart", { app: "cart" }, {}, [{ name: "http", port: 80, targetPort: 8080 }]);
const base = [shopNs, cart, cartSvc];

describe("DIAG-029 mTLS posture", () => {
  it("finds nothing on a hardened mesh: mesh-wide STRICT, no overrides, authorization everywhere", async () => {
    const { f, skipped } = await runCheck(ID, "security", { resources: base, files: crs(meshStrict, meshAuthz) });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("summarizes the posture as one info line when it deviates from the baseline", async () => {
    const legacyNs = namespace("legacy", INJECTED_NS);
    const api = sidecarPod("legacy", "api", "1.31.2", { app: "api" });
    const { f } = await runCheck(ID, "security", {
      resources: [...base, legacyNs, api],
      files: crs(
        pa("legacy", "permissive", { mtls: { mode: "PERMISSIVE" } }),
        pa("shop", "cart-disable", { selector: { matchLabels: { app: "cart" } }, mtls: { mode: "STRICT" }, portLevelMtls: { "8080": { mode: "DISABLE" } } }),
        authz("shop", "cart-allow", { selector: { matchLabels: { app: "cart" } }, rules: [{}] }),
      ),
    });
    expect(f?.severity).toBe("info");
    expect(f!.issues).toHaveLength(1);
    const s = f!.issues![0];
    expect(s.severity).toBe("info");
    expect(s.namespaces).toEqual([]);
    expect(s.detail).toMatch(/no mesh-wide STRICT PeerAuthentication in istio-system/);
    expect(s.detail).toMatch(/PERMISSIVE overrides: namespace legacy/);
    expect(s.detail).toMatch(/DISABLE: shop\/cart-disable \(port 8080\)/);
    expect(s.detail).toMatch(/no AuthorizationPolicy: .*legacy/);
    expect(s.detail).not.toMatch(/no AuthorizationPolicy: [^;]*shop/);
  });

  it("warns when a DestinationRule sends plaintext to backends that require mTLS", async () => {
    const plain = istioResource("networking.istio.io/v1", "DestinationRule", "shop", "cart-plain", { host: "cart.shop.svc.cluster.local", trafficPolicy: { tls: { mode: "DISABLE" } } });
    const { f } = await runCheck(ID, "security", { resources: base, files: crs(meshStrict, meshAuthz, plain) });
    expect(f!.issues!.map((i) => [i.severity, i.detail])).toEqual([
      ["warning", expect.stringMatching(/^DestinationRule shop\/cart-plain: tls.mode DISABLE toward Service shop\/cart, whose 1 mesh pod .*reject.* plaintext/)],
    ]);
  });

  it("does not warn about a DestinationRule DISABLE when no Envoy client applies it (ambient-only mesh)", async () => {
    const meshNs = namespace("mesh", AMBIENT_NS);
    const web = withPorts(ambientPod("mesh", "web", { app: "web" }), [8080]);
    const webSvc = service("mesh", "web", { app: "web" }, {}, [{ name: "http", port: 80, targetPort: 8080 }]);
    const plain = istioResource("networking.istio.io/v1", "DestinationRule", "mesh", "web-plain", { host: "web.mesh.svc.cluster.local", trafficPolicy: { tls: { mode: "DISABLE" } } });
    // The pod dump without the fixture's sidecar pod: no Envoy client at all.
    const istiodOnly = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\nspec:\n  containers:\n    - name: discovery\n";
    const { f } = await runCheck(ID, "security", { resources: [meshNs, web, webSvc], files: { ...crs(meshStrict, meshAuthz, plain), "cluster/pods": istiodOnly, "proxies/default/test-pod-abc123/istio-proxy.log": null } });
    expect(f!.issues!.filter((i) => i.severity === "warning").map((i) => i.detail)).toEqual([]);
    expect(f!.issues![0].detail).toMatch(/mesh\/web-plain \(no sidecar, gateway or waypoint client in the dump applies it\)/);
  });

  it("resolves a named Service targetPort against portLevelMtls before warning about a DestinationRule DISABLE", async () => {
    const named = withPorts(sidecarPod("shop", "cart", "1.31.2", { app: "cart" }), [8080]);
    ((named.spec as { containers: Obj[] }).containers[0].ports as Obj[])[0].name = "http-app";
    const svc = service("shop", "cart", { app: "cart" }, {}, [{ name: "http", port: 80, targetPort: "http-app" }]);
    const plain = istioResource("networking.istio.io/v1", "DestinationRule", "shop", "cart-plain", { host: "cart.shop.svc.cluster.local", trafficPolicy: { tls: { mode: "DISABLE" } } });
    const permissive = pa("shop", "cart-port", { selector: { matchLabels: { app: "cart" } }, portLevelMtls: { "8080": { mode: "PERMISSIVE" } } });
    const ok = await runCheck(ID, "security", { resources: [shopNs, named, svc], files: crs(meshStrict, meshAuthz, plain, permissive) });
    expect(ok.f?.issues?.some((i) => i.severity === "warning") ?? false).toBe(false);
    const strict = await runCheck(ID, "security", { resources: [shopNs, named, svc], files: crs(meshStrict, meshAuthz, plain) });
    expect(strict.f!.issues!.find((i) => i.severity === "warning")!.detail).toMatch(/target port 8080/);
  });

  it("warns when a webhook or CRD conversion Service is backed by pods that require mTLS", async () => {
    const hookPod = withPorts(sidecarPod("shop", "hooks", "1.31.2", { app: "hooks" }), [9443]);
    const hookSvc = service("shop", "hooks", { app: "hooks" }, {}, [{ name: "https", port: 443, targetPort: 9443 }]);
    const mwc = { apiVersion: "admissionregistration.k8s.io/v1", kind: "MutatingWebhookConfiguration", metadata: { name: "shop-defaults" }, webhooks: [{ name: "defaults.shop.example.com", clientConfig: { service: { namespace: "shop", name: "hooks", path: "/mutate" } } }] };
    const crd = { apiVersion: "apiextensions.k8s.io/v1", kind: "CustomResourceDefinition", metadata: { name: "carts.shop.example.com" }, spec: { conversion: { strategy: "Webhook", webhook: { clientConfig: { service: { namespace: "shop", name: "hooks", port: 443 } } } } } };
    const { f } = await runCheck(ID, "security", { resources: [...base, hookPod, hookSvc, mwc, crd], files: crs(meshStrict, meshAuthz) });
    const w = f!.issues!.find((i) => /kube-apiserver/.test(i.detail))!;
    expect(w.severity).toBe("warning");
    expect(w.detail).toMatch(/CustomResourceDefinition carts\.shop\.example\.com conversion, MutatingWebhookConfiguration shop-defaults call Service shop\/hooks port 443.*target port 9443/);
    const fixed = pa("shop", "hooks-port", { selector: { matchLabels: { app: "hooks" } }, portLevelMtls: { "9443": { mode: "PERMISSIVE" } } });
    const ok = await runCheck(ID, "security", { resources: [...base, hookPod, hookSvc, mwc, crd], files: crs(meshStrict, meshAuthz, fixed) });
    expect(ok.f?.issues?.some((i) => /kube-apiserver/.test(i.detail)) ?? false).toBe(false);
  });

  it("does not warn about a DestinationRule DISABLE toward ztunnel-captured backends: Envoy clients send HBONE", async () => {
    const meshNs = namespace("mesh", AMBIENT_NS);
    const web = withPorts(ambientPod("mesh", "web", { app: "web" }), [8080]);
    const webSvc = service("mesh", "web", { app: "web" }, {}, [{ name: "http", port: 80, targetPort: 8080 }]);
    const plain = istioResource("networking.istio.io/v1", "DestinationRule", "mesh", "web-plain", { host: "web.mesh.svc.cluster.local", trafficPolicy: { tls: { mode: "DISABLE" } } });
    const istiod = (env: Obj[]) => deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", env }] });
    const ambientOn = { name: "PILOT_ENABLE_AMBIENT", value: "true" };
    const on = await runCheck(ID, "security", { resources: [...base, meshNs, web, webSvc, istiod([ambientOn])], files: crs(meshStrict, meshAuthz, plain) });
    expect(on.f!.issues!.filter((i) => i.severity === "warning")).toEqual([]);
    expect(on.f!.issues![0].detail).toMatch(/mesh\/web-plain \(its backends are ztunnel-captured: sidecar, gateway and waypoint clients send HBONE to them, which ztunnel accepts\)/);
    const off = await runCheck(ID, "security", { resources: [...base, meshNs, web, webSvc, istiod([ambientOn, { name: "PILOT_ENABLE_SENDING_HBONE", value: "false" }])], files: crs(meshStrict, meshAuthz, plain) });
    expect(off.f!.issues!.find((i) => i.severity === "warning")!.detail).toMatch(/^DestinationRule mesh\/web-plain: tls.mode DISABLE/);
  });

  it("skips webhook ports a sidecar does not capture, and lowers a webhook with failurePolicy Ignore to info", async () => {
    const hook = (annotations: Record<string, string>) => {
      const p = withPorts(sidecarPod("shop", "hooks", "1.31.2", { app: "hooks" }), [9443]);
      (p.metadata as Obj).annotations = annotations;
      return p;
    };
    const hookSvc = service("shop", "hooks", { app: "hooks" }, {}, [{ name: "https", port: 443, targetPort: 9443 }]);
    const mwc = (failurePolicy?: string) => ({ apiVersion: "admissionregistration.k8s.io/v1", kind: "MutatingWebhookConfiguration", metadata: { name: "shop-defaults" }, webhooks: [{ name: "defaults.shop.example.com", ...(failurePolicy ? { failurePolicy } : {}), clientConfig: { service: { namespace: "shop", name: "hooks", path: "/mutate" } } }] });
    const run = (annotations: Record<string, string>, failurePolicy?: string) => runCheck(ID, "security", { resources: [...base, hook(annotations), hookSvc, mwc(failurePolicy)], files: crs(meshStrict, meshAuthz) });
    const excluded = await run({ "traffic.sidecar.istio.io/excludeInboundPorts": "15020,9443" });
    expect(excluded.f?.issues?.some((i) => /kube-apiserver/.test(i.detail)) ?? false).toBe(false);
    const notIncluded = await run({ "traffic.sidecar.istio.io/includeInboundPorts": "8080" });
    expect(notIncluded.f?.issues?.some((i) => /kube-apiserver/.test(i.detail)) ?? false).toBe(false);
    const captured = await run({ "traffic.sidecar.istio.io/includeInboundPorts": "*" });
    expect(captured.f!.issues!.find((i) => /kube-apiserver/.test(i.detail))!.severity).toBe("warning");
    const ignore = await run({}, "Ignore");
    const w = ignore.f!.issues!.find((i) => /kube-apiserver/.test(i.detail))!;
    expect(w.severity).toBe("info");
    expect(w.detail).toMatch(/so these calls fail and, with failurePolicy Ignore, are skipped silently \(requests are admitted without the webhook's mutation or validation\)/);
    expect(w.detail).not.toMatch(/so these calls fail;/);
  });

  it("collapses generated PERMISSIVE PeerAuthentications by their generator", async () => {
    const gen = (i: number) => {
      const r = pa("shop", `gen-${i}`, { selector: { matchLabels: { app: `svc-${i}` } }, mtls: { mode: "PERMISSIVE" } });
      (r.metadata as Obj).ownerReferences = [{ apiVersion: "example.com/v1", kind: "MeshPolicy", name: "shop-policy", uid: "1" }];
      return r;
    };
    const { f } = await runCheck(ID, "security", { resources: base, files: crs(meshAuthz, ...Array.from({ length: 8 }, (_, i) => gen(i))) });
    const s = f!.issues![0].detail;
    expect(s).toMatch(/PERMISSIVE overrides: 8 policies generated by MeshPolicy shop-policy \(change the generator's source config\)/);
    expect(s).not.toMatch(/gen-3/);
  });

  it("reports several PeerAuthentications selecting one workload with the effective mode", async () => {
    const a = pa("shop", "cart-strict", { selector: { matchLabels: { app: "cart" } }, mtls: { mode: "STRICT" } }, "2026-01-01T00:00:00Z");
    const b = pa("shop", "cart-permissive", { selector: { matchLabels: { app: "cart" } }, mtls: { mode: "PERMISSIVE" } }, "2026-02-01T00:00:00Z");
    const { f } = await runCheck(ID, "security", { resources: base, files: crs(meshStrict, meshAuthz, a, b) });
    const c = f!.issues!.find((i) => /select/.test(i.detail))!;
    expect(c.severity).toBe("warning");
    expect(c.detail).toMatch(/shop\/cart-permissive, shop\/cart-strict select the same 1 pod .*only the oldest, shop\/cart-strict.*effective mode STRICT/);
    expect(c.namespace).toBe("shop");
  });

  it("reports portLevelMtls on ports the pods do not expose, and on a Service port instead of the target port", async () => {
    const p = pa("shop", "cart-ports", { selector: { matchLabels: { app: "cart" } }, portLevelMtls: { "80": { mode: "PERMISSIVE" }, "9090": { mode: "PERMISSIVE" }, "8080": { mode: "PERMISSIVE" } } });
    const { f } = await runCheck(ID, "security", { resources: base, files: crs(meshStrict, meshAuthz, p) });
    const d = f!.issues!.filter((i) => /portLevelMtls/.test(i.detail));
    expect(d.map((i) => [i.severity, i.detail]).sort()).toEqual([
      ["info", expect.stringMatching(/shop\/cart-ports portLevelMtls 9090: no selected pod declares that container port/)],
      ["warning", expect.stringMatching(/shop\/cart-ports portLevelMtls 80: a Service port; portLevelMtls takes the container \(target\) port 8080/)],
    ]);
  });

  it("counts a Service target port as served when no container declares it", async () => {
    const bare = sidecarPod("shop", "cart", "1.31.2", { app: "cart" });
    const p = pa("shop", "cart-ports", { selector: { matchLabels: { app: "cart" } }, portLevelMtls: { "8080": { mode: "PERMISSIVE" }, "9090": { mode: "PERMISSIVE" } } });
    const { f } = await runCheck(ID, "security", { resources: [shopNs, bare, cartSvc], files: crs(meshStrict, meshAuthz, p) });
    const d = f!.issues!.filter((i) => /portLevelMtls/.test(i.detail)).map((i) => i.detail);
    expect(d).toEqual([expect.stringMatching(/portLevelMtls 9090: no selected pod declares that container port and no Service targets it/)]);
  });

  it("reports portLevelMtls on a selector-less policy (ignored) when DIAG-011 does not", async () => {
    const p = pa("shop", "ns-ports", { mtls: { mode: "STRICT" }, portLevelMtls: { "8080": { mode: "DISABLE" } } });
    const { f } = await runCheck(ID, "security", { resources: base, files: crs(meshStrict, meshAuthz, p) });
    expect(f!.issues!.some((i) => /shop\/ns-ports.*no selector.*ignored/.test(i.detail))).toBe(true);
    // With ambient in the mesh, DIAG-011 reports the same policy: no duplicate here.
    const amb = await runCheck(ID, "security", {
      resources: [...base, namespace("mesh", AMBIENT_NS), ambientPod("mesh", "web")],
      files: crs(meshStrict, meshAuthz, p),
    });
    expect(amb.f?.issues?.some((i) => /ns-ports/.test(i.detail)) ?? false).toBe(false);
  });

  it("is not evaluated without cluster/crs", async () => {
    const { skipped } = await runCheck(ID, "security", { resources: base, files: { "cluster/crs": null } });
    expect(skipped?.reason).toMatch(/not evaluated/);
  });
});

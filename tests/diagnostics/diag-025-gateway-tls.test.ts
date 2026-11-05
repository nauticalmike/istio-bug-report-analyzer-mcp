import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, namespace, pod } from "./template-harness.js";
import { crs, istioResource, runCheck } from "./ambient-fixtures.js";
import { SECRETS_TABLE } from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

const ID = "DIAG-025";
const ISTIOD_LOG = "istio/istio-system/istiod-abc/discovery.log";
const GW_POD = "shop-gateway-7c9d5f6b8-qq2rt";
const GW_LOG = `proxies/shop/${GW_POD}/istio-proxy.log`;

const gatewayPod = pod("shop", GW_POD, { istio: "shop-gateway" }, [{ name: "istio-proxy", args: ["proxy", "router"] }]);
const base = [namespace("shop"), namespace("payments"), namespace("certs"), gatewayPod];

const istioGateway = (name: string, servers: Record<string, unknown>[], ns = "shop") =>
  istioResource("networking.istio.io/v1", "Gateway", ns, name, { selector: { istio: "shop-gateway" }, servers });

const https = (credentialName: string, mode = "SIMPLE") => ({ port: { number: 443, name: "https", protocol: "HTTPS" }, hosts: ["shop.example.com"], tls: { mode, credentialName } });

const apiGateway = (name: string, refs: Record<string, unknown>[], ns = "shop") =>
  istioResource("gateway.networking.k8s.io/v1", "Gateway", ns, name, {
    gatewayClassName: "istio",
    listeners: [{ name: "https", port: 443, protocol: "HTTPS", tls: { mode: "Terminate", certificateRefs: refs } }],
  });

const grant = (ns: string, fromNs: string) =>
  istioResource("gateway.networking.k8s.io/v1beta1", "ReferenceGrant", ns, "allow", {
    from: [{ group: "gateway.networking.k8s.io", kind: "Gateway", namespace: fromNs }],
    to: [{ group: "", kind: "Secret" }],
  });

const secrets = (extra: string[] = []) => ({ "cluster/secrets": [SECRETS_TABLE.trimEnd(), ...extra, ""].join("\n") });

describe("DIAG-025 gateway TLS credentials", () => {
  it("is critical for an istio Gateway credentialName with no Secret in the gateway pods' namespace", async () => {
    const gw = istioGateway("web", [https("shop-example-com-cert"), https("missing-cert")]);
    const { f } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), ...secrets() } });
    expect(f?.severity).toBe("critical");
    expect(f!.issues!.map((i) => i.detail)).toEqual([expect.stringMatching(/^Gateway shop\/web servers\[1\] \(port 443\) credentialName missing-cert: no Secret shop\/missing-cert/)]);
    expect(f!.issues![0].namespaces).toEqual(["shop"]);
  });

  it("refuses an istio Gateway credentialName in another namespace, and resolves kubernetes:// and ns/name forms", async () => {
    const gw = istioGateway("web", [https("payments/payments-registry"), https("kubernetes://shop-example-com-cert"), https("shop/cart-db"), https("builtin://")]);
    const { f } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), ...secrets() } });
    expect(f!.issues!.map((i) => i.detail)).toEqual([expect.stringMatching(/servers\[0\].*names a Secret in payments, but the gateway pods run in shop/)]);
  });

  it("ignores PASSTHROUGH and ISTIO_MUTUAL servers", async () => {
    const gw = istioGateway("web", [https("nope", "PASSTHROUGH"), https("nope", "ISTIO_MUTUAL")]);
    const { f, skipped } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), ...secrets() } });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("checks Gateway API certificateRefs in the Gateway namespace and across namespaces with ReferenceGrant", async () => {
    const gw = apiGateway("api", [{ name: "missing" }, { name: "wild", namespace: "certs" }, { name: "shop-example-com-cert" }]);
    const ungranted = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), ...secrets(["certs          wild                       kubernetes.io/tls                     2      1d"]) } });
    expect(ungranted.f!.issues!.map((i) => i.detail).sort()).toEqual([
      expect.stringMatching(/certificateRef certs\/wild: is in namespace certs with no ReferenceGrant/),
      expect.stringMatching(/certificateRef missing: no Secret shop\/missing/),
    ]);
    const granted = await runCheck(ID, "security", { resources: base, files: { ...crs(gw, grant("certs", "shop")), ...secrets(["certs          wild                       kubernetes.io/tls                     2      1d"]) } });
    expect(granted.f!.issues!.map((i) => i.detail)).toEqual([expect.stringMatching(/certificateRef missing/)]);
  });

  it("reports SDS and Envoy log lines (missing, expired, key mismatch, refused) grouped by credential", async () => {
    const istiodLog = [
      "2026-03-18T10:00:00Z\twarn\tads\tfailed to fetch key and certificate for kubernetes://shop-old-cert: secret shop/shop-old-cert not found",
      "2026-03-18T10:00:30Z\twarn\tads\tfailed to fetch key and certificate for kubernetes://shop-old-cert: secret shop/shop-old-cert not found",
      '2026-03-18T10:01:00Z\twarn\tads\tinvalid certificates: shop/shop-example-com-cert "kubernetes://shop-example-com-cert": certificate is expired or not yet valid',
      "2026-03-18T10:02:00Z\twarn\tads\tproxy shop-gateway-7c9d5f6b8-qq2rt.shop attempted to access unauthorized certificates other-cert: cross namespace secret reference requires ReferenceGrant",
      "",
    ].join("\n");
    const gwLog = "2026-03-18T10:03:00Z\twarning\tenvoy config\tgRPC config for type.googleapis.com/envoy.config.listener.v3.Listener rejected: Failed to load private key from <inline>, Cert chain and private key mismatch: KEY_VALUES_MISMATCH\n";
    const { f } = await runCheck(ID, "security", { resources: base, files: { [ISTIOD_LOG]: istiodLog, [GW_LOG]: gwLog, ...secrets() } });
    const d = f!.issues!.map((i) => i.detail);
    expect(d).toEqual(expect.arrayContaining([
      expect.stringMatching(/kubernetes:\/\/shop-old-cert.*\(2 lines from 1 pod\)/),
      expect.stringMatching(/certificate shop\/shop-example-com-cert is invalid/),
      expect.stringMatching(/refused credentials other-cert/),
      expect.stringMatching(/1 proxy .*KEY_VALUES_MISMATCH/),
    ]));
    expect(f!.issues!.every((i) => i.severity === "critical")).toBe(true);
    // A key mismatch is one finding, not also a "failed to load" one.
    expect(d.filter((x) => /KEY_VALUES_MISMATCH|failed to load/.test(x))).toHaveLength(1);
    expect(f!.issues!.find((i) => /is invalid/.test(i.detail))!.namespace).toBe("shop");
  });

  it("is not evaluated when a Gateway names credentials but cluster/secrets is missing", async () => {
    const gw = istioGateway("web", [https("missing-cert")]);
    const { f, skipped } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), "cluster/secrets": null } });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/cluster\/secrets was not collected/);
  });

  it("does not call a Secret missing when cluster/secrets lists nothing or has no NAMESPACE column", async () => {
    const gw = istioGateway("web", [https("missing-cert"), https("payments/payments-registry")]);
    for (const content of ["", "No resources found\n", "NAME                       TYPE                DATA   AGE\nshop-example-com-cert      kubernetes.io/tls   2      12d\n"]) {
      const { f } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), "cluster/secrets": content } });
      const d = f!.issues!.map((i) => i.detail);
      expect(d.some((x) => /no Secret shop\/missing-cert/.test(x))).toBe(false);
      // The cross-namespace reference does not need the listing.
      expect(d.some((x) => /servers\[1\].*names a Secret in payments/.test(x))).toBe(true);
      expect(f!.issues!.find((i) => /^partly evaluated/.test(i.detail))!.detail).toMatch(/missing-Secret cross-check/);
    }
  });

  it("judges a missing Secret only in namespaces the listing covers", async () => {
    const gw = istioGateway("web", [https("missing-cert")]);
    const otherNsOnly = ["NAMESPACE      NAME      TYPE      DATA   AGE", "payments       registry  Opaque    1      5d", ""].join("\n");
    const { f, skipped } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), "cluster/secrets": otherNsOnly } });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("folds a failing -cacert Secret into its base Secret's line", async () => {
    const istiodLog = [
      "2026-03-18T10:00:00Z\twarn\tads\tfailed to fetch key and certificate for kubernetes://shop-mtls: secret shop/shop-mtls not found",
      "2026-03-18T10:00:00Z\twarn\tads\tfailed to fetch ca certificate for kubernetes://shop-mtls-cacert: secret shop/shop-mtls not found",
      "2026-03-18T10:00:00Z\twarn\tads\tfailed to fetch ca certificate for kubernetes://other-cacert: secret shop/other not found",
      "",
    ].join("\n");
    const { f } = await runCheck(ID, "security", { resources: base, files: { [ISTIOD_LOG]: istiodLog, ...secrets() } });
    const d = f!.issues!.map((i) => i.detail);
    expect(d.filter((x) => /shop-mtls/.test(x))).toEqual([expect.stringMatching(/kubernetes:\/\/shop-mtls: .*its -cacert Secret too, 1 line/)]);
    expect(d.some((x) => /kubernetes:\/\/other-cacert/.test(x))).toBe(true);
  });

  it("words a DestinationRule credentialName failure as TLS origination, not a listener certificate", async () => {
    const dr = istioResource("networking.istio.io/v1", "DestinationRule", "shop", "partner", { host: "api.partner.example.com", trafficPolicy: { tls: { mode: "MUTUAL", credentialName: "partner-client" } } });
    const istiodLog = "2026-03-18T10:00:00Z\twarn\tads\tfailed to fetch key and certificate for kubernetes://partner-client: secret shop/partner-client not found\n";
    const { f } = await runCheck(ID, "security", { resources: base, files: { [ISTIOD_LOG]: istiodLog, ...crs(dr), ...secrets() } });
    const i = f!.issues!.find((x) => /partner-client/.test(x.detail))!;
    expect(i.detail).toMatch(/DestinationRule shop\/partner.*TLS origination/);
    expect(i.detail).not.toMatch(/listeners/);
  });

  it("finds nothing when every credential exists", async () => {
    const gw = istioGateway("web", [https("shop-example-com-cert")]);
    const { f, skipped } = await runCheck(ID, "security", { resources: base, files: { ...crs(gw), ...secrets() } });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });
});

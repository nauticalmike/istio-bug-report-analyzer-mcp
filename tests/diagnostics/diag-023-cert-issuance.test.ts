import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, deployment, namespace, pod } from "./template-harness.js";
import { runCheck } from "./ambient-fixtures.js";
import { CLUSTER_PODS } from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

const ID = "DIAG-023";
const ISTIOD_LOG = "istio/istio-system/istiod-abc/discovery.log";
const cartLog = "proxies/shop/cart-6d8f9c7b5-x2x4q/istio-proxy.log";
const paymentsLog = "proxies/payments/payments-5f7d8b9c6-k8m2n/istio-proxy.log";
const ztunnelLog = "proxies/istio-system/ztunnel-4k2lp/istio-proxy.log";
const ztunnelDump = "proxies/istio-system/ztunnel-4k2lp/config_dump";

const lines = (...l: string[]) => [...l, ""].join("\n");

const STILL_FAILING = lines(
  "2026-03-18T10:00:00.000000Z\twarn\tca\tca request failed, starting attempt 1 in 101ms",
  "2026-03-18T10:00:01.000000Z\terror\tcitadelclient\tfailed to sign CSR: rpc error: code = Unavailable",
  "2026-03-18T10:00:01.000000Z\twarn\tsds\tfailed to warm certificate: failed to generate workload certificate: create certificate: rpc error",
  "2026-03-18T10:05:01.000000Z\twarn\tsds\tfailed to warm certificate: failed to generate workload certificate: create certificate: rpc error",
);

const RECOVERED = lines(
  "2026-03-18T10:00:00.000000Z\twarn\tca\tca request failed, starting attempt 1 in 101ms",
  "2026-03-18T10:00:01.000000Z\twarn\tsds\tfailed to warm certificate: failed to generate workload certificate: create certificate: rpc error",
  "2026-03-18T10:00:05.000000Z\tinfo\tcache\tgenerated new workload certificate\tlatency=4s ttl=23h59m58s",
);

const HEALTHY = lines("2026-03-18T10:00:05.000000Z\tinfo\tcache\tgenerated new workload certificate\tlatency=40ms ttl=23h59m59s");

const ZTUNNEL_FAILING = lines(
  '2026-03-18T10:00:00.000000Z\twarn\tidentity::manager\tcertificate fetch failed (signing gRPC error (Unauthenticated)) and no valid existing certificate; will retry in 1s id=spiffe://cluster.local/ns/shop/sa/cart',
  '2026-03-18T10:00:02.000000Z\twarn\tidentity::manager\tcertificate fetch failed (signing gRPC error (Unauthenticated)) and no valid existing certificate; will retry in 2s id=spiffe://cluster.local/ns/shop/sa/cart',
  '2026-03-18T10:00:03.000000Z\twarn\tidentity::manager\tcertificate fetch failed (signing gRPC error (Unauthenticated)) and no valid existing certificate; will retry in 2s id=spiffe://cluster.local/ns/shop/sa/web',
);

const impersonation = (reason: string, at = "10:00:00") =>
  `2026-03-18T${at}.000000Z\twarn\tserverca\timpersonation failed for identity spiffe://cluster.local/ns/shop/sa/cart, error: ${reason}\tclient=10.0.0.4:5555`;

const NO_INSTANCES = lines(impersonation('no instances of "shop/cart" found on node "node-1"'), impersonation('no instances of "shop/web" found on node "node-1"', "10:00:01"));

const TOKEN_INVALID = lines(
  "2026-03-18T10:00:00.000000Z\terror\tsecurity\tFailed to authenticate client from 10.0.0.7:4444: Authenticator KubeJWTAuthenticator: failed to validate the JWT from cluster \"Kubernetes\": service account token has been invalidated",
);

/** One failed CSR attempt as pilot-agent logs it: the citadel client line and the SDS warm line. */
const attempt = (at: string, err: string) => [
  `2026-03-18T${at}.000000Z\terror\tcitadelclient\tfailed to sign CSR: create certificate: ${err}`,
  `2026-03-18T${at}.000000Z\twarn\tsds\tfailed to warm certificate: failed to generate workload certificate: create certificate: ${err}`,
];

const at = (hhmmss: string) => `2026-03-18T${hhmmss}.000000Z`;
const issuedAt = (hhmmss: string, latency: string, ttl: string) => `${at(hhmmss)}\tinfo\tcache\tgenerated new workload certificate\tresourceName=default latency=${latency} ttl=${ttl}`;
const retryAt = (hhmmss: string) => `${at(hhmmss)}\twarn\tca\tca request failed, starting attempt 1 in 101ms`;
const signAt = (hhmmss: string) => `${at(hhmmss)}\terror\tcitadelclient\tfailed to sign CSR: create certificate: rpc error: code = Unavailable desc = connection refused`;
const proxyLog = (ns: string, name: string) => `proxies/${ns}/${name}/istio-proxy.log`;

/** A pod that got a 1h certificate at 10:00, failed to renew from 10:30 and got the next one at 11:05 (latency 35m). */
const EXPIRED_THEN_RENEWED = lines(issuedAt("10:00:00", "40ms", "1h0m0s"), retryAt("10:30:00"), signAt("10:30:01"), signAt("10:50:00"), issuedAt("11:05:00", "35m0s", "59m59s"));

describe("DIAG-023 workload certificate issuance", () => {
  it("is critical when proxies keep failing after their last issued certificate, info for a startup race that recovered", async () => {
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: STILL_FAILING, [paymentsLog]: RECOVERED } });
    expect(f?.severity).toBe("critical");
    const critical = f!.issues!.find((i) => i.severity === "critical")!;
    expect(critical.detail).toMatch(/1 proxy .*still fail.*end of their log/);
    expect(critical.detail).toMatch(/2 failed attempts, longest span 5m/);
    expect(critical.detail).toMatch(/shop\/cart-6d8f9c7b5-x2x4q/);
    expect(critical.namespaces).toEqual(["shop"]);
    const recovered = f!.issues!.find((i) => i.severity === "info" && /proxy/.test(i.detail))!;
    expect(recovered.detail).toMatch(/1 proxy .*startup race/);
    expect(recovered.namespaces).toEqual(["payments"]);
  });

  it("counts one attempt per failed CSR, not one per line, and ignores the gRPC retry lines", async () => {
    const three = lines(...attempt("10:00:00", "rpc error: code = Unavailable desc = connection refused"), ...attempt("10:00:20", "rpc error: code = Unavailable desc = connection refused"), ...attempt("10:00:40", "rpc error: code = Unavailable desc = connection refused"));
    const retries = Array.from({ length: 12 }, (_, i) => `2026-03-18T10:00:${String(i).padStart(2, "0")}.000000Z\twarn\tca\tca request failed, starting attempt ${i + 1} in 200ms`);
    const retriedThenIssued = lines(...retries, "2026-03-18T10:01:00.000000Z\tinfo\tcache\tgenerated new workload certificate");
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: three, [paymentsLog]: retriedThenIssued } });
    const proxyLines = f!.issues!.filter((i) => /prox/.test(i.detail));
    expect(proxyLines).toHaveLength(1);
    expect(proxyLines[0].severity).toBe("critical");
    expect(proxyLines[0].detail).toMatch(/3 failed attempts/);
    expect(proxyLines[0].detail).toMatch(/CA error: connection refused/);
    expect(proxyLines[0].detail).not.toMatch(/payments/);
  });

  it("is a warning for failures over several minutes before success and for a single failure with no success yet", async () => {
    const sustained = lines(...attempt("10:00:00", "rpc error: code = Unavailable"), ...attempt("10:06:00", "rpc error: code = Unavailable"), "2026-03-18T10:07:00.000000Z\tinfo\tcache\tgenerated new workload certificate");
    const once = lines("2026-03-18T10:00:00.000000Z\twarn\tsds\tfailed to warm certificate: rpc error: code = Unavailable");
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: once, [paymentsLog]: sustained } });
    expect(f?.severity).toBe("warning");
    const d = f!.issues!.map((i) => `${i.severity} ${i.detail}`);
    expect(d).toEqual(expect.arrayContaining([expect.stringMatching(/^warning 1 proxy .*5m or more.*payments\//), expect.stringMatching(/^warning 1 proxy .*have none since.*shop\//)]));
  });

  it("classifies the CA error of each failing pod (DNS, expired CA certificate, GOAWAY)", async () => {
    const dns = lines(...attempt("10:00:00", "dial tcp: lookup istiod.istio-system.svc on 10.96.0.10:53: no such host"), ...attempt("10:02:00", "dial tcp: lookup istiod.istio-system.svc on 10.96.0.10:53: no such host"));
    const expired = lines(...attempt("10:00:00", "x509: certificate has expired or is not yet valid"), ...attempt("10:02:00", "x509: certificate has expired or is not yet valid"));
    const calm = lines(...attempt("10:00:00", 'rpc error: code = Unavailable desc = closing transport due to: connection error: desc = "error reading from server: EOF", received prior goaway: code: ENHANCE_YOUR_CALM'), ...attempt("10:02:00", "received prior goaway: code: ENHANCE_YOUR_CALM"));
    const thirdLog = "proxies/shop/web-7b9c8d6f5-p4q7r/istio-proxy.log";
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: dns, [paymentsLog]: expired, [thirdLog]: calm } });
    const critical = f!.issues!.find((i) => i.severity === "critical")!;
    expect(critical.detail).toMatch(/3 proxies/);
    expect(critical.detail).toContain("DNS lookup of the CA address failed (1 pod)");
    expect(critical.detail).toContain("an expired or not yet valid certificate (CA or root) (1 pod)");
    expect(critical.detail).toContain("GOAWAY ENHANCE_YOUR_CALM");
    expect(critical.detail).not.toContain("istiod.istio-system.svc");
  });

  it("reports ztunnel certificate fetch failures with distinct identities, and a prefetch the CA rejects as critical", async () => {
    const prefetch = lines('2026-03-18T10:00:05.000000Z\terror\tcert_fetcher\tunable to prefetch cert for "spiffe://cluster.local/ns/shop/sa/cart", skipping, Signing(Status { code: Unauthenticated, message: "authentication failure" })');
    const { f } = await runCheck(ID, "security", { files: { [ztunnelLog]: ZTUNNEL_FAILING + prefetch, [ztunnelDump]: JSON.stringify({ workloads: [] }), "cluster/pods": CLUSTER_PODS } });
    const z = f!.issues!.find((i) => /certificate fetch failed/.test(i.detail))!;
    expect(z.severity).toBe("critical");
    expect(z.detail).toMatch(/1 ztunnel pod .*2 identities.*3 lines.*Unauthenticated/);
    const p = f!.issues!.find((i) => /prefetch/.test(i.detail))!;
    expect(p.severity).toBe("critical");
    expect(p.detail).toMatch(/rejected by the CA/);
  });

  it("words impersonation failures by their reason, never as a trust-domain mismatch", async () => {
    const { f } = await runCheck(ID, "security", {
      files: { [ISTIOD_LOG]: NO_INSTANCES + lines(impersonation("caller (ztunnel) is not allowed to impersonate", "10:01:00"), impersonation("pod found, but UID does not match: a vs b", "10:02:00")) },
      meshDebug: { trustDomain: "corp.example" },
    });
    const d = f!.issues!.filter((x) => /impersonation/.test(x.detail));
    const by = (re: RegExp) => d.find((x) => re.test(x.detail))!;
    expect(by(/no instances on node/).severity).toBe("warning");
    expect(by(/no instances on node/).detail).toMatch(/2 lines from 1 istiod pod/);
    expect(by(/caller not allowed/).severity).toBe("critical");
    expect(by(/caller not allowed/).detail).toMatch(/CA_TRUSTED_NODE_ACCOUNTS/);
    expect(by(/pod UID mismatch/).severity).toBe("info");
    expect(d.map((x) => x.detail).join("\n")).not.toMatch(/trust domain/);
  });

  it("does not report a stale-log note alone, and is not evaluated when every log is of a pod no longer in the dump", async () => {
    const stale = { "istio/istio-system/istiod-old/discovery.log": lines(impersonation("caller (ztunnel) is not allowed to impersonate")) };
    const some = await runCheck(ID, "security", { files: stale });
    expect(some.f).toBeUndefined();
    expect(some.skipped).toBeUndefined();
    const all = await runCheck(ID, "security", { istiodPods: ["istiod-old"], files: { ...stale, "proxies/default/test-pod-abc123/istio-proxy.log": null } });
    expect(all.f).toBeUndefined();
    expect(all.skipped?.reason).toMatch(/not evaluated: .*istiod log.* no longer in the dump/);
  });

  it("words istiod client-authentication rejections as xDS authentication when istiod is not the CA, and adds CA context", async () => {
    const istiod = deployment("istio-system", "istiod", {
      labels: { app: "istiod" },
      replicas: 1,
      containers: [{ name: "discovery", env: [{ name: "ENABLE_CA_SERVER", value: "false" }] }],
    });
    const { f } = await runCheck(ID, "security", { resources: [istiod], files: { [ISTIOD_LOG]: TOKEN_INVALID, [cartLog]: STILL_FAILING } });
    const authn = f!.issues!.find((i) => /rejected client authentication/.test(i.detail))!;
    expect(authn.severity).toBe("warning");
    expect(authn.detail).toMatch(/service account token invalidated/);
    expect(authn.detail).toMatch(/xDS connections, not certificate requests/);
    const ctx = f!.issues!.find((i) => /^CA context/.test(i.detail))!;
    expect(ctx.detail).toMatch(/ENABLE_CA_SERVER=false/);
    expect(ctx.detail).toMatch(/1 istiod pod/);
  });

  it("grades a renewal that took longer than the remaining lifetime as an expired certificate, never a startup race", async () => {
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: EXPIRED_THEN_RENEWED } });
    expect(f?.severity).toBe("warning");
    const d = f!.issues!.find((i) => /expired/.test(i.detail))!;
    expect(d.severity).toBe("warning");
    expect(d.detail).toMatch(/^1 proxy .*renewed their workload certificate only after it had expired/);
    expect(d.detail).toMatch(/certificate TTL 1h; renewal starts 30m before expiry/);
    expect(d.detail).toMatch(/without a valid certificate for up to 5m/);
    expect(d.detail).toMatch(/between 2026-03-18T10:30Z and 2026-03-18T11:05Z/);
    expect(f!.issues!.map((i) => i.detail).join("\n")).not.toMatch(/startup/);
  });

  it("is critical when many proxies renewed only after expiry, and grades by latency= when the earlier certificate is outside the log", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 9; i++) files[proxyLog("shop", `cart-6d8f9c7b5-p${i}`)] = EXPIRED_THEN_RENEWED;
    // No issued line before the failures, which start an hour into the log: a renewal, graded by its latency.
    files[proxyLog("payments", "payments-5f7d8b9c6-k8m2n")] = lines(`${at("09:00:00")}\tinfo\tsds\tSDS: PUSH`, retryAt("10:00:00"), retryAt("10:00:01"), issuedAt("10:40:00", "40m0s", "1h0m0s"));
    const { f } = await runCheck(ID, "security", { files });
    const d = f!.issues!.find((i) => /only after it had expired/.test(i.detail))!;
    expect(d.severity).toBe("critical");
    expect(d.detail).toMatch(/^10 proxies/);
    expect(d.detail).toMatch(/CA retries only|failed attempts/);
    expect(d.detail).toMatch(/payments\/payments-5f7d8b9c6-k8m2n/);
  });

  it("words a short renewal retry as info, a renewal still failing before expiry as a warning, and after expiry as critical", async () => {
    const brief = lines(issuedAt("00:00:00", "40ms", "24h0m0s"), signAt("12:00:00"), issuedAt("12:00:05", "5s", "23h59m55s"));
    const failingValid = lines(issuedAt("00:00:00", "40ms", "24h0m0s"), signAt("12:00:00"), signAt("12:05:00"), signAt("12:10:00"));
    const failingExpired = lines(issuedAt("10:00:00", "40ms", "1h0m0s"), signAt("10:30:00"), signAt("10:50:00"), signAt("11:10:00"));
    const webLog = proxyLog("shop", "web-7b9c8d6f5-p4q7r");
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: brief, [paymentsLog]: failingValid, [webLog]: failingExpired } });
    const by = (re: RegExp) => f!.issues!.find((i) => re.test(i.detail))!;
    expect(by(/renewed it before it expired/).severity).toBe("info");
    expect(by(/renewed it before it expired/).detail).toMatch(/shop\/cart-/);
    expect(by(/fail to renew .*still valid/).severity).toBe("warning");
    expect(by(/fail to renew .*still valid/).detail).toMatch(/still valid for at least 11\.8h/);
    expect(by(/no valid workload certificate since it expired/).severity).toBe("critical");
    expect(by(/no valid workload certificate since it expired/).detail).toMatch(/expired up to 10m before the end of the log/);
    expect(f!.issues!.map((i) => i.detail).join("\n")).not.toMatch(/startup race/);
  });

  it("adds expired-certificate evidence from the proxy certs dump", async () => {
    const failingExpired = lines(issuedAt("10:00:00", "40ms", "1h0m0s"), signAt("10:30:00"), signAt("10:50:00"), signAt("11:10:00"));
    const certs = JSON.stringify({ certificates: [{ ca_cert: [{ expiration_time: "2036-01-01T00:00:00Z" }], cert_chain: [{ serial_number: "abc", subject_alt_names: [{ uri: "spiffe://cluster.local/ns/shop/sa/cart" }], expiration_time: "2026-03-18T11:00:00Z" }] }] });
    const { f } = await runCheck(ID, "security", { files: { [cartLog]: failingExpired, "proxies/shop/cart-6d8f9c7b5-x2x4q/certs": certs } });
    const d = f!.issues!.find((i) => /certs dump/.test(i.detail))!;
    expect(d.severity).toBe("critical");
    expect(d.detail).toMatch(/the certs dump of 1 proxy .*holds an expired workload certificate \(expired up to 10m before the end of their log\): shop\/cart-6d8f9c7b5-x2x4q/);
    expect(d.detail).not.toMatch(/spiffe|abc/);
  });

  it("says the result is partial when only istiod logs were collected", async () => {
    const { f } = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: NO_INSTANCES, "proxies/default/test-pod-abc123/istio-proxy.log": null } });
    const p = f!.issues!.find((i) => /^partial/.test(i.detail))!;
    expect(p.severity).toBe("info");
    expect(p.detail).toMatch(/partial: istiod logs only, no proxy logs were collected/);
  });

  describe("deleted service accounts (istiod's line names no namespace)", () => {
    const saGone = lines(
      `${at("10:00:00")}\terror\tsecurity\tFailed to authenticate client from 10.0.0.7:4444: Authenticator KubeJWTAuthenticator: failed to validate the JWT from cluster "Kubernetes": the service account authentication returns an error: serviceaccounts "cart" not found`,
    );
    const cartPod = () => {
      const p = pod("shop", "cart-6d8f9c7b5-x2x4q", { app: "cart" }, [{ name: "istio-proxy", args: ["proxy", "sidecar"] }]);
      (p.spec as Record<string, unknown>).serviceAccountName = "cart";
      return p;
    };
    const sa = (ns: string, name: string) => ({ apiVersion: "v1", kind: "ServiceAccount", metadata: { namespace: ns, name } });
    const UNAUTHENTICATED = lines(
      ...attempt("10:00:00", "rpc error: code = Unauthenticated desc = request authenticate failure"),
      ...attempt("10:05:00", "rpc error: code = Unauthenticated desc = request authenticate failure"),
    );
    const deleted = (f: { issues?: { detail: string }[] } | undefined) => f!.issues!.find((i) => /service account deleted/.test(i.detail))! as { detail: string; severity: string; namespaces?: string[] };

    it("matches a still-failing proxy by account name only for wording, without raising to critical", async () => {
      const { f } = await runCheck(ID, "security", { resources: [namespace("shop"), cartPod()], files: { [ISTIOD_LOG]: saGone, [cartLog]: STILL_FAILING } });
      const d = deleted(f);
      expect(d.severity).toBe("warning");
      expect(d.detail).toMatch(/service account cart no longer exists/);
      expect(d.detail).not.toMatch(/still-failing proxy run as it/);
      expect(d.detail).toMatch(/1 still-failing proxy runs as a service account of that name \(not confirmed: istiod's log names no namespace\): shop\/cart-6d8f9c7b5-x2x4q/);
      const alone = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: saGone } });
      expect(deleted(alone.f).severity).toBe("warning");
    });

    it("is critical when the proxy's own CA error is Unauthenticated", async () => {
      const { f } = await runCheck(ID, "security", { resources: [namespace("shop"), cartPod()], files: { [ISTIOD_LOG]: saGone, [cartLog]: UNAUTHENTICATED } });
      const d = deleted(f);
      expect(d.severity).toBe("critical");
      expect(d.detail).toMatch(/1 still-failing proxy run as it: shop\/cart-6d8f9c7b5-x2x4q/);
      expect(d.namespaces).toEqual(["shop"]);
    });

    it("is critical when the dump lists the pod's namespace's ServiceAccounts and that one is absent", async () => {
      const { f } = await runCheck(ID, "security", { resources: [namespace("shop"), cartPod(), sa("shop", "default")], files: { [ISTIOD_LOG]: saGone, [cartLog]: STILL_FAILING } });
      const d = deleted(f);
      expect(d.severity).toBe("critical");
      expect(d.detail).toMatch(/1 still-failing proxy run as it: shop\/cart-6d8f9c7b5-x2x4q/);
    });

    it("does not tie a proxy to the deleted account when its ServiceAccount is still in the dump", async () => {
      const { f } = await runCheck(ID, "security", { resources: [namespace("shop"), cartPod(), sa("shop", "default"), sa("shop", "cart")], files: { [ISTIOD_LOG]: saGone, [cartLog]: STILL_FAILING } });
      const d = deleted(f);
      expect(d.severity).toBe("warning");
      expect(d.detail).not.toMatch(/cart-6d8f9c7b5-x2x4q/);
    });
  });

  it("grades ztunnel prefetch failures per identity: repeated or still failing is critical, a single line a warning, a gone short-lived pod info", async () => {
    const prefetchLine = (hhmmss: string, sa: string) => `${at(hhmmss)}\terror\tcert_fetcher\tunable to prefetch cert for "spiffe://cluster.local/ns/shop/sa/${sa}", skipping, Signing(Status { code: Unavailable, message: "connection refused" })`;
    const shopPod = pod("shop", "web-7b9c8d6f5-p4q7r", { app: "web" }, [{ name: "app" }]);
    (shopPod.spec as Record<string, unknown>).serviceAccountName = "web";
    const log = lines(prefetchLine("10:00:00", "web"), prefetchLine("10:03:00", "web"), prefetchLine("10:00:00", "web-once"), prefetchLine("10:00:00", "job"));
    const webOnce = pod("shop", "web-once-1", { app: "web-once" }, [{ name: "app" }]);
    (webOnce.spec as Record<string, unknown>).serviceAccountName = "web-once";
    const { f } = await runCheck(ID, "security", {
      resources: [namespace("shop"), shopPod, webOnce],
      files: { [ztunnelLog]: log, [ztunnelDump]: JSON.stringify({ workloads: [] }), "cluster/pods": CLUSTER_PODS },
    });
    const p = f!.issues!.filter((i) => /prefetch/.test(i.detail));
    const by = (sev: string) => p.find((i) => i.severity === sev)!.detail;
    expect(by("critical")).toMatch(/1 identity \(shop\/web\)/);
    expect(by("warning")).toMatch(/1 identity \(shop\/web-once\)/);
    expect(by("info")).toMatch(/1 identity \(shop\/job\).*short-lived/);
  });

  describe("ztunnel identities whose certificate is available at collection", () => {
    const prefetchLine = (hhmmss: string, sa: string) => `${at(hhmmss)}\terror\tcert_fetcher\tunable to prefetch cert for "spiffe://cluster.local/ns/shop/sa/${sa}", skipping, Signing(Status { code: Unavailable, message: "connection refused" })`;
    const certsDump = (rows: { sa: string; state: string }[]) =>
      JSON.stringify({ workloads: [], certificates: rows.map((r) => ({ identity: `spiffe://cluster.local/ns/shop/sa/${r.sa}`, state: r.state, certChain: [], rootCerts: [] })) });
    const saPod = (name: string, sa: string) => {
      const p = pod("shop", name, { app: sa }, [{ name: "app" }]);
      (p.spec as Record<string, unknown>).serviceAccountName = sa;
      return p;
    };

    it("does not call a fetch failure critical when ztunnel's config_dump holds the certificate as Available", async () => {
      const { f } = await runCheck(ID, "security", {
        files: { [ztunnelLog]: ZTUNNEL_FAILING, [ztunnelDump]: certsDump([{ sa: "cart", state: "Available" }, { sa: "web", state: "Available" }]), "cluster/pods": CLUSTER_PODS },
      });
      const z = f!.issues!.find((i) => /certificate fetch failed/.test(i.detail))!;
      expect(z.severity).toBe("warning");
      expect(z.detail).toContain("recovered: certificate available at collection");
      expect(z.detail).not.toContain("cannot send or accept mesh traffic");
    });

    it("keeps the fetch failure critical for the identity still Unavailable and names the recovered ones", async () => {
      const { f } = await runCheck(ID, "security", {
        files: { [ztunnelLog]: ZTUNNEL_FAILING, [ztunnelDump]: certsDump([{ sa: "cart", state: "Unavailable: signing gRPC error" }, { sa: "web", state: "Available" }]), "cluster/pods": CLUSTER_PODS },
      });
      const z = f!.issues!.find((i) => /certificate fetch failed/.test(i.detail))!;
      expect(z.severity).toBe("critical");
      expect(z.detail).toMatch(/1 of them recovered: certificate available at collection/);
    });

    it("lowers a repeated prefetch failure to a warning when the identity's certificate is Available", async () => {
      const log = lines(prefetchLine("10:00:00", "web"), prefetchLine("10:03:00", "web"));
      const { f } = await runCheck(ID, "security", {
        resources: [namespace("shop"), saPod("web-7b9c8d6f5-p4q7r", "web")],
        files: { [ztunnelLog]: log, [ztunnelDump]: certsDump([{ sa: "web", state: "Available" }]), "cluster/pods": CLUSTER_PODS },
      });
      const p = f!.issues!.filter((i) => /prefetch/.test(i.detail));
      expect(p.some((i) => i.severity === "critical")).toBe(false);
      const w = p.find((i) => /shop\/web\)/.test(i.detail))!;
      expect(w.severity).toBe("warning");
      expect(w.detail).toContain("recovered: certificate available at collection");
    });

    it("counts ztunnel pods per identity, not across identities", async () => {
      const second = "ztunnel-7m9qx";
      const pods = `${CLUSTER_PODS}---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ${second}\n  namespace: istio-system\nspec:\n  containers:\n    - name: istio-proxy\n      image: docker.io/istio/ztunnel:1.31.2\n`;
      const { f } = await runCheck(ID, "security", {
        resources: [namespace("shop"), saPod("web-7b9c8d6f5-p4q7r", "web"), saPod("payments-1", "payments")],
        files: {
          [ztunnelLog]: lines(prefetchLine("10:00:00", "web"), prefetchLine("10:03:00", "web"), prefetchLine("10:00:00", "payments")),
          [`proxies/istio-system/${second}/istio-proxy.log`]: lines(prefetchLine("10:00:10", "web"), prefetchLine("10:04:00", "web")),
          [ztunnelDump]: JSON.stringify({ workloads: [] }),
          [`proxies/istio-system/${second}/config_dump`]: JSON.stringify({ workloads: [] }),
          "cluster/pods": pods,
        },
      });
      const p = f!.issues!.filter((i) => /prefetch/.test(i.detail));
      expect(p.find((i) => i.severity === "critical")!.detail).toMatch(/^2 ztunnel pods: .*\(shop\/web\)/);
      expect(p.find((i) => i.severity === "warning")!.detail).toMatch(/^1 ztunnel pod: .*\(shop\/payments\)/);
    });
  });

  it("finds nothing on a healthy mesh (issued certificates only)", async () => {
    const { f, skipped } = await runCheck(ID, "security", { files: { [cartLog]: HEALTHY } });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("is not evaluated when no proxy, ztunnel or istiod logs were collected", async () => {
    const { f, skipped } = await runCheck(ID, "security", {
      files: { [ISTIOD_LOG]: null, "proxies/default/test-pod-abc123/istio-proxy.log": null },
    });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/not evaluated: .*no (sidecar|istiod)/);
  });
});

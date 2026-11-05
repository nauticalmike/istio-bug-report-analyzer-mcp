import { describe, it, expect, afterEach, vi } from "vitest";
import {
  controlPlaneSync,
  parseAdszTotalClients,
  parsePushStatus,
  parseSyncz,
  pushStatusByIstiod,
  xdsTypeName,
} from "../../src/diagnostics/sources/xds-status.js";
import { istiodMetrics, metricValue, parsePrometheusLine, parsePrometheusText, scanPrometheusFile } from "../../src/diagnostics/sources/prometheus.js";
import { parseServerInfo, proxyServerInfo } from "../../src/diagnostics/sources/server-info.js";
import { envFlagValue, isSensitiveEnvName, looksLikeSecret, workloadEnv } from "../../src/diagnostics/sources/workload-env.js";
import { parseSecretList, secretNames } from "../../src/diagnostics/sources/secrets.js";
import { buildStore, cleanupArchives, deployment } from "./template-harness.js";
import {
  ADSZ,
  CART_POD,
  FAKE_BASE64_KEY,
  FAKE_JWT,
  GATEWAY_POD,
  ISTIOD_ENV,
  ISTIOD_ID,
  ISTIOD_METRICS,
  PUSH_STATUS,
  SECRET_DATA_VALUES,
  SECRETS_TABLE,
  SECRETS_YAML,
  SYNCZ,
  TYPE_URL,
  controlPlaneFiles,
  istiodPodWithEnv,
  serverInfo,
} from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

describe("syncz", () => {
  it("names xDS types from their type URLs", () => {
    expect(xdsTypeName(TYPE_URL.CDS)).toBe("CDS");
    expect(xdsTypeName(TYPE_URL.SDS)).toBe("SDS");
    expect(xdsTypeName(TYPE_URL.WDS)).toBe("WDS");
    expect(xdsTypeName("type.googleapis.com/istio.mesh.v1alpha1.Custom")).toBe("istio.mesh.v1alpha1.Custom");
  });

  it("parses per proxy and type the sent and acked nonce, NACK error and staleness", () => {
    const proxies = parseSyncz(SYNCZ, ISTIOD_ID)!;
    expect(proxies.map((p) => [p.namespace, p.pod, p.proxyType, p.istiod])).toEqual([
      ["shop", CART_POD, "sidecar", ISTIOD_ID],
      ["payments", "payments-5f7d8b9c6-k8m2n", "sidecar", ISTIOD_ID],
      ["shop", GATEWAY_POD, "router", ISTIOD_ID],
    ]);
    expect(proxies[0].types.every((t) => !t.nacked && !t.stale)).toBe(true);

    const lds = proxies[1].types.find((t) => t.type === "LDS")!;
    expect(lds).toMatchObject({ sent: "p2", acked: "p0", nacked: true, stale: false, typeUrl: TYPE_URL.LDS });
    expect(lds.error).toMatch(/Invalid regex/);
    expect(proxies[1].types.find((t) => t.type === "CDS")).toMatchObject({ nacked: false, stale: false });

    // Older istiod (no `resources` map): the top-level nonce fields, without errors.
    expect(proxies[2].types.find((t) => t.type === "CDS")).toMatchObject({ sent: "g2", acked: "g1", stale: true, nacked: false, error: null });
    expect(proxies[2].types.find((t) => t.type === "LDS")).toMatchObject({ stale: false });
  });

  it("redacts credentials in a NACK error (lastError)", () => {
    const syncz = [{ proxy: "cart-1.shop", resources: { [TYPE_URL.LDS]: { sent: "a", acked: "b", lastError: `ext_authz config rejected: header Authorization: Bearer ${FAKE_JWT} password=${FAKE_BASE64_KEY}` } } }];
    const error = parseSyncz(syncz, ISTIOD_ID)![0].types.find((t) => t.type === "LDS")!.error!;
    expect(error).not.toContain(FAKE_JWT);
    expect(error).not.toContain(FAKE_BASE64_KEY);
    expect(error).toContain("ext_authz config rejected");
  });

  it("returns null for something that is not a syncz list and skips malformed entries", () => {
    expect(parseSyncz("upstream connect error", ISTIOD_ID)).toBeNull();
    expect(parseSyncz({ totalPushes: 1 }, ISTIOD_ID)).toBeNull();
    expect(parseSyncz([null, 3, { proxy: "" }, { proxy: "a.b" }], ISTIOD_ID)).toHaveLength(1);
  });

  it("reads totalClients from adsz", () => {
    expect(parseAdszTotalClients(ADSZ)).toBe(3);
    expect(parseAdszTotalClients({ clients: [] })).toBeNull();
    expect(parseAdszTotalClients("text")).toBeNull();
  });

  it("collects every istiod's syncz with its client counts", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const sync = controlPlaneSync(store);
    if ("notEvaluated" in sync) throw new Error(sync.notEvaluated);
    expect(sync.istiods).toEqual([{ istiod: ISTIOD_ID, namespace: "istio-system", pod: "istiod-abc", syncz: "ok", clients: 3, totalClients: 3 }]);
    expect(sync.proxies).toHaveLength(3);
  });

  it("is not evaluated when no istiod has syncz", async () => {
    const store = await buildStore({ files: { "istio/istio-system/istiod-abc/debug/syncz": null } });
    expect(controlPlaneSync(store)).toEqual({ notEvaluated: expect.stringMatching(/no istiod debug\/syncz was collected/) });
  });
});

// cluster/pods (CLUSTER_PODS) lists istiod-abc; this istiod is not in it: a replaced pod, or
// another cluster's istiod in a merged archive.
const OLD = "istio/istio-system/istiod-old-7f9c8d6b5-zz9xk";
const OLD_ID = "istio-system/istiod-old-7f9c8d6b5-zz9xk";
const OLD_SYNCZ = JSON.stringify([{ proxy: "payments-1.shop", proxy_type: "sidecar", cluster_id: "Kubernetes", cluster_sent: "n1", cluster_acked: "n0" }]);
const OLD_PUSH = JSON.stringify({ pilot_vservice_dup_domain: { "payments.example.com:80": { proxy: "payments-1.shop", message: "duplicate domain" } } });
const OLD_METRICS = 'pilot_total_rejected_configs{type="gateway",name="shop/old"} 9\n';

describe("istiods no longer in the pod dump", () => {
  const oldFiles = { [`${OLD}/debug/syncz`]: OLD_SYNCZ, [`${OLD}/debug/adsz`]: JSON.stringify({ totalClients: 1 }), [`${OLD}/debug/push_status`]: OLD_PUSH, [`${OLD}/metrics`]: OLD_METRICS };

  it("skips their syncz, push_status and metrics while a live istiod has data", async () => {
    const store = await buildStore({ files: controlPlaneFiles(oldFiles) });
    const sync = controlPlaneSync(store);
    if ("notEvaluated" in sync) throw new Error(sync.notEvaluated);
    expect(sync.istiods.map((i) => i.istiod)).toEqual([ISTIOD_ID]);
    expect(sync.proxies.some((p) => p.istiod === OLD_ID)).toBe(false);
    expect(sync.skippedStale.map((i) => [i.istiod, i.stale, i.clients])).toEqual([[OLD_ID, true, 1]]);
    expect(sync.staleFallback).toBe(false);

    const push = pushStatusByIstiod(store);
    if ("notEvaluated" in push) throw new Error(push.notEvaluated);
    expect(push.map((p) => [p.istiod, p.stale])).toEqual([[ISTIOD_ID, undefined]]);

    const metrics = await istiodMetrics(store, ["pilot_total_rejected_configs"]);
    if ("notEvaluated" in metrics) throw new Error(metrics.notEvaluated);
    expect(metrics.map((m) => [m.istiod, m.stale])).toEqual([[ISTIOD_ID, undefined]]);
  });

  it("falls back to them, flagged, when no live istiod has the data", async () => {
    const live = "istio/istio-system/istiod-abc";
    const store = await buildStore({ files: controlPlaneFiles({ ...oldFiles, [`${live}/debug/syncz`]: null, [`${live}/debug/push_status`]: null, [`${live}/metrics`]: null }) });
    const sync = controlPlaneSync(store);
    if ("notEvaluated" in sync) throw new Error(sync.notEvaluated);
    expect(sync.staleFallback).toBe(true);
    expect(sync.skippedStale).toEqual([]);
    expect(sync.proxies.map((p) => p.istiod)).toEqual([OLD_ID]);
    expect(sync.istiods.find((i) => i.istiod === OLD_ID)).toMatchObject({ stale: true, syncz: "ok" });
    expect(sync.istiods.find((i) => i.istiod === ISTIOD_ID)).toMatchObject({ syncz: "missing" });
    expect(sync.istiods.find((i) => i.istiod === ISTIOD_ID)?.stale).toBeUndefined();

    const push = pushStatusByIstiod(store);
    if ("notEvaluated" in push) throw new Error(push.notEvaluated);
    expect(push.map((p) => [p.istiod, p.stale])).toEqual([[OLD_ID, true]]);

    const metrics = await istiodMetrics(store, ["pilot_total_rejected_configs"]);
    if ("notEvaluated" in metrics) throw new Error(metrics.notEvaluated);
    expect(metrics.map((m) => [m.istiod, m.stale])).toEqual([[OLD_ID, true]]);
  });

  it("uses every istiod when liveness is unknown (no pod dump)", async () => {
    const store = await buildStore({ noPodDump: true, files: controlPlaneFiles({ ...oldFiles, "cluster/pods": null }) });
    const sync = controlPlaneSync(store);
    if ("notEvaluated" in sync) throw new Error(sync.notEvaluated);
    expect(sync.istiods.map((i) => i.istiod).sort()).toEqual([ISTIOD_ID, OLD_ID].sort());
    expect(sync.staleFallback).toBe(false);
  });
});

describe("memory bounds (RSS)", () => {
  it("reads adsz totalClients from the head of the file, without parsing the client list", async () => {
    // A client list that is not valid JSON past the head: a whole-file parse would fail.
    const adsz = `{"totalClients": 2238, "clients": [${'{"connectionId":"cart-1.shop-1"},'.repeat(5000)}`;
    const store = await buildStore({ files: controlPlaneFiles({ "istio/istio-system/istiod-abc/debug/adsz": adsz }) });
    const spy = vi.spyOn(store.getIstiodPods()[0].debugEndpoints, "get");
    const sync = controlPlaneSync(store);
    if ("notEvaluated" in sync) throw new Error(sync.notEvaluated);
    expect(sync.istiods[0].totalClients).toBe(2238);
    expect(spy.mock.calls.map((c) => c[0])).not.toContain("adsz");
  });

  it("parses push_status without keeping it in the store's endpoint cache", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const spy = vi.spyOn(store.getIstiodPods()[0].debugEndpoints, "get");
    const out = pushStatusByIstiod(store);
    if ("notEvaluated" in out) throw new Error(out.notEvaluated);
    expect(out[0].metrics.length).toBeGreaterThan(0);
    expect(spy).not.toHaveBeenCalledWith("push_status");
  });
});

describe("push_status", () => {
  it("counts each metric's entries and distinct proxies with the top messages", () => {
    const metrics = parsePushStatus(PUSH_STATUS)!;
    expect(metrics.map((m) => [m.metric, m.count, m.proxies])).toEqual([
      ["pilot_conflict_inbound_listener", 3, 3],
      ["pilot_eds_no_instances", 1, 0],
      ["pilot_vservice_dup_domain", 1, 1],
    ]);
    expect(metrics[0].topMessages[0]).toEqual({ message: expect.stringMatching(/^Conflicting inbound listener:8080/), count: 2 });
    expect(metrics[0].topMessages).toHaveLength(2);
    expect(parsePushStatus(PUSH_STATUS, { topMessages: 1 })![0].topMessages).toHaveLength(1);
  });

  it("returns null for a non-object and an empty list for an empty push", () => {
    expect(parsePushStatus("no push yet")).toBeNull();
    expect(parsePushStatus({})).toEqual([]);
  });

  it("reads push_status per istiod", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const out = pushStatusByIstiod(store);
    if ("notEvaluated" in out) throw new Error(out.notEvaluated);
    expect(out[0].istiod).toBe(ISTIOD_ID);
    expect(out[0].metrics.find((m) => m.metric === "pilot_vservice_dup_domain")?.count).toBe(1);
  });
});

describe("Prometheus text", () => {
  it("parses names, labels with escapes, values and optional timestamps", () => {
    expect(parsePrometheusLine('pilot_xds{version="1.31.2"} 3')).toEqual({ name: "pilot_xds", labels: { version: "1.31.2" }, value: 3 });
    expect(parsePrometheusLine("process_resident_memory_bytes 1.5e+09")).toEqual({ name: "process_resident_memory_bytes", labels: {}, value: 1.5e9 });
    expect(parsePrometheusLine('citadel_server_csr_count{label="with \\"quotes\\" and \\\\ slash"} 5 1710756000000')).toEqual({
      name: "citadel_server_csr_count",
      labels: { label: 'with "quotes" and \\ slash' },
      value: 5,
    });
    expect(parsePrometheusLine('x_bucket{le="+Inf"} +Inf')?.value).toBe(Infinity);
    expect(parsePrometheusLine("# TYPE pilot_xds gauge")).toBeNull();
    expect(parsePrometheusLine("garbage line here")).toBeNull();
  });

  it("selects named metrics and sums matching samples", () => {
    const samples = parsePrometheusText(ISTIOD_METRICS, ["pilot_total_rejected_configs", "pilot_total_xds_rejects"]);
    expect(samples.map((s) => s.name)).toEqual(["pilot_total_rejected_configs", "pilot_total_rejected_configs", "pilot_total_xds_rejects", "pilot_total_xds_rejects"]);
    expect(metricValue(samples, "pilot_total_rejected_configs", { type: "gateway" })).toBe(2);
    expect(metricValue(samples, "pilot_total_rejected_configs")).toBe(3);
    expect(metricValue(samples, "pilot_xds")).toBeNull();
  });

  it("streams a metrics file and reads istiod metrics per pod", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const samples = await scanPrometheusFile(store, "istio/istio-system/istiod-abc/metrics", ["pilot_xds"]);
    expect(samples).toEqual([{ name: "pilot_xds", labels: { version: "1.31.2" }, value: 3 }]);
    expect(await scanPrometheusFile(store, "istio/istio-system/missing/metrics")).toBeNull();

    const per = await istiodMetrics(store, ["pilot_total_rejected_configs"]);
    if ("notEvaluated" in per) throw new Error(per.notEvaluated);
    expect(per).toEqual([{ istiod: ISTIOD_ID, samples: expect.any(Array) }]);
    expect(metricValue(per[0].samples, "pilot_total_rejected_configs", { type: "gateway" })).toBe(2);
  });

  it("is not evaluated when no istiod metrics were collected", async () => {
    const store = await buildStore({ files: { "istio/istio-system/istiod-abc/metrics": null } });
    expect(await istiodMetrics(store, ["pilot_xds"])).toEqual({ notEvaluated: expect.stringMatching(/no istiod metrics were collected/) });
  });
});

describe("server_info", () => {
  it("reads concurrency, state, Envoy version and uptime", () => {
    expect(parseServerInfo(serverInfo(32))).toEqual({ concurrency: 32, state: "LIVE", envoyVersion: "1.35.3", uptimeSeconds: 3600 });
    expect(parseServerInfo(`2026-03-18T10:00:00Z\tinfo\tlog line\n${serverInfo(2)}`)?.concurrency).toBe(2);
    expect(parseServerInfo("not json")).toBeNull();
    expect(parseServerInfo('{"state":"LIVE"}')).toEqual({ concurrency: null, state: "LIVE", envoyVersion: null, uptimeSeconds: null });
  });

  it("reads a proxy's server_info from the archive", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    expect(proxyServerInfo(store, "shop", GATEWAY_POD)?.concurrency).toBe(32);
    expect(proxyServerInfo(store, "shop", "nope")).toBeNull();
  });
});

describe("container env", () => {
  it("classifies secret-shaped values", () => {
    expect(looksLikeSecret(FAKE_JWT)).toBe(true);
    expect(looksLikeSecret(FAKE_BASE64_KEY)).toBe(true);
    expect(looksLikeSecret("0123456789abcdef0123456789abcdef")).toBe(true);
    expect(looksLikeSecret("-----BEGIN PRIVATE KEY-----\nMIIE")).toBe(true);
    expect(looksLikeSecret("https://bot:pw@registry.example.com")).toBe(true);
    for (const v of ["true", "100ms", "10s", "istiod.istio-system.svc:15012", "/var/run/secrets/tokens/istio-token", "kubernetes-istio-system-default", "", "a value with spaces in it ok"]) {
      expect(looksLikeSecret(v), v).toBe(false);
    }
  });

  it("classifies a two-part JWT-like token and, for licence-named variables, any long base64url value", () => {
    const [header, payload] = FAKE_JWT.split(".");
    expect(looksLikeSecret(`${header}.${payload}`)).toBe(true);
    // Lower-case only, with dots: not secret-shaped on its own, but a licence key by its name.
    const licence = "shopkeyv2.aaaabbbbccccddddeeeeffff.gggghhhhiiiijjjj";
    expect(looksLikeSecret(licence)).toBe(false);
    expect(looksLikeSecret(licence, "SHOP_LICENSE_KEY")).toBe(true);
    expect(looksLikeSecret(licence, "SHOP_LICENCE")).toBe(true);
    expect(looksLikeSecret("enterprise", "SHOP_LICENSE_TIER")).toBe(false);
    expect(looksLikeSecret(licence, "SHOP_FEATURE_FLAGS")).toBe(false);
    const env = workloadEnv(istiodPodWithEnv([{ name: "SHOP_LICENSE_KEY", value: licence }]));
    expect(env.find((e) => e.name === "SHOP_LICENSE_KEY")).toMatchObject({ sensitiveName: true, secretLikeValue: true });
  });

  it("never flags secret-named variables whose value is a reference: a namespace/name or a path", () => {
    const env = workloadEnv(
      istiodPodWithEnv([
        { name: "SHOP_LICENSE_SECRET", value: "istio-system/shop-enterprise-license-key" },
        { name: "SHOP_LICENSE_VOLUME", value: "/etc/shop/license/shop-enterprise-license.key" },
        { name: "SHOP_LICENSE_FILE", value: "/var/run/secrets/shop/license/license-key-v2" },
        { name: "SHOP_LICENSE_REF", value: "payments/payments-enterprise-license.v2" },
        { name: "SHOP_LICENSE_KEY", value: FAKE_BASE64_KEY },
      ]),
    );
    const by = Object.fromEntries(env.map((e) => [e.name, e]));
    expect(by.SHOP_LICENSE_SECRET).toMatchObject({ sensitiveName: true, secretLikeValue: false });
    expect(by.SHOP_LICENSE_VOLUME).toMatchObject({ sensitiveName: true, secretLikeValue: false });
    // Licence-named, but the value is a path or a namespace/name reference.
    expect(by.SHOP_LICENSE_FILE).toMatchObject({ sensitiveName: true, secretLikeValue: false });
    expect(by.SHOP_LICENSE_REF).toMatchObject({ sensitiveName: true, secretLikeValue: false });
    expect(by.SHOP_LICENSE_KEY).toMatchObject({ sensitiveName: true, secretLikeValue: true });
    // Paths are not secrets under any name; a key that only starts with a slash still is.
    expect(looksLikeSecret("/var/run/secrets/shop/AbCdEf0123456789xyz", "SHOP_TOKEN")).toBe(false);
    expect(looksLikeSecret(`/${FAKE_BASE64_KEY}`, "SHOP_TOKEN")).toBe(true);
  });

  it("flags secret-named variables", () => {
    for (const n of ["MESH_LICENSE_KEY", "UPSTREAM_API_TOKEN", "DB_PASSWORD", "SIGNING_KEY", "CLIENT_SECRET"]) expect(isSensitiveEnvName(n), n).toBe(true);
    for (const n of ["PILOT_DEBOUNCE_AFTER", "KEYCLOAK_URL", "POD_NAME", "GOMEMLIMIT"]) expect(isSensitiveEnvName(n), n).toBe(false);
  });

  it("lists env names with their source and booleans, never the values", () => {
    const env = workloadEnv(istiodPodWithEnv(ISTIOD_ENV));
    const by = Object.fromEntries(env.map((e) => [e.name, e]));
    expect(by.PILOT_DEBOUNCE_AFTER).toEqual({ container: "discovery", initContainer: false, name: "PILOT_DEBOUNCE_AFTER", source: "value", valueFromKind: null, sensitiveName: false, secretLikeValue: false });
    expect(by.MESH_LICENSE_KEY).toMatchObject({ source: "value", sensitiveName: true, secretLikeValue: true });
    expect(by.UPSTREAM_API_TOKEN).toMatchObject({ source: "valueFrom", valueFromKind: "secretKeyRef", sensitiveName: true, secretLikeValue: false });
    expect(by.POD_NAME).toMatchObject({ source: "valueFrom", valueFromKind: "fieldRef" });
    expect(by.EMPTY_FLAG).toMatchObject({ source: "unset" });
    expect(by.INIT_TOKEN).toMatchObject({ container: "init-certs", initContainer: true, secretLikeValue: true });
    const text = JSON.stringify(env);
    expect(text).not.toContain(FAKE_JWT);
    expect(text).not.toContain(FAKE_BASE64_KEY);
  });

  it("reads env from Deployment templates", () => {
    const d = deployment("istio-system", "istiod", { containers: [{ name: "discovery", env: [{ name: "PILOT_DEBOUNCE_MAX", value: "30s" }] }] });
    expect(workloadEnv(d).map((e) => e.name)).toEqual(["PILOT_DEBOUNCE_MAX"]);
    expect(workloadEnv({ kind: "ConfigMap", metadata: { name: "x" } })).toEqual([]);
  });

  it("returns a flag's literal value only when it is neither secret-named nor secret-shaped", () => {
    const pod = istiodPodWithEnv([...ISTIOD_ENV, { name: "PILOT_DEBOUNCE_AFTER", value: "60s" }]);
    expect(envFlagValue(pod, "PILOT_DEBOUNCE_AFTER")).toBe("60s"); // the last definition wins
    expect(envFlagValue(pod, "ENABLE_DEBUG_ENDPOINT_AUTH", { container: "discovery" })).toBe("false");
    expect(envFlagValue(pod, "ENABLE_DEBUG_ENDPOINT_AUTH", { container: "other" })).toBeNull();
    expect(envFlagValue(pod, "MESH_LICENSE_KEY")).toBeNull();
    expect(envFlagValue(pod, "UPSTREAM_API_TOKEN")).toBeNull();
    expect(envFlagValue(pod, "MISSING")).toBeNull();
  });
});

describe("secret names", () => {
  it("parses the kubectl table, with and without the namespace column", () => {
    expect(parseSecretList(SECRETS_TABLE)).toEqual([
      { namespace: "istio-system", name: "istio-ca-secret", type: "istio.io/ca-root" },
      { namespace: "shop", name: "shop-example-com-cert", type: "kubernetes.io/tls" },
      { namespace: "shop", name: "cart-db", type: "Opaque" },
      { namespace: "payments", name: "payments-registry", type: "kubernetes.io/dockerconfigjson" },
    ]);
    expect(parseSecretList("NAME   TYPE     DATA   AGE\ncart-db   Opaque   1   2d\n")).toEqual([{ namespace: null, name: "cart-db", type: "Opaque" }]);
  });

  it("reads names and types from -o yaml output and never its data", () => {
    const secrets = parseSecretList(SECRETS_YAML);
    expect(secrets).toEqual([
      { namespace: "shop", name: "shop-example-com-cert", type: "kubernetes.io/tls" },
      { namespace: "shop", name: "cart-db", type: "Opaque" },
    ]);
    const text = JSON.stringify(secrets);
    for (const v of SECRET_DATA_VALUES) expect(text).not.toContain(v);
  });

  it("reads multi-document YAML", () => {
    const docs = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: a\n  namespace: shop\ntype: Opaque\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n";
    expect(parseSecretList(docs)).toEqual([{ namespace: "shop", name: "a", type: "Opaque" }]);
  });

  it("streams cluster/secrets from the archive, or says it was not collected", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const secrets = await secretNames(store);
    if ("notEvaluated" in secrets) throw new Error(secrets.notEvaluated);
    expect(secrets.map((s) => `${s.namespace}/${s.name}`)).toContain("shop/shop-example-com-cert");

    const none = await buildStore({ files: { "cluster/secrets": null } });
    expect(await secretNames(none)).toEqual({ notEvaluated: "not evaluated: cluster/secrets was not collected" });
  });
});

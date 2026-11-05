import { describe, it, expect, afterEach, vi } from "vitest";
import {
  evaluateLogRule,
  logFilesOf,
  logRuleGap,
  registerLogRules,
  staleLogText,
  registeredLogRuleScan,
  scanLogRules,
  unregisterLogRules,
  type LogRule,
} from "../../src/diagnostics/log-rules.js";
import { redactHost, redactHostsInText } from "../../src/diagnostics/redact.js";
import { buildStore, cleanupArchives } from "./template-harness.js";
import { CART_POD, CLUSTER_PODS, CNI_POD, FAKE_JWT, GATEWAY_POD, ISTIOD_LOG, PROXY_LOG, ZTUNNEL_POD, controlPlaneFiles } from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

const RULES: LogRule[] = [
  { id: "t_proxy_rejected", components: ["proxy"], match: /gRPC config for \S+ rejected/, hint: "rejected" },
  { id: "t_istiod_ack_error", components: ["istiod"], match: /ADS:(?:LDS|RDS|CDS|EDS): ACK ERROR/ },
  { id: "t_ztunnel_policy", components: ["ztunnel"], match: "policy rejection: allow policies exist" },
  { id: "t_proxy_policy", components: ["proxy"], match: "policy rejection: allow policies exist" },
  { id: "t_cni_no_ztunnel", components: ["cni"], match: "AddPodToMesh returned: no ztunnel connection" },
  { id: "t_ztunnel_cni", components: ["ztunnel"], match: /failed to connect to the Istio CNI node agent/g },
  { id: "t_token", components: ["proxy", "istiod"], match: "failed to fetch token" },
  { id: "t_jwks", components: ["istiod"], match: "Failed to GET from", redact: redactHostsInText },
];

const byId = (id: string) => RULES.find((r) => r.id === id)!;

describe("logFilesOf", () => {
  it("splits proxies/ into Envoy proxies and ztunnel, and finds istiod and cni logs", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const proxy = logFilesOf(store, "proxy");
    expect(proxy.map((f) => [f.source, f.proxyType])).toEqual(expect.arrayContaining([[`proxy/shop/${CART_POD}`, "sidecar"], [`proxy/shop/${GATEWAY_POD}`, "gateway"]]));
    expect(proxy.some((f) => f.pod === ZTUNNEL_POD)).toBe(false);
    expect(logFilesOf(store, "ztunnel")).toEqual([
      { component: "ztunnel", source: `ztunnel/istio-system/${ZTUNNEL_POD}`, path: `proxies/istio-system/${ZTUNNEL_POD}/istio-proxy.log`, namespace: "istio-system", pod: ZTUNNEL_POD, proxyType: "ztunnel" },
    ]);
    expect(logFilesOf(store, "istiod").map((f) => f.path)).toEqual(["istio/istio-system/istiod-abc/discovery.log"]);
    expect(logFilesOf(store, "cni")).toEqual([{ component: "cni", source: `cni/${CNI_POD}`, path: `cni/${CNI_POD}/cni.log`, pod: CNI_POD }]);
  });
});

describe("logs of pods no longer in the pod dump", () => {
  // cluster/pods covers istio-system; this istiod and this ztunnel are not in it.
  const OLD_ISTIOD = "istio/istio-system/istiod-old-7f9c8d6b5-zz9xk/discovery.log";
  const OLD_ZTUNNEL = "proxies/istio-system/ztunnel-9q8wp/istio-proxy.log";

  it("marks them stale, never reads them, and counts them per rule as staleFiles/staleSources", async () => {
    const store = await buildStore({ files: controlPlaneFiles({ [OLD_ISTIOD]: ISTIOD_LOG, [OLD_ZTUNNEL]: "2026-03-18T10:00:01.000000Z\terror\taccess\terror=\"policy rejection: allow policies exist, but none allowed\"\n" }) });
    expect(logFilesOf(store, "istiod").find((f) => f.path === OLD_ISTIOD)?.stale).toBe(true);
    expect(logFilesOf(store, "istiod").find((f) => f.pod === "istiod-abc")?.stale).toBeUndefined();
    const spy = vi.spyOn(store, "scanFileLines");
    const scan = await scanLogRules(store, RULES);
    const read = spy.mock.calls.map((c) => c[0]);
    expect(read).not.toContain(OLD_ISTIOD);
    expect(read).not.toContain(OLD_ZTUNNEL);
    expect(scan.hits.get("t_istiod_ack_error")).toMatchObject({ count: 2, sources: 1, staleFiles: 1, staleSources: 1 });
    expect(scan.hits.get("t_ztunnel_policy")).toMatchObject({ count: 2, sources: 1, staleFiles: 1, staleSources: 1 });
    expect(scan.hits.get("t_istiod_ack_error")!.bySource.map((s) => s.pod)).toEqual(["istiod-abc"]);
    expect(scan.components.istiod).toMatchObject({ files: 2, read: 1, stale: 1 });
    // A rule over two components counts the stale logs of both.
    expect(scan.hits.get("t_token")).toMatchObject({ staleFiles: 1 });
    // Nothing stale: no field; staleLines is gone.
    expect(scan.hits.get("t_cni_no_ztunnel")?.staleFiles).toBeUndefined();
    expect(scan.hits.get("t_istiod_ack_error")).not.toHaveProperty("staleLines");
    expect(staleLogText(scan.hits.get("t_istiod_ack_error")!)).toBe("; 1 log file of a pod no longer in the dump ignored");
    expect(staleLogText(scan.hits.get("t_cni_no_ztunnel")!)).toBe("");
  });

  it("is not evaluated when every log of the rule's components is of a pod no longer in the dump", async () => {
    // cluster/pods lists istiod-abc; only the old istiod has a log.
    const store = await buildStore({ files: controlPlaneFiles({ "istio/istio-system/istiod-abc/discovery.log": null, [OLD_ISTIOD]: ISTIOD_LOG }) });
    const scan = await scanLogRules(store, RULES);
    expect(scan.components.istiod).toMatchObject({ files: 1, read: 0, stale: 1 });
    expect(logRuleGap(scan, byId("t_istiod_ack_error"))).toBe("not evaluated: the only istiod log is of a pod no longer in the dump");
    // The proxy logs of t_token are live: evaluated.
    expect(logRuleGap(scan, byId("t_token"))).toBeNull();
  });

  it("names the count when several logs are all stale", async () => {
    const store = await buildStore({ files: controlPlaneFiles({ "istio/istio-system/istiod-abc/discovery.log": null, [OLD_ISTIOD]: ISTIOD_LOG, "istio/istio-system/istiod-old-7f9c8d6b5-aa1bb/discovery.log": ISTIOD_LOG }) });
    const scan = await scanLogRules(store, RULES);
    expect(logRuleGap(scan, byId("t_istiod_ack_error"))).toBe("not evaluated: all 2 istiod logs are of pods no longer in the dump");
    expect(scan.hits.get("t_istiod_ack_error")).toMatchObject({ count: 0, staleFiles: 2, staleSources: 2 });
    expect(staleLogText(scan.hits.get("t_istiod_ack_error")!)).toBe("; 2 log files of pods no longer in the dump ignored");
  });

  it("counts every log when the pod dump does not cover the namespace or is missing", async () => {
    const store = await buildStore({ files: controlPlaneFiles({ [OLD_ISTIOD]: ISTIOD_LOG, "cluster/pods": null }) });
    const scan = await scanLogRules(store, RULES);
    expect(scan.hits.get("t_istiod_ack_error")).toMatchObject({ count: 4, sources: 2 });
    expect(scan.hits.get("t_istiod_ack_error")?.staleFiles).toBeUndefined();
  });
});

describe("meshctl archive layout", () => {
  it("finds <cluster>/logs/<ns>/<pod>/discovery.log and istio-proxy.log", async () => {
    // No bug-report pod dump to judge liveness against.
    const store = await buildStore({
      noPodDump: true,
      files: {
        "shop-cluster/logs/istio-system/istiod-7c8d9f6b5-q2w4e/discovery.log": ISTIOD_LOG,
        "shop-cluster/logs/shop/cart-6d8f9c7b5-r5t6y/istio-proxy.log": PROXY_LOG,
        "shop-cluster/logs/istio-system/ztunnel-b7c9d/istio-proxy.log": "x\n",
        "pay-cluster/logs/shop/cart-6d8f9c7b5-r5t6y/istio-proxy.log": PROXY_LOG,
      },
    });
    expect(logFilesOf(store, "istiod")).toEqual(expect.arrayContaining([
      { component: "istiod", source: "istiod/istio-system/istiod-7c8d9f6b5-q2w4e", path: "shop-cluster/logs/istio-system/istiod-7c8d9f6b5-q2w4e/discovery.log", namespace: "istio-system", pod: "istiod-7c8d9f6b5-q2w4e" },
    ]));
    const proxies = logFilesOf(store, "proxy").filter((f) => f.path.includes("/logs/"));
    // The same pod in two clusters' dirs gets distinct sources.
    expect(proxies.map((f) => f.source).sort()).toEqual(["proxy/shop/cart-6d8f9c7b5-r5t6y", expect.stringMatching(/^proxy\/shop\/cart-6d8f9c7b5-r5t6y@(shop|pay)-cluster$/)]);
    expect(logFilesOf(store, "ztunnel").map((f) => f.pod)).toEqual(["ztunnel-b7c9d"]);
    const scan = await scanLogRules(store, RULES);
    expect(scan.hits.get("t_istiod_ack_error")).toMatchObject({ count: 2 });
    expect(scan.hits.get("t_proxy_rejected")?.count).toBe(4);
  });
});

describe("scanLogRules", () => {
  it("counts each rule per source with first/last time, in one pass per file", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const spy = vi.spyOn(store, "scanFileLines");
    const scan = await scanLogRules(store, RULES);

    const paths = spy.mock.calls.map((c) => c[0]);
    expect(new Set(paths).size).toBe(paths.length);
    expect(paths).toContain(`proxies/istio-system/${ZTUNNEL_POD}/istio-proxy.log`);

    const rejected = scan.hits.get("t_proxy_rejected")!;
    expect(rejected).toMatchObject({ ruleId: "t_proxy_rejected", count: 3, sources: 2, firstTime: "2026-03-18T09:59:00.000Z", lastTime: "2026-03-18T10:03:00.000Z" });
    expect(rejected.bySource).toEqual([
      { source: `proxy/shop/${CART_POD}`, path: `proxies/shop/${CART_POD}/istio-proxy.log`, component: "proxy", namespace: "shop", pod: CART_POD, proxyType: "sidecar", count: 2, firstTime: "2026-03-18T10:00:06.000Z", lastTime: "2026-03-18T10:03:00.000Z" },
      { source: `proxy/shop/${GATEWAY_POD}`, path: `proxies/shop/${GATEWAY_POD}/istio-proxy.log`, component: "proxy", namespace: "shop", pod: GATEWAY_POD, proxyType: "gateway", count: 1, firstTime: "2026-03-18T09:59:00.000Z", lastTime: "2026-03-18T09:59:00.000Z" },
    ]);

    expect(scan.hits.get("t_istiod_ack_error")).toMatchObject({ count: 2, sources: 1 });
    expect(scan.hits.get("t_ztunnel_policy")).toMatchObject({ count: 2, sources: 1 });
    // Envoy-proxy rules never see ztunnel logs.
    expect(scan.hits.get("t_proxy_policy")).toMatchObject({ count: 0, sources: 0, bySource: [], examples: [] });
    expect(scan.hits.get("t_proxy_policy")?.firstTime).toBeUndefined();
    expect(scan.hits.get("t_cni_no_ztunnel")).toMatchObject({ count: 2, sources: 1 });
    // A global regex keeps counting (no lastIndex carried between lines).
    expect(scan.hits.get("t_ztunnel_cni")).toMatchObject({ count: 1 });
    expect(scan.hits.get("t_token")).toMatchObject({ count: 1 });

    expect(scan.components.ztunnel).toEqual({ files: 1, read: 1, bytes: expect.any(Number) });
    expect(scan.failed).toEqual([]);
  });

  it("redacts examples (secrets always, hosts when the rule asks) and caps them, preferring distinct sources", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const scan = await scanLogRules(store, [...RULES, { id: "t_capped", components: ["proxy"], match: "rejected", maxExamples: 2 }]);

    const token = scan.hits.get("t_token")!.examples;
    expect(token).toHaveLength(1);
    expect(token[0]).not.toContain(FAKE_JWT);
    expect(token[0]).toContain("Bearer [redacted]");

    const jwks = scan.hits.get("t_jwks")!.examples[0];
    expect(jwks).not.toContain("login.example.com");
    expect(jwks).toContain(redactHost("login.example.com"));

    const capped = scan.hits.get("t_capped")!.examples;
    expect(capped).toHaveLength(2);
    expect(capped.some((l) => l.startsWith("2026-03-18T09:59"))).toBe(true); // the gateway's, not a second cart line
    expect(scan.hits.get("t_proxy_rejected")!.examples).toHaveLength(3);
  });

  it("cuts long example lines", async () => {
    const store = await buildStore({ files: { "istio/istio-system/istiod-abc/discovery.log": `2026-03-18T10:00:00Z\terror\tx\tboom ${"y".repeat(5000)}\n` } });
    const scan = await scanLogRules(store, [{ id: "t_boom", components: ["istiod"], match: "boom" }]);
    expect(scan.hits.get("t_boom")!.examples[0].length).toBeLessThan(700);
  });

  it("records unreadable files instead of reading them as empty", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const real = store.scanFileLines.bind(store);
    vi.spyOn(store, "scanFileLines").mockImplementation(async (path, onLine, opts) => {
      if (path.startsWith("cni/")) throw new Error("EIO");
      return real(path, onLine, opts);
    });
    const scan = await scanLogRules(store, RULES);
    expect(scan.failed).toEqual([{ path: `cni/${CNI_POD}/cni.log`, error: "EIO" }]);
    expect(scan.components.cni).toEqual({ files: 1, read: 0, bytes: 0 });
    expect(logRuleGap(scan, byId("t_cni_no_ztunnel"))).toMatch(/not evaluated: .*istio-cni log file\(s\) could not be read/);
  });
});

describe("logRuleGap", () => {
  it("says which component's logs were not collected, and is null when any was", async () => {
    const store = await buildStore({
      files: controlPlaneFiles({ [`cni/${CNI_POD}/cni.log`]: null, [`proxies/istio-system/${ZTUNNEL_POD}/istio-proxy.log`]: null, [`proxies/istio-system/${ZTUNNEL_POD}/config_dump`]: null }),
    });
    const scan = await scanLogRules(store, RULES);
    expect(scan.components.cni).toEqual({ files: 0, read: 0, bytes: 0, missing: expect.stringMatching(/no istio-cni logs were collected/) });
    expect(logRuleGap(scan, byId("t_cni_no_ztunnel"))).toMatch(/^not evaluated: no istio-cni logs were collected/);
    expect(logRuleGap(scan, byId("t_ztunnel_policy"))).toMatch(/^not evaluated: no ztunnel logs were collected/);
    expect(logRuleGap(scan, { id: "x", components: ["proxy", "ztunnel"], match: "x" })).toBeNull();
    expect(logRuleGap(scan, byId("t_istiod_ack_error"))).toBeNull();
  });
});

describe("registered rules", () => {
  afterEach(() => unregisterLogRules(["t_reg_a", "t_reg_b", "t_reg_c"]));

  it("scans every registered rule once per store and shares the pass", async () => {
    registerLogRules([
      { id: "t_reg_a", components: ["proxy"], match: "rejected" },
      { id: "t_reg_b", components: ["istiod"], match: "ACK ERROR" },
    ]);
    const store = await buildStore({ files: controlPlaneFiles() });
    const spy = vi.spyOn(store, "scanFileLines");
    const [a, b] = await Promise.all([registeredLogRuleScan(store, ["t_reg_a"]), registeredLogRuleScan(store, ["t_reg_b"])]);
    const calls = spy.mock.calls.length;
    expect(a.hits.get("t_reg_a")?.count).toBe(3);
    expect(b.hits.get("t_reg_b")?.count).toBe(2);
    // Both answered from the same pass, which also covered the other rule.
    expect(a.hits.has("t_reg_b")).toBe(true);
    await registeredLogRuleScan(store);
    expect(spy.mock.calls.length).toBe(calls);

    // A rule registered later gets one more pass, for the new rules only; earlier results stay.
    registerLogRules([{ id: "t_reg_c", components: ["cni"], match: "no ztunnel connection" }]);
    const c = await registeredLogRuleScan(store, ["t_reg_a", "t_reg_c"]);
    expect(c.hits.get("t_reg_c")?.count).toBe(2);
    expect(c.hits.get("t_reg_a")?.count).toBe(3);
    expect(spy.mock.calls.length).toBe(calls + 1);
  });

  it("refuses a second, different definition under the same id and accepts the same one", () => {
    registerLogRules([{ id: "t_reg_a", components: ["proxy"], match: /rejected/ }]);
    expect(() => registerLogRules([{ id: "t_reg_a", components: ["proxy"], match: /rejected/ }])).not.toThrow();
    expect(() => registerLogRules([{ id: "t_reg_a", components: ["istiod"], match: /rejected/ }])).toThrow(/already registered/);
  });

  it("rejects an unknown rule id", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    await expect(registeredLogRuleScan(store, ["t_nope"])).rejects.toThrow(/unknown log rule "t_nope"/);
  });

  it("evaluateLogRule registers, scans and returns the hits or the gap", async () => {
    const store = await buildStore({ files: controlPlaneFiles({ [`cni/${CNI_POD}/cni.log`]: null }) });
    const hits = await evaluateLogRule(store, { id: "t_reg_a", components: ["proxy"], match: "rejected" });
    expect(hits).toMatchObject({ ruleId: "t_reg_a", count: 3 });
    expect(await evaluateLogRule(store, { id: "t_reg_c", components: ["cni"], match: "x" })).toEqual({ notEvaluated: expect.stringMatching(/no istio-cni logs/) });
  });
});

describe("grouped rules", () => {
  it("counts matches per group key with distinct sources, and drops lines whose key is null", async () => {
    const istiod = "istio/istio-system/istiod-abc/discovery.log";
    const log = [
      '2026-03-18T10:00:00Z\twarn\tmodel\tFailed to GET from "https://login.example.com/keys": timeout. Retry in 1s',
      '2026-03-18T10:00:01Z\twarn\tmodel\tFailed to GET from "https://login.example.com/keys": timeout. Retry in 1s',
      '2026-03-18T10:00:02Z\twarn\tmodel\tFailed to GET from "https://idp.example.org/jwks": refused. Retry in 1s',
      "2026-03-18T10:00:03Z\twarn\tmodel\tFailed to GET from nowhere",
      "",
    ].join("\n");
    const pods = `${CLUSTER_PODS}---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-def\n  namespace: istio-system\n`;
    const store = await buildStore({ files: { ...controlPlaneFiles(), [istiod]: log, "istio/istio-system/istiod-def/discovery.log": log, "cluster/pods": pods } });
    const rule: LogRule = {
      id: "t_grouped",
      components: ["istiod"],
      match: "Failed to GET from",
      group: (line) => {
        const m = /https?:\/\/([^/"\s:]+)/.exec(line);
        return m ? redactHost(m[1]) : null;
      },
    };
    const scan = await scanLogRules(store, [rule]);
    const hits = scan.hits.get("t_grouped")!;
    expect(hits.count).toBe(8);
    expect(hits.groups).toMatchObject([
      { key: redactHost("login.example.com"), count: 4, sources: 2, members: 2 },
      { key: redactHost("idp.example.org"), count: 2, sources: 2, members: 2 },
    ]);
    // Rules without a group function have no groups field.
    const plain = await scanLogRules(store, [{ id: "t_plain", components: ["istiod"], match: "Failed to GET from" }]);
    expect(plain.hits.get("t_plain")!.groups).toBeUndefined();
  });

  it("caps the number of groups and counts the rest as overflow", async () => {
    const lines = Array.from({ length: 6 }, (_, i) => `2026-03-18T10:00:0${i}Z\twarn\tFailed to GET from https://h${i}.example.com/k`);
    const store = await buildStore({ files: { ...controlPlaneFiles(), "istio/istio-system/istiod-abc/discovery.log": lines.join("\n") } });
    const rule: LogRule = { id: "t_cap", components: ["istiod"], match: "Failed to GET from", maxGroups: 4, group: (l) => /h\d/.exec(l)?.[0] ?? null };
    const hits = (await scanLogRules(store, [rule])).hits.get("t_cap")!;
    expect(hits.groups).toHaveLength(4);
    expect(hits.groupsOverflow).toBe(2);
    expect(hits.groupsOverflowKeys).toBe(2);
  });

  it("treats rules with a different group function as different definitions", () => {
    const g1 = () => "a";
    const g2 = () => "b";
    registerLogRules([{ id: "t_reg_g", components: ["istiod"], match: "x", group: g1 }]);
    expect(() => registerLogRules([{ id: "t_reg_g", components: ["istiod"], match: "x", group: g1 }])).not.toThrow();
    expect(() => registerLogRules([{ id: "t_reg_g", components: ["istiod"], match: "x", group: g2 }])).toThrow(/already registered/);
    unregisterLogRules(["t_reg_g"]);
  });
});

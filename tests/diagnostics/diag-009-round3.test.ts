import { describe, it, expect, afterEach } from "vitest";
import { AMBIENT_POLICY_CHECKS } from "../../src/diagnostics/mesh-checks/ambient-policy.js";
import type { Issue } from "../../src/diagnostics/checks.js";
import { ambientPod, buildStore, cleanupArchives, injectResources, namespace, sidecarPod, type Obj } from "./template-harness.js";
import { AMBIENT_NS, INJECTED_NS, authz, crs, istioResource, runCheck } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

const run = (resources: Obj[], files: Record<string, string | null>) => runCheck("DIAG-009", "security", { resources, files });
const custom = (ns: string, name: string, selector?: Obj) => authz(ns, name, { ...(selector ? { selector: { matchLabels: selector } } : {}), action: "CUSTOM", provider: { name: "ext" }, rules: [{}] });
const twoAmbient = [namespace("shop", AMBIENT_NS), namespace("store", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" }), ambientPod("store", "cart", { app: "cart" })];

describe("DIAG-009 merged lines carry the namespaces they cover", () => {
  it("one policy copied into two namespaces sets Issue.namespaces", async () => {
    const { f } = await run(twoAmbient, crs(custom("shop", "ext-authz"), custom("store", "ext-authz")));
    expect(f?.issues).toHaveLength(1);
    expect(f?.issues?.[0].detail).toMatch(/^AuthorizationPolicy ext-authz in 2 namespaces/);
    expect(f?.issues?.[0].namespaces).toEqual(["shop", "store"]);
  });

  it("a root-namespace policy lists the namespaces of the pods it applies to", async () => {
    const { f } = await run(twoAmbient, crs(custom("istio-system", "ext-authz", { app: "cart" })));
    expect(f?.issues).toHaveLength(1);
    expect(f?.issues?.[0].namespace).toBeUndefined();
    expect(f?.issues?.[0].namespaces).toEqual(["shop", "store"]);
  });

  it("a single-namespace line keeps Issue.namespace", async () => {
    const { f } = await run(twoAmbient, crs(custom("shop", "ext-authz")));
    expect(f?.issues?.[0].namespace).toBe("shop");
  });
});

describe("DIAG-009 istio.io/dry-run follows Go strconv.ParseBool", () => {
  for (const value of ["1", "t", "T", "TRUE", "true", "True"]) {
    it(`skips a policy annotated ${JSON.stringify(value)}`, async () => {
      const pol = authz("shop", "dry", { action: "CUSTOM", provider: { name: "ext" }, rules: [{}] }, { annotations: { "istio.io/dry-run": value } });
      const { f } = await run(twoAmbient, crs(pol));
      expect(f).toBeUndefined();
    });
  }
  for (const value of ["tRUE", "yes", "0", "false"]) {
    it(`enforces (and reports) a policy annotated ${JSON.stringify(value)}`, async () => {
      const pol = authz("shop", "dry", { action: "CUSTOM", provider: { name: "ext" }, rules: [{}] }, { annotations: { "istio.io/dry-run": value } });
      const { f } = await run(twoAmbient, crs(pol));
      expect(f?.affectedResources[0]).toMatch(/^shop\/dry: action CUSTOM/);
    });
  }
});

describe("ambient policy checks on a large archive", () => {
  it("scope lookups stay fast (40k pods, 4k selector policies of each kind)", async () => {
    const store = await buildStore({ resources: [namespace("ns-0")], files: crs(istioResource("networking.istio.io/v1", "VirtualService", "ns-0", "vs", { hosts: ["a"] })) });
    const items: Obj[] = [];
    const namespaces = 200;
    for (let n = 0; n < namespaces; n++) items.push(namespace(`ns-${n}`, n % 2 ? AMBIENT_NS : INJECTED_NS));
    for (let i = 0; i < 40_000; i++) {
      const n = `ns-${i % namespaces}`;
      const labels = { app: `app-${i % 4_000}` };
      items.push((i % namespaces) % 2 ? ambientPod(n, `p-${i}`, labels) : sidecarPod(n, `p-${i}`, "1.31.2", labels));
    }
    for (let k = 0; k < 4_000; k++) {
      const n = `ns-${k % namespaces}`;
      items.push(custom(n, `authz-${k}`, { app: `app-${k}` }));
      items.push(istioResource("security.istio.io/v1", "PeerAuthentication", n, `pa-${k}`, { selector: { matchLabels: { app: `app-${k}` } }, mtls: { mode: "DISABLE" } }));
      items.push(istioResource("networking.istio.io/v1", "Sidecar", n, `sc-${k}`, { workloadSelector: { labels: { app: `app-${k}` } }, egress: [{ hosts: ["./*"] }] }));
    }
    store.getClusterDumpItems("cluster/crs"); // parse once so the section counts exist, then swap in the synthetic objects
    injectResources(store, items);

    const start = performance.now();
    let lines = 0;
    for (const check of Object.values(AMBIENT_POLICY_CHECKS)) {
      const out = check(store, {}) as Issue[];
      if (!Array.isArray(out)) throw new Error(JSON.stringify(out));
      lines += out.length;
    }
    expect(lines).toBeGreaterThan(0);
    const elapsed = performance.now() - start;
    // About 0.15 s indexed; scanning every pod per policy took about 3 s.
    expect(elapsed).toBeLessThan(1_500);
  });
});

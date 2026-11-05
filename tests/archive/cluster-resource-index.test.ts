import { describe, it, expect, afterEach } from "vitest";
import { apiGroup } from "../../src/archive/store.js";
import type { ParsedResource } from "../../src/types.js";
import { buildStore, cleanupArchives, injectResources, namespace, pod, service, type Obj } from "../diagnostics/template-harness.js";

afterEach(cleanupArchives);

type Filter = { kind?: string; namespace?: string; name?: string; group?: string };

/** The pre-index semantics: a linear filter over every parsed resource. */
function linear(all: ParsedResource[], f: Filter): ParsedResource[] {
  return all.filter((r) =>
    (!f.kind || r.kind === f.kind) &&
    (f.group === undefined || apiGroup(r.apiVersion) === f.group) &&
    (!f.namespace || r.metadata?.namespace === f.namespace) &&
    (!f.name || r.metadata?.name === f.name));
}

describe("getClusterResources indexes", () => {
  it("returns what the linear filter returns, in the same order, for every filter shape", async () => {
    const items: Obj[] = [
      namespace("a"),
      namespace("b"),
      pod("a", "p1", {}),
      service("a", "s1", { app: "x" }),
      pod("b", "p1", {}),
      { apiVersion: "networking.istio.io/v1", kind: "Gateway", metadata: { name: "g", namespace: "a" } },
      { apiVersion: "gateway.networking.k8s.io/v1", kind: "Gateway", metadata: { name: "g", namespace: "a" } },
      pod("a", "p2", {}),
      { apiVersion: "example.com/v1", kind: "Pod", metadata: { name: "p1", namespace: "a" } },
      service("b", "s1", { app: "x" }),
    ];
    const store = await buildStore({ resources: items });
    const all = store.getClusterResources();
    expect(all.length).toBeGreaterThanOrEqual(items.length);
    const filters: Filter[] = [
      {},
      { kind: "Pod" },
      { kind: "Pod", group: "" },
      { kind: "Pod", group: "example.com" },
      { kind: "Pod", namespace: "a" },
      { kind: "Pod", namespace: "a", name: "p1" },
      { kind: "Pod", namespace: "a", name: "p1", group: "" },
      { kind: "Gateway", group: "gateway.networking.k8s.io" },
      { kind: "Gateway", group: "networking.istio.io", namespace: "a", name: "g" },
      { namespace: "b" },
      { name: "p1" },
      { namespace: "a", name: "s1" },
      { group: "" },
      { kind: "Missing" },
      { kind: "Pod", namespace: "", name: "" },
    ];
    for (const f of filters) expect(store.getClusterResources(f).map((r) => `${r.apiVersion}|${r.kind}|${r.metadata.namespace}|${r.metadata.name}`), JSON.stringify(f)).toEqual(linear(all, f).map((r) => `${r.apiVersion}|${r.kind}|${r.metadata.namespace}|${r.metadata.name}`));
  });

  it("hands out copies, so a caller sorting its result does not reorder the next lookup", async () => {
    const store = await buildStore({ resources: [pod("a", "z", {}), pod("a", "b", {})], noPodDump: true });
    store.getClusterResources({ kind: "Pod" }).sort((x, y) => x.metadata.name.localeCompare(y.metadata.name));
    expect(store.getClusterResources({ kind: "Pod" }).map((p) => p.metadata.name)).toEqual(["z", "b"]);
  });

  it("answers filtered lookups on 40k objects without scanning them per call", async () => {
    const store = await buildStore({ resources: [] });
    const items: Obj[] = [];
    for (let i = 0; i < 40_000; i++) items.push(pod(`ns-${i % 200}`, `p-${i}`, { app: `a-${i % 50}` }));
    injectResources(store, items);
    const start = performance.now();
    let found = 0;
    for (let i = 0; i < 20_000; i++) found += store.getClusterResources({ kind: "Pod", group: "", namespace: `ns-${i % 200}`, name: `p-${i}` }).length;
    expect(found).toBe(20_000);
    // A linear scan per call is 20k x 40k = 800M comparisons (tens of seconds).
    expect(performance.now() - start).toBeLessThan(3_000);
  });
});

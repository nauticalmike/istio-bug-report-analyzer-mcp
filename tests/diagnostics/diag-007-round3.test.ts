import { describe, it, expect, afterEach } from "vitest";
import { buildStore, cleanupArchives, injectResources, namespace, type Obj } from "./template-harness.js";
import { controlPlane, defaultValidator, injectedPod, injectorWebhook } from "./revision-fixtures.js";
import { orphanedRevisions } from "../../src/diagnostics/mesh-checks/revisions.js";
import type { Issue } from "../../src/diagnostics/checks.js";

afterEach(cleanupArchives);

/** Revisions 1-27 and 1-28 both run; the default tag points at 1-27. */
function base(): Obj[] {
  return [
    namespace("istio-system"),
    ...controlPlane("1-27"),
    ...controlPlane("1-28"),
    injectorWebhook("1-27"),
    injectorWebhook("1-28"),
    injectorWebhook("1-27", { tag: "default" }),
    defaultValidator("1-27"),
  ];
}

const nsName = (i: number) => `ns-${String(i).padStart(2, "0")}`;

/** `count` namespaces labelled for 1-28, each with `perNs` pods still injected by 1-27. */
function canary(count: number, perNs: number): Obj[] {
  const out = base();
  for (let i = 0; i < count; i++) {
    out.push(namespace(nsName(i), { "istio.io/rev": "1-28" }));
    for (let j = 0; j < perNs; j++) out.push(injectedPod(nsName(i), `p-${j}`, "1-27"));
  }
  return out;
}

/** A loaded store whose cluster resources are `items` (no YAML round trip for large sets). */
async function storeOf(items: Obj[]) {
  const store = await buildStore({ resources: base() });
  store.getClusterResources(); // parse the dump (its item count feeds clusterSectionGap) before swapping
  injectResources(store, items);
  return store;
}

async function issues(items: Obj[]): Promise<Issue[]> {
  const store = await storeOf(items);
  const out = orphanedRevisions(store, {});
  if (!Array.isArray(out)) throw new Error(out.notEvaluated);
  return out;
}

const restart = (list: Issue[]) => list.find((i) => i.detail.includes("restart pending"));

describe("DIAG-007 round 3: merged pod lines", () => {
  it("caps a pod list at 10 namespace segments and lists every namespace in Issue.namespaces", async () => {
    const line = restart(await issues(canary(14, 2)));
    expect(line?.detail).toMatch(/^28 pods on revision 1-27 where injection now selects 1-28 \(restart pending\): ns-00: p-0, p-1; /);
    expect(line?.detail.match(/ns-\d\d: /g)).toHaveLength(10);
    expect(line?.detail).toMatch(/ns-09: p-0, p-1; \(\+4 namespaces\)$/);
    expect(line?.detail).not.toContain("ns-10");
    expect(line?.namespace).toBeUndefined();
    expect(line?.namespaces).toEqual(Array.from({ length: 14 }, (_, i) => nsName(i)));
  });

  it("keeps a single-namespace line on Issue.namespace, uncapped text", async () => {
    const line = restart(await issues(canary(1, 2)));
    expect(line?.detail).toBe("2 pods on revision 1-27 where injection now selects 1-28 (restart pending): ns-00: p-0, p-1");
    expect(line?.namespace).toBe("ns-00");
    expect(line?.namespaces).toBeUndefined();
  });

  it("writes one namespace past the cap in the singular", async () => {
    const line = restart(await issues(canary(11, 1)));
    expect(line?.detail).toMatch(/; \(\+1 namespace\)$/);
  });

  it("sets Issue.namespaces on a stranded-revision line spanning namespaces", async () => {
    const items = [...canary(0, 0), namespace("a"), namespace("b"), injectedPod("a", "x", "1-20"), injectedPod("b", "y", "1-20")];
    const line = (await issues(items)).find((i) => i.detail.startsWith("revision 1-20 has no running istiod"));
    expect(line?.detail).toContain("(a: x; b: y)");
    expect(line?.namespaces).toEqual(["a", "b"]);
  });

  it("sets Issue.namespaces on an unserved-namespace group", async () => {
    const items = [...base(), namespace("a", { "istio.io/rev": "gone" }), namespace("b", { "istio.io/rev": "gone" })];
    const line = (await issues(items)).find((i) => i.detail.startsWith("istio.io/rev=gone selects no injector webhook"));
    expect(line?.namespaces).toEqual(["a", "b"]);
  });

  it("judges 40k restart-pending canary pods in under a second", async () => {
    const store = await storeOf(canary(40, 1000));
    const start = performance.now();
    const out = orphanedRevisions(store, {});
    const elapsed = performance.now() - start;
    expect(Array.isArray(out) ? restart(out)?.detail : out.notEvaluated).toMatch(/^40000 pods on revision 1-27 .*\(\+30 namespaces\)$/);
    expect(elapsed).toBeLessThan(1000);
  });
});

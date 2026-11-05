import { describe, it, expect, afterEach } from "vitest";
import { ordered, waypointUnusable } from "../../src/diagnostics/mesh-checks/ambient-traffic.js";
import type { Issue } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives, injectResources, namespace, pod, waypoint, type Obj } from "./template-harness.js";
import { ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

describe("ambient traffic issue ordering (round 3)", () => {
  it("keeps the most severe of duplicate details, whatever their order", () => {
    const a: Issue = { detail: "same", severity: "critical", namespace: "x" };
    const b: Issue = { detail: "same", severity: "info", namespace: "x" };
    const c: Issue = { detail: "other", severity: "warning" };
    expect(ordered([a, b, c]).map((i) => [i.detail, i.severity])).toEqual([["same", "critical"], ["other", "warning"]]);
    expect(ordered([b, a, c]).map((i) => [i.detail, i.severity])).toEqual([["same", "critical"], ["other", "warning"]]);
  });
});

describe("DIAG-012 round 3: large archive", () => {
  it("judges 20k labelled pods and 2k waypoints in under 3 s (gateway pods and mesh pods indexed)", async () => {
    const store = await buildStore({ resources: [namespace("seed")] });
    const items: Obj[] = [ztunnelDaemonSet()];
    const namespaces = 100;
    for (let n = 0; n < namespaces; n++) items.push(namespace(`ns-${n}`));
    // 2k ready waypoints with no waypoint pod: each binding to one checks for its pods.
    for (let w = 0; w < 2_000; w++) items.push(waypoint(`ns-${w % namespaces}`, `wp-${w}`, { labels: { "istio.io/waypoint-for": "all" } }));
    for (let i = 0; i < 20_000; i++) {
      const ns = `ns-${i % namespaces}`;
      // Half name an existing waypoint of their namespace, half a missing one.
      const target = i % 2 ? `wp-${(i % 20) * namespaces + (i % namespaces)}` : `ghost-${i % 50}`;
      items.push({ ...pod(ns, `p-${i}`, { app: `a-${i}`, "istio.io/use-waypoint": target }), status: { phase: "Running" } });
    }
    store.getClusterResources(); // parse the dumps first, so the sections count as present
    injectResources(store, items);
    const start = performance.now();
    const issues = waypointUnusable(store) as Issue[];
    expect(issues, JSON.stringify(issues).slice(0, 300)).toBeInstanceOf(Array);
    expect(issues.some((i) => /no waypoint pod/.test(i.detail))).toBe(true);
    expect(issues.some((i) => /no Gateway/.test(i.detail))).toBe(true);
    expect(performance.now() - start).toBeLessThan(3_000);
  });
});

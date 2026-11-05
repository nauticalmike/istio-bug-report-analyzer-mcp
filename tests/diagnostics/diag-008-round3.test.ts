import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, buildStore, cleanupArchives, namespace, type Obj } from "./template-harness.js";
import { controlPlane, injectedPod, injectorWebhook, plainPod } from "./revision-fixtures.js";
import { dualModeNamespaces } from "../../src/diagnostics/mesh-checks/revisions.js";
import type { Issue } from "../../src/diagnostics/checks.js";

afterEach(cleanupArchives);

const AMBIENT = { "istio.io/dataplane-mode": "ambient" };
const nsName = (i: number) => `amb-${String(i).padStart(2, "0")}`;

function base(): Obj[] {
  return [namespace("istio-system"), ...controlPlane(""), injectorWebhook("")];
}

async function issues(resources: Obj[]): Promise<Issue[]> {
  const out = dualModeNamespaces(await buildStore({ resources }), {});
  if (!Array.isArray(out)) throw new Error(out.notEvaluated);
  return out;
}

describe("DIAG-008 round 3: merged lines", () => {
  it("caps the restart-pending pod list at 10 namespaces and lists all of them in Issue.namespaces", async () => {
    const resources = base();
    for (let i = 0; i < 12; i++) resources.push(namespace(nsName(i), AMBIENT), injectedPod(nsName(i), "old", "default"), ambientPod(nsName(i), "new"));
    const line = (await issues(resources)).find((i) => i.detail.includes("(restart pending)"));
    expect(line?.detail).toMatch(/^12 pods in ambient namespaces still run a sidecar/);
    expect(line?.detail.match(/amb-\d\d: /g)).toHaveLength(10);
    expect(line?.detail).toMatch(/amb-09: old; \(\+2 namespaces\)$/);
    expect(line?.namespace).toBeUndefined();
    expect(line?.namespaces).toEqual(Array.from({ length: 12 }, (_, i) => nsName(i)));
  });

  it("sets Issue.namespaces on an IST0123 group and on a stale-label group spanning namespaces", async () => {
    const resources = [
      ...base(),
      namespace("orders", { ...AMBIENT, "istio-injection": "enabled" }),
      namespace("billing", { ...AMBIENT, "istio-injection": "enabled" }),
      namespace("old-a", { ...AMBIENT, "istio.io/rev": "gone" }),
      namespace("old-b", { ...AMBIENT, "istio.io/rev": "gone" }),
      plainPod("orders", "api"),
    ];
    const out = await issues(resources);
    const conflict = out.find((i) => i.detail.includes("(IST0123)"));
    const stale = out.find((i) => i.detail.includes("(stale label)"));
    expect(conflict?.namespaces).toEqual(["billing", "orders"]);
    expect(stale?.namespaces).toEqual(["old-a", "old-b"]);
  });

  it("keeps a one-namespace group on Issue.namespace", async () => {
    const out = await issues([...base(), namespace("orders", { ...AMBIENT, "istio-injection": "enabled" })]);
    const conflict = out.find((i) => i.detail.includes("(IST0123)"));
    expect(conflict?.namespace).toBe("orders");
    expect(conflict?.namespaces).toBeUndefined();
  });
});

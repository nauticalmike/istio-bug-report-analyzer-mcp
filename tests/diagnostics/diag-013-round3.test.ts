import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, service, sidecarPod, type Obj } from "./template-harness.js";
import { AMBIENT_NS, virtualService, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

async function run(resources: Obj[]) {
  const { findings } = await runEngine({ resources }, ["sidecar-to-ambient"]);
  return finding(findings, "DIAG-013");
}

const retryVs = (name: string) => virtualService("legacy", name, { hosts: ["api"], http: [{ retries: { attempts: 3 }, route: [{ destination: { host: "api" } }] }] });
const legacy: Obj[] = [namespace("legacy", { "istio-injection": "enabled" }), sidecarPod("legacy", "api", "1.31.2", { app: "api" }), service("legacy", "api", { app: "api" })];

describe("DIAG-013 round 3", () => {
  it("a sidecar Service with ambient clients already present is critical, worded as for ServiceEntries", async () => {
    const f = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart"), ...legacy, retryVs("api-retries")]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^Service legacy\/api \(sidecar, ambient clients, no waypoint\): VirtualService legacy\/api-retries \(retries\)/)]);
  });

  it("keeps the migration-blocker warning while no ambient client exists", async () => {
    const f = await run([ztunnelDaemonSet(), ...legacy, retryVs("api-retries")]);
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/\(sidecar, no waypoint; migration blocker\)/)]);
  });

  it("caps the parts of one host's line at 8, then +N more", async () => {
    const vss = Array.from({ length: 12 }, (_, i) => retryVs(`api-${String(i).padStart(2, "0")}`));
    const f = await run([ztunnelDaemonSet(), ...legacy, ...vss]);
    const detail = f?.affectedResources[0] ?? "";
    expect(detail.match(/VirtualService /g)).toHaveLength(8);
    expect(detail).toMatch(/; \+4 more/);
  });
});

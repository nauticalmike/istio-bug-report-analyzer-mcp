import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, envoyFilter, finding, namespace, runEngine, type Obj } from "./template-harness.js";
import { AMBIENT_NS, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

const luaPatch = {
  applyTo: "HTTP_FILTER",
  match: { context: "SIDECAR_INBOUND", listener: { filterChain: { filter: { name: "envoy.filters.network.http_connection_manager" } } } },
  patch: { operation: "INSERT_BEFORE", value: { name: "envoy.filters.http.lua", typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua" } } },
};

async function run(resources: Obj[]) {
  const { findings } = await runEngine({ resources }, ["envoyfilter"]);
  return finding(findings, "DIAG-014");
}

describe("DIAG-014 round 3", () => {
  it("a root-namespace filter selecting ambient pods in several namespaces lists them in Issue.namespaces", async () => {
    const ef = envoyFilter("istio-system", "lua-all", { workloadSelector: { labels: { tier: "web" } }, configPatches: [luaPatch] });
    const f = await run([
      ztunnelDaemonSet(),
      namespace("shop", AMBIENT_NS),
      namespace("web", AMBIENT_NS),
      ambientPod("shop", "cart", { tier: "web" }),
      ambientPod("web", "front", { tier: "web" }),
      ef,
    ]);
    expect(f?.issues).toHaveLength(1);
    expect(f?.issues?.[0].namespace).toBe("istio-system");
    expect(f?.issues?.[0].namespaces).toEqual(["istio-system", "shop", "web"]);
  });

  it("a filter selecting pods of its own namespace only sets no namespaces list", async () => {
    const ef = envoyFilter("shop", "lua", { workloadSelector: { labels: { tier: "web" } }, configPatches: [luaPatch] });
    const f = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { tier: "web" }), ef]);
    expect(f?.issues?.[0].namespace).toBe("shop");
    expect(f?.issues?.[0].namespaces).toBeUndefined();
  });
});

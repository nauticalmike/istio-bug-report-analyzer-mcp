import { describe, it, expect, afterEach } from "vitest";
import { scanLogRules, type LogRule } from "../../src/diagnostics/log-rules.js";
import { parsePushStatus, parseSyncz } from "../../src/diagnostics/sources/xds-status.js";
import { buildStore, cleanupArchives } from "./template-harness.js";
import { CART_POD, GATEWAY_POD, ISTIOD_ID, PUSH_STATUS, SYNCZ, controlPlaneFiles } from "./control-plane-fixtures.js";

// Additions to the shared helpers: sentTime in syncz, and per-line grouping in log rules.

afterEach(cleanupArchives);

describe("parseSyncz sentTime", () => {
  it("keeps the sent time of the resources map, null for the legacy fields", () => {
    const proxies = parseSyncz(SYNCZ, ISTIOD_ID)!;
    expect(proxies[0].types.find((t) => t.type === "CDS")?.sentTime).toBe("2026-03-18T10:00:00.000Z");
    expect(proxies[2].types.find((t) => t.type === "CDS")?.sentTime).toBeNull();
  });

  it("drops Go's zero time and unparseable times", () => {
    const [p] = parseSyncz(
      [{ proxy: "a.b", resources: { "type.googleapis.com/envoy.config.cluster.v3.Cluster": { sent: "x", acked: "y", sentTime: "0001-01-01T00:00:00Z" }, "type.googleapis.com/envoy.config.listener.v3.Listener": { sent: "x", sentTime: "soon" } } }],
      ISTIOD_ID,
    )!;
    expect(p.types.map((t) => t.sentTime)).toEqual([null, null]);
  });
});

describe("parsePushStatus namespaces", () => {
  it("lists the namespaces of the proxies each metric names", () => {
    const metrics = parsePushStatus(PUSH_STATUS)!;
    expect(metrics.map((m) => [m.metric, m.namespaces])).toEqual([
      ["pilot_conflict_inbound_listener", ["payments", "shop"]],
      ["pilot_eds_no_instances", []],
      ["pilot_vservice_dup_domain", ["shop"]],
    ]);
  });
});

describe("log rule groups", () => {
  const rule: LogRule = {
    id: "t_group_rejected",
    components: ["proxy"],
    match: /gRPC config for (\S+) rejected: (.*)/,
    hint: "rejected",
    group: (line) => {
      const m = /gRPC config for (\S+) rejected: (.*)/.exec(line);
      return m ? { key: `${m[1].slice(m[1].lastIndexOf(".") + 1)}|${m[2]}` } : null;
    },
  };

  it("buckets matching lines by key with line counts, distinct sources and one example each", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const hits = (await scanLogRules(store, [rule])).hits.get(rule.id)!;
    expect(hits.count).toBe(3);
    expect(hits.groups).toEqual([
      {
        key: "Listener|Invalid regex",
        count: 3,
        members: 2,
        sources: 2,
        memberExamples: [`proxy/shop/${CART_POD}`, `proxy/shop/${GATEWAY_POD}`],
        memberIds: [`proxy/shop/${CART_POD}`, `proxy/shop/${GATEWAY_POD}`],
        sourceIds: [`proxy/shop/${CART_POD}`, `proxy/shop/${GATEWAY_POD}`],
        example: expect.stringContaining("rejected: Invalid regex"),
        firstTime: "2026-03-18T09:59:00.000Z",
        lastTime: "2026-03-18T10:03:00.000Z",
      },
    ]);
    expect(hits.groupsOverflow).toBe(0);
  });

  it("counts distinct members the rule names in the line, else the source", async () => {
    const byWord: LogRule = {
      id: "t_group_member",
      components: ["istiod"],
      match: "ACK ERROR",
      group: (line) => {
        const m = /ADS:(\w+): ACK ERROR (\S+)/.exec(line);
        return m ? { key: m[1], member: m[2].replace(/-\d+$/, "") } : null;
      },
    };
    const store = await buildStore({ files: controlPlaneFiles() });
    const hits = (await scanLogRules(store, [byWord])).hits.get(byWord.id)!;
    expect(hits.groups).toMatchObject([{ key: "LDS", count: 2, members: 2, memberExamples: ["payments-5f7d8b9c6-k8m2n.payments", "payments-5f7d8b9c6-p3p4q.payments"] }]);
  });

  it("caps the number of groups and counts the lines past the cap", async () => {
    const lines = Array.from({ length: 12 }, (_, i) => `2026-03-18T10:00:0${i % 10}.000000Z\twarning\tenvoy config\tgRPC config for x.T${i} rejected: e${i}`).join("\n");
    const store = await buildStore({ files: { [`proxies/shop/${CART_POD}/istio-proxy.log`]: lines } });
    const capped: LogRule = { ...rule, id: "t_group_capped", maxGroups: 10 };
    const hits = (await scanLogRules(store, [capped])).hits.get(capped.id)!;
    expect(hits.groups).toHaveLength(10);
    expect(hits.groupsOverflow).toBe(2);
    expect(hits.count).toBe(12);
  });

  it("leaves groups out for rules without a group function", async () => {
    const store = await buildStore({ files: controlPlaneFiles() });
    const plain: LogRule = { id: "t_group_none", components: ["proxy"], match: "rejected" };
    expect((await scanLogRules(store, [plain])).hits.get(plain.id)!.groups).toBeUndefined();
  });
});

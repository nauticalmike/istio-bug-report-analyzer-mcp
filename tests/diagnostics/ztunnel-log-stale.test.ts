import { describe, it, expect, afterEach } from "vitest";
import { ztunnelLogGap, ztunnelLogScan } from "../../src/diagnostics/sources/ztunnel-log.js";
import { buildStore, cleanupArchives } from "./template-harness.js";
import { ALLOW_GAP, CNI_AGENT_LINE, TS, accessLine, logOf, plainLine, ztunnelPodResource } from "./ztunnel-log-fixtures.js";

afterEach(cleanupArchives);

// logFilesOf marks logs of pods missing from a pod dump that covers their namespace as
// stale; ztunnelLogScan does not read them at all and counts the files and pods only.
describe("ztunnelLogScan stale logs", () => {
  it("does not read logs of pods no longer in the dump and counts their files and pods", async () => {
    const store = await buildStore({
      resources: [ztunnelPodResource("ztunnel-a1b2c")],
      files: {
        "proxies/istio-system/ztunnel-a1b2c/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP })]),
        "proxies/istio-system/ztunnel-old00/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP }), accessLine({ at: 2, error: ALLOW_GAP }), accessLine({ at: 3, level: "info" })]),
      },
    });
    const scan = await ztunnelLogScan(store);
    expect(scan.classes.get("policy-allow-gap")?.count).toBe(1);
    expect(scan.staleFiles).toBe(1);
    expect(scan.staleSources).toBe(1);
    // Stale files are not streamed: only the live file is read.
    expect(scan.scan.components.ztunnel).toMatchObject({ files: 2, read: 1, stale: 1 });
    expect([...scan.pods.values()].some((p) => p.pod === "ztunnel-old00")).toBe(false);
    expect(ztunnelLogGap(scan)).toBeNull();
  });

  it("is not evaluated when every ztunnel log is of a pod no longer in the dump", async () => {
    const store = await buildStore({
      resources: [ztunnelPodResource("ztunnel-a1b2c")],
      files: {
        "proxies/istio-system/ztunnel-old00/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP })]),
        "proxies/istio-system/ztunnel-old11/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP })]),
      },
    });
    const scan = await ztunnelLogScan(store);
    expect(scan.scan.components.ztunnel).toMatchObject({ files: 2, read: 0, stale: 2 });
    expect(ztunnelLogGap(scan)).toBe("not evaluated: all 2 ztunnel logs are of pods no longer in the dump");
  });

  it("says ztunnel logs were not collected when ztunnel proxy dirs hold only a config_dump", async () => {
    const store = await buildStore({
      resources: [ztunnelPodResource("ztunnel-a1b2c")],
      files: {
        "proxies/istio-system/ztunnel-a1b2c/config_dump": JSON.stringify({ workloads: {}, services: {}, policies: [], certificates: [] }),
        "proxies/istio-system/ztunnel-d3e4f/config_dump": JSON.stringify({ workloads: {}, services: {}, policies: [], certificates: [] }),
      },
    });
    const scan = await ztunnelLogScan(store);
    expect(ztunnelLogGap(scan)).toBe("not evaluated: ztunnel logs not collected (2 ztunnel pods present, config_dump only)");
  });
});

describe("ztunnelLogScan CNI agent connection", () => {
  it("records per pod the failure window, the log span and whether ztunnel connected afterwards", async () => {
    const store = await buildStore({
      resources: [ztunnelPodResource("ztunnel-a1b2c"), ztunnelPodResource("ztunnel-d3e4f", "node-2")],
      files: {
        "proxies/istio-system/ztunnel-a1b2c/istio-proxy.log": logOf([
          plainLine(0, "info", "ztunnel", "version: 1.31.2"),
          CNI_AGENT_LINE(2),
          CNI_AGENT_LINE(5),
          plainLine(6, "info", "inpod::workloadmanager", "handling new stream"),
          plainLine(600, "info", "ztunnel", "still running"),
        ]),
        "proxies/istio-system/ztunnel-d3e4f/istio-proxy.log": logOf([plainLine(0, "info", "ztunnel", "version: 1.31.2"), CNI_AGENT_LINE(3), CNI_AGENT_LINE(9)]),
      },
    });
    const scan = await ztunnelLogScan(store);
    const a = scan.cniConnect.get("ztunnel/istio-system/ztunnel-a1b2c");
    expect(a).toMatchObject({ count: 2, first: Date.parse(TS(2)), last: Date.parse(TS(5)), connectedAfter: true });
    expect(scan.spans.get("ztunnel/istio-system/ztunnel-a1b2c")).toEqual({ first: Date.parse(TS(0)), last: Date.parse(TS(600)) });
    const b = scan.cniConnect.get("ztunnel/istio-system/ztunnel-d3e4f");
    expect(b).toMatchObject({ count: 2, connectedAfter: false });
    expect(scan.spans.get("ztunnel/istio-system/ztunnel-d3e4f")?.last).toBe(Date.parse(TS(9)));
  });
});

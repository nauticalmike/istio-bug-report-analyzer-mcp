import { describe, it, expect, afterEach } from "vitest";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { cleanupArchives, finding, runTemplates } from "./template-harness.js";

afterEach(cleanupArchives);

const PROXY_LOG = "proxies/default/test-pod-abc123/istio-proxy.log";
const ISTIOD_LOG = "istio/istio-system/istiod-abc/discovery.log";

/** Logs whose newest timestamp is the given day (the capture date). */
function loggedOn(day: string): Record<string, string> {
  return {
    [PROXY_LOG]: `${day}T08:00:00.000Z\tinfo\tready\n${day}T09:30:00.000Z\twarn\tslow upstream\n`,
    [ISTIOD_LOG]: `${day}T07:00:00.000Z\tinfo\tads\tpush\n`,
  };
}

function versions(cp: string, client = cp): string {
  return bugReportVersions(cp).replace(/^(version\.BuildInfo\{Version:")[^"]*/m, `$1${client}`);
}

describe("DIAG-006 judges support as of the capture date", () => {
  it("does not flag a minor that was still supported when the archive was captured", async () => {
    // 1.29 reached end of life on 2026-10-15; this archive was captured before that.
    const f = finding(await runTemplates({ versions: versions("1.29.4"), files: loggedOn("2026-09-10") }, ["version"]), "DIAG-006");
    expect(f).toBeUndefined();
  });

  it("flags a minor past end of life on the capture date and names that date", async () => {
    const f = finding(await runTemplates({ versions: versions("1.28.9"), files: loggedOn("2026-09-10") }, ["version"]), "DIAG-006");
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toContain("was not a supported Istio minor on 2026-09-10");
    expect(f?.affectedResources[0]).toContain("capture date");
  });

  it("reports an unsupported istioctl client alone as info", async () => {
    const f = finding(await runTemplates({ versions: versions("1.31.2", "1.26.1"), files: loggedOn("2026-09-10") }, ["version"]), "DIAG-006");
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringContaining("client (istioctl) 1.26.1")]);
  });

  it("keeps warning severity when the control plane is unsupported too", async () => {
    const f = finding(await runTemplates({ versions: versions("1.26.4", "1.26.1"), files: loggedOn("2026-09-10") }, ["version"]), "DIAG-006");
    expect(f?.severity).toBe("warning");
  });

  it("falls back to today's window as info when the archive has no capture date", async () => {
    const files = { [PROXY_LOG]: "no timestamps here\n", [ISTIOD_LOG]: "none here either\n" };
    const f = finding(await runTemplates({ versions: versions("1.28.9"), files }, ["version"]), "DIAG-006");
    expect(f?.affectedResources[0]).toContain("as of today: no capture date found in the archive");
    // Without the capture date, today's window may postdate the archive: not a warning.
    expect(f?.severity).toBe("info");
  });

  it("names the source when the capture date comes from cluster events", async () => {
    const files = {
      [PROXY_LOG]: "no timestamps here\n",
      [ISTIOD_LOG]: "none here either\n",
      "cluster/events": 'apiVersion: v1\nkind: Event\nmetadata:\n  name: a\nlastTimestamp: "2026-09-10T10:00:00Z"\n',
    };
    const f = finding(await runTemplates({ versions: versions("1.28.9"), files }, ["version"]), "DIAG-006");
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toContain("on 2026-09-10 (capture date, the newest event in cluster/events");
  });
});

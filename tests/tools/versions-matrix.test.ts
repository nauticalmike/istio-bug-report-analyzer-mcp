import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getVersions } from "../../src/tools/versions.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function versionsText(versionsFile: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "versions-matrix-"));
  dirs.push(dir);
  const archiveDir = join(dir, "bug-report");
  await createMinimalArchive(archiveDir);
  await writeFile(join(archiveDir, "versions"), versionsFile);
  const store = await BugReportStore.fromDirectory(archiveDir);
  return (getVersions(store).content[0] as { text: string }).text;
}

const buildInfo = (v: string) =>
  `version.BuildInfo{Version:"${v}", GitRevision:"0000000000000000000000000000000000000000", GolangVersion:"", BuildStatus:"Clean", GitTag:"${v}"}`;
const serverInfo = (rev: string, v: string) => `version.ServerInfo{Component:"pilot", Revision:"${rev}", Info:${buildInfo(v)}}`;

function bugReportVersions(opts: { client: string; revisions: { rev: string; body: string }[]; proxies: string[] }): string {
  return [
    "CLI version:",
    buildInfo(opts.client),
    "",
    "✅ The following Istio control plane revisions/versions were found in the cluster:",
    ...opts.revisions.flatMap(({ rev, body }) => [`Revision ${rev}:`, body, ""]),
    "✅ The following proxy revisions/versions were found in the cluster:",
    `Revision default: Versions {${opts.proxies.join(", ")}}`,
    "",
  ].join("\n");
}

describe("versions tool", () => {
  it("does not report skew between a -solo build and the community build of the same version", async () => {
    const text = await versionsText(bugReportVersions({
      client: "1.31.2-solo",
      revisions: [{ rev: "default", body: `&version.MeshInfo{${serverInfo("default", "1.31.2-solo")}}` }],
      proxies: ["1.31.2"],
    }));
    expect(text).not.toContain("VERSION SKEW");
  });

  it("reports patch-only differences as supported, not as skew", async () => {
    const text = await versionsText(bugReportVersions({
      client: "1.31.2",
      revisions: [{ rev: "default", body: `&version.MeshInfo{${serverInfo("default", "1.31.2")}}` }],
      proxies: ["1.31.0", "1.31.2"],
    }));
    expect(text).not.toContain("VERSION SKEW");
    expect(text).toContain("Patch-level differences only (supported): 1.31.0, 1.31.2");
  });

  it("reports minor skew with the DIAG-001 detail", async () => {
    const text = await versionsText(bugReportVersions({
      client: "1.31.2",
      revisions: [{ rev: "default", body: `&version.MeshInfo{${serverInfo("default", "1.31.2")}}` }],
      proxies: ["1.29.4"],
    }));
    expect(text).toContain("VERSION SKEW DETECTED");
    expect(text).toContain("proxies on 1.29.4, control plane 1.31: 2 minors behind");
  });

  it("collapses identical istiod entries in the raw MeshInfo output with a count", async () => {
    const entries = Array.from({ length: 40 }, () => serverInfo("default", "1.31.2")).join(", ");
    const text = await versionsText(bugReportVersions({
      client: "1.31.2",
      revisions: [{ rev: "default", body: `&version.MeshInfo{${entries}}` }],
      proxies: ["1.31.2"],
    }));
    expect(text.split(serverInfo("default", "1.31.2")).length - 1).toBe(1);
    expect(text).toContain(`${serverInfo("default", "1.31.2")} (x40)`);
  });

  it("collapses identical MeshInfo blocks repeated across revisions", async () => {
    const block = `&version.MeshInfo{${serverInfo("default", "1.31.2")}}`;
    const text = await versionsText(bugReportVersions({
      client: "1.31.2",
      revisions: [{ rev: "a", body: block }, { rev: "b", body: block }, { rev: "c", body: block }],
      proxies: ["1.31.2"],
    }));
    const raw = text.slice(text.indexOf("Raw version output:"));
    expect(raw.split(block).length - 1).toBe(1);
    expect(raw).toContain("Revisions a, b, c (same MeshInfo, x3):");
  });

  // istioctl up to ~1.19 wrote each MeshInfo with kr/pretty: one field per line, `}` at column 0 closing it.
  const prettyEntry = (v: string) =>
    ["    {", '        Component: "pilot",', '        Revision:  "default",', `        Info:      ${buildInfo(v)},`, "    },"].join("\n");
  const prettyMeshInfo = (entries: string[]) => ["&version.MeshInfo{", ...entries, "}"].join("\n");

  it("collapses identical entries of a multi-line (kr/pretty) MeshInfo with a count", async () => {
    const entries = [...Array.from({ length: 40 }, () => prettyEntry("1.18.7")), prettyEntry("1.18.6")];
    const versions = bugReportVersions({ client: "1.18.7", revisions: [{ rev: "default", body: prettyMeshInfo(entries) }], proxies: ["1.18.7"] });
    const text = await versionsText(versions);
    const raw = text.slice(text.indexOf("Raw version output:"));
    expect(raw.split('Version:"1.18.7"').length - 1).toBe(2); // the CLI line and one entry
    expect(raw).toContain("    }, (x40)");
    expect(raw).toContain('Version:"1.18.6"');
    expect(raw.split("\n").length).toBeLessThan(30);
    expect(text).not.toContain("Revisions without a control plane version");
  });

  it("collapses a kr/pretty MeshInfo whose BuildInfo is multi-line too, and reads its versions", async () => {
    const nested = (v: string) =>
      [
        "    {",
        '        Component: "pilot",',
        '        Revision:  "default",',
        "        Info:      version.BuildInfo{",
        `            Version:       "${v}",`,
        '            BuildStatus:   "Clean",',
        "        },",
        "    },",
      ].join("\n");
    const entries = [...Array.from({ length: 12 }, () => nested("1.18.7")), nested("1.18.6")];
    const text = await versionsText(bugReportVersions({ client: "1.18.7", revisions: [{ rev: "default", body: prettyMeshInfo(entries) }], proxies: ["1.18.7"] }));
    const raw = text.slice(text.indexOf("Raw version output:"));
    expect(raw).toContain("    }, (x12)");
    expect(raw.split('Version:       "1.18.7"').length - 1).toBe(1);
    expect(text).toMatch(/1\.18\.6/);
    expect(text).not.toContain("Revisions without a control plane version");
  });

  it("merges revisions whose multi-line MeshInfo is identical", async () => {
    const body = prettyMeshInfo([prettyEntry("1.18.7"), prettyEntry("1.18.7")]);
    const text = await versionsText(bugReportVersions({ client: "1.18.7", revisions: [{ rev: "a", body }, { rev: "b", body }], proxies: ["1.18.7"] }));
    expect(text).toContain("Revisions a, b (same MeshInfo, x2):");
  });

  it("reports a revision without running istiod as a tag or idle revision, not as missing data", async () => {
    const text = await versionsText(bugReportVersions({
      client: "1.31.2",
      revisions: [
        { rev: "1-31", body: `&version.MeshInfo{${serverInfo("1-31", "1.31.2")}}` },
        { rev: "prod-stable", body: `no running Istio pods in namespace "istio-system"` },
      ],
      proxies: ["1.31.2"],
    }));
    expect(text).toContain("prod-stable: no running istiod pods carry this revision (usually a revision tag or an idle revision; not missing data)");
  });

  it("warns when istioctl is older than the control plane and suggests re-collecting", async () => {
    const text = await versionsText(bugReportVersions({
      client: "1.29.3",
      revisions: [{ rev: "default", body: `&version.MeshInfo{${serverInfo("default", "1.31.2")}}` }],
      proxies: ["1.31.2"],
    }));
    expect(text).toContain("istioctl client 1.29.3 is older than the control plane (1.31)");
    expect(text).toContain("re-collect the bug report with istioctl 1.31");
  });
});

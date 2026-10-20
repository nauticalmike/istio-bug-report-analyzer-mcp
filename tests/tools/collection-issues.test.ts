import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { parseCollectionIssues, getCollectionIssues } from "../../src/tools/collection-issues.js";
import { loadBugReport } from "../../src/tools/load.js";
import { getOverview } from "../../src/tools/overview.js";
import { getIstiodDebug } from "../../src/tools/istiod-debug.js";

const MARSHAL_ERR =
  "received unsuccessful status code 500: json: error calling MarshalJSON for type *krt.DebugHandler: json: unsupported type: map[gatewaycommon.ConflictOwner]map[v1.SectionName]v1.ListenerConditionReason";

// Shape of the bug-report.log istioctl 1.31.2 writes when istiod debug collection fails.
const ISTIO_131_LOG = [
  "2026-10-20T20:23:09.841583Z\terror\tpodExec error: error exec'ing into istio-system/istiod-6dc487f44f-sffgt discovery container: command terminated with exit code 255",
  `Error: ${MARSHAL_ERR}`,
  "",
  "",
  "stderr:",
  `Error: ${MARSHAL_ERR}`,
  "",
  "",
  "stdout:",
  `2026-10-20T20:23:09.090425Z\terror\t${MARSHAL_ERR}`,
  "2026-10-20T20:23:10.000000Z\tinfo\tDone.",
].join("\n");

describe("parseCollectionIssues", () => {
  it("deduplicates repeated errors across stderr/stdout/log-line forms", () => {
    const issues = parseCollectionIssues(ISTIO_131_LOG);
    expect(issues.map((i) => i.message)).toEqual([
      "podExec error: error exec'ing into istio-system/istiod-6dc487f44f-sffgt discovery container: command terminated with exit code 255",
      MARSHAL_ERR,
    ]);
    expect(issues[1].count).toBe(3);
    expect(issues.every((i) => i.level === "error")).toBe(true);
  });

  it("folds Istio's rate-limited '(repeated N times)' lines into the same issue", () => {
    const issues = parseCollectionIssues(
      [
        `2026-10-20T20:23:09.090425Z\terror\t${MARSHAL_ERR}`,
        `2026-10-20T20:23:09.190425Z\terror\t${MARSHAL_ERR} (repeated 4 times)`,
      ].join("\n"),
    );
    expect(issues).toEqual([{ level: "error", message: MARSHAL_ERR, count: 5 }]);
  });

  it("ignores info lines", () => {
    expect(parseCollectionIssues("2026-10-20T20:23:10.000000Z\tinfo\tDone.\n")).toEqual([]);
  });

  it("keeps warnings", () => {
    const issues = parseCollectionIssues("2026-10-20T20:23:10.000000Z\twarn\tskipping namespace kube-system\n");
    expect(issues).toEqual([{ level: "warn", message: "skipping namespace kube-system", count: 1 }]);
  });
});

describe("collection issues in tool output", () => {
  let tempDir: string;
  let archiveDir: string;
  let store: BugReportStore;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "collection-issues-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    await writeFile(join(archiveDir, "bug-report.log"), ISTIO_131_LOG);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("reads bug-report.log once per store", async () => {
    const first = getCollectionIssues(store);
    expect(getCollectionIssues(store)).toBe(first);
    expect((await first).length).toBe(2);
  });

  it("load_bug_report lists collection errors", async () => {
    const result = await loadBugReport({ path: archiveDir }, () => null, () => {}, () => {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Collection issues (2)");
    expect(text).toContain("status code 500");
    expect(text).toContain("(x3)");
  });

  it("get_overview lists collection errors", async () => {
    const text = ((await getOverview(store)).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Collection issues (2)");
    expect(text).toContain("status code 500");
  });

  it("get_istiod_debug explains a missing endpoint with the collection error", async () => {
    const text = ((await getIstiodDebug(store, { endpoint: "krt" })).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain('Debug endpoint "krt" not found');
    expect(text).toContain("bug-report.log");
    expect(text).toContain("status code 500");
  });

  it("omits the section when bug-report.log has no issues", async () => {
    const cleanDir = join(tempDir, "clean");
    await createMinimalArchive(cleanDir);
    const clean = await BugReportStore.fromDirectory(cleanDir);
    const text = ((await getOverview(clean)).content[0] as { type: "text"; text: string }).text;
    expect(text).not.toContain("Collection issues");
  });
});

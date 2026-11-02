import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { CollectionIssueCollector, MAX_COLLECTION_ISSUES, formatCollectionIssues, parseCollectionIssues, getCollectionIssues } from "../../src/tools/collection-issues.js";
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

// Shape of istioctl's multi-error output: a count header, then one tab-indented bullet per error.
const MULTI_ERROR_LOG = [
  "2026-10-20T20:23:09.000000Z\terror\t3 errors occurred:",
  "\t* failed to fetch /debug/syncz: received unsuccessful status code 404",
  "\t* failed to fetch /debug/krtz: received unsuccessful status code 404",
  "\t* the v1alpha3 API is deprecated, use v1",
  "",
  "",
  "Error: 1 error occurred:",
  "\t* context deadline exceeded",
  "",
  "2026-10-20T20:23:10.000000Z\tinfo\tDone.",
].join("\n");

describe("parseCollectionIssues multi-error details", () => {
  it("keeps the detail bullets under their 'N errors occurred:' header", () => {
    const issues = parseCollectionIssues(MULTI_ERROR_LOG);
    expect(issues).toHaveLength(2);
    expect(issues[0]).toMatchObject({
      level: "error",
      message: "3 errors occurred:",
      details: [
        "failed to fetch /debug/syncz: received unsuccessful status code 404",
        "failed to fetch /debug/krtz: received unsuccessful status code 404",
        "the v1alpha3 API is deprecated, use v1",
      ],
    });
    expect(issues[1]).toMatchObject({ message: "1 error occurred:", details: ["context deadline exceeded"] });
  });

  it("treats headers with different details as different issues", () => {
    const issues = parseCollectionIssues([MULTI_ERROR_LOG, MULTI_ERROR_LOG.replace("deadline exceeded", "canceled")].join("\n"));
    expect(issues.map((i) => [i.message, i.count])).toEqual([["3 errors occurred:", 2], ["1 error occurred:", 1], ["1 error occurred:", 1]]);
  });

  it("get_istiod_debug cites a multi-error header by its debug-related details", async () => {
    const dir = await mkdtemp(join(tmpdir(), "collection-issues-multi-"));
    try {
      await createMinimalArchive(dir);
      await writeFile(join(dir, "bug-report.log"), MULTI_ERROR_LOG);
      const store = await BugReportStore.fromDirectory(dir);
      const text = ((await getIstiodDebug(store, { endpoint: "krtz" })).content[0] as { type: "text"; text: string }).text;
      expect(text).toContain("  - 3 errors occurred:\n      * failed to fetch /debug/syncz: received unsuccessful status code 404");
      expect(text).not.toContain("context deadline exceeded");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("lists the details in tool output", () => {
    const text = formatCollectionIssues(parseCollectionIssues(MULTI_ERROR_LOG)).join("\n");
    expect(text).toContain("  - [error] 3 errors occurred:\n      * failed to fetch /debug/syncz: received unsuccessful status code 404\n");
    expect(text).toContain("      * context deadline exceeded");
  });
});

describe("parseCollectionIssues port variants", () => {
  const portForward = (port: number) => `2026-10-20T20:23:09.000000Z\terror\tfailed to port-forward to istio-system/istiod-abc: listen tcp4 127.0.0.1:${port}: bind: address already in use`;

  it("collapses messages that differ only in port numbers and counts the variants", () => {
    const lines = Array.from({ length: 50 }, (_, i) => portForward(30000 + i));
    lines.push(portForward(30000));
    const issues = parseCollectionIssues(lines.join("\n"));
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ message: lines[0].replace(/^\S+\terror\t/, ""), count: 51, variants: 50 });
    expect(formatCollectionIssues(issues)[1]).toMatch(/\(x51, 50 variants differing only in port\)$/);
  });

  it("keeps messages that differ in more than ports apart", () => {
    const issues = parseCollectionIssues([portForward(30000), portForward(30001).replace("istiod-abc", "istiod-def")].join("\n"));
    expect(issues).toHaveLength(2);
  });
});

describe("CollectionIssueCollector distinct-issue cap", () => {
  const unique = (i: number) => `2026-10-20T20:23:09.000000Z\twarn\tunique warning number ${i} for resource r${i}`;

  it(`keeps at most ${MAX_COLLECTION_ISSUES} distinct issues and counts the lines past the cap`, () => {
    const c = new CollectionIssueCollector();
    for (let i = 0; i < MAX_COLLECTION_ISSUES + 1000; i++) c.add(unique(i));
    // A line of an issue already kept still counts there, past the cap.
    c.add(unique(0));
    const issues = c.issues();
    expect(issues).toHaveLength(MAX_COLLECTION_ISSUES);
    expect(issues[0].count).toBe(2);
    expect(c.overflowLines).toBe(1000);
  });

  it("says in tool output that lines past the cap were not grouped", () => {
    const text = formatCollectionIssues([{ level: "warn", message: "x", count: 1 }], 1234).join("\n");
    expect(text).toContain("1234 more line(s) with further distinct messages");
  });

  it("still counts port variants past the first issue without keeping each text", () => {
    const c = new CollectionIssueCollector();
    for (let p = 30000; p < 30020; p++) c.add(`2026-10-20T20:23:09.000000Z\terror\tbind 127.0.0.1:${p}: address already in use`);
    expect(c.issues()[0]).toMatchObject({ count: 20, variants: 20 });
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

describe("getCollectionIssues on an unreadable bug-report.log", () => {
  let tempDir: string;

  afterAll(async () => {
    if (!tempDir) return;
    await chmod(join(tempDir, "bug-report", "bug-report.log"), 0o644).catch(() => {});
    await rm(tempDir, { recursive: true, force: true });
  });

  it.skipIf(process.getuid?.() === 0)("reports the read failure instead of an empty list", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "collection-issues-unreadable-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    // bug-report.log is streamed once, at load.
    await chmod(join(archiveDir, "bug-report.log"), 0o000);
    const store = await BugReportStore.fromDirectory(archiveDir);
    const issues = await getCollectionIssues(store);
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toMatch(/^bug-report\.log could not be read: /);
    expect(store.getCompletenessSignal("bug-report-log").status).toBe("not_evaluated");
  });
});

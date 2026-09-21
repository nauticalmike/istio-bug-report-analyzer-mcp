import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawnSync, execSync } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createLargeArchive, DEFAULT_LARGE_OPTIONS } from "../fixtures/create-large-fixture.js";

const REPO_ROOT = resolve(__dirname, "..", "..");

// The dev-us bug report is ~20GB extracted with 2,249 proxy pods; loading it
// killed the server with "JavaScript heap out of memory" at both the 4GB
// default and a 12GB heap. This suite reproduces that class of failure at CI
// scale: a synthetic ~400MB archive loaded in a child process capped at 192MB.
// Loading must index files without reading their contents into memory, while
// content stays reachable on demand.
const CHILD_HEAP_MB = 192;

describe("BugReportStore large archive load", () => {
  let tempDir: string;
  let archiveDir: string;
  let childScript: string;

  beforeAll(async () => {
    execSync("npx tsc", { cwd: REPO_ROOT, stdio: "pipe" });
    tempDir = await mkdtemp(join(tmpdir(), "store-large-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createLargeArchive(archiveDir);

    // The child imports the built store so the heap cap applies to exactly
    // the code the published server runs.
    childScript = join(tempDir, "load-child.mjs");
    await writeFile(childScript, `
      import { BugReportStore } from ${JSON.stringify(join(REPO_ROOT, "dist", "archive", "store.js"))};
      const store = await BugReportStore.fromDirectory(process.argv[2]);
      const pods = store.getProxyPods("load-test");
      const heapAfterLoadMb = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      const logs = store.getProxyLogs("load-test", "synthetic-pod-0");
      const debug = store.getIstiodDebug("istio-system", "istiod-synthetic-0", "syncz");
      console.log(JSON.stringify({
        podCount: pods.length,
        heapAfterLoadMb,
        hasMarker: logs !== null && logs.includes("SYNTHETIC-MARKER"),
        syncedProxy: Array.isArray(debug) ? debug[0]?.proxy : null,
        version: store.getVersions()?.clientVersion ?? null,
      }));
    `);
  }, 180_000);

  afterAll(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it(`loads a ~400MB archive and serves content within a ${CHILD_HEAP_MB}MB heap`, () => {
    const child = spawnSync(
      process.execPath,
      [`--max-old-space-size=${CHILD_HEAP_MB}`, childScript, archiveDir],
      { encoding: "utf-8", timeout: 120_000 }
    );

    expect(
      child.status,
      `child exited ${child.status} (signal ${child.signal})\nstderr:\n${child.stderr?.slice(-2000)}`
    ).toBe(0);

    const summary = JSON.parse(child.stdout.trim().split("\n").pop()!);
    expect(summary.podCount).toBe(DEFAULT_LARGE_OPTIONS.podCount);
    expect(summary.hasMarker).toBe(true);
    expect(summary.syncedProxy).toBe("synthetic-pod-0.load-test");
    expect(summary.version).toBe("1.30.0");
    // Loading must not retain file contents: the index of a 400MB archive is
    // a few MB. Half the heap cap leaves generous slack without letting an
    // eager loader sneak by.
    expect(summary.heapAfterLoadMb).toBeLessThan(CHILD_HEAP_MB / 2);
  }, 180_000);
});

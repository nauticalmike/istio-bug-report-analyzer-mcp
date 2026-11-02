import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync, execSync } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { noisyProxyLogBlock, writeRepeatedLog } from "../fixtures/create-log-fixture.js";

const REPO_ROOT = resolve(__dirname, "..", "..");
const MB = 1024 * 1024;
const RUN_LARGE = process.env.RUN_LARGE === "1";

const RARE_ERROR = "2026-01-01T01:00:00.000000Z\terror\tca\tSYNTHETIC-RARE-ERROR certificate signing failed for workload demo/app\n";
const COLLECTION_FAILURE = "Error: SYNTHETIC-COLLECTION-FAILURE failed to fetch debug endpoint\n";
const INFO_BLOCK = Array.from({ length: 100 }, (_, i) => `2026-01-01T00:00:${String(i % 60).padStart(2, "0")}.000000Z\tinfo\tcollecting proxy ${i}`).join("\n") + "\n";

interface ChildResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
  out: { text?: string; issues?: { message: string }[]; maxRssMb: number };
}

/**
 * Builds the server into its own outDir (other suites build into dist/ in parallel)
 * and runs each tool in a child process, so heap caps and peak RSS apply to the
 * code the published server runs and to nothing else.
 */
async function buildChild(tempDir: string): Promise<string> {
  const outDir = join(tempDir, "dist");
  execSync(`npx tsc --outDir ${JSON.stringify(outDir)}`, { cwd: REPO_ROOT, stdio: "pipe" });
  // The build imports its dependencies by package name.
  await symlink(join(REPO_ROOT, "node_modules"), join(tempDir, "node_modules"));
  const script = join(tempDir, "child.mjs");
  await writeFile(script, `
    import { BugReportStore } from ${JSON.stringify(join(outDir, "archive", "store.js"))};
    import { findErrors } from ${JSON.stringify(join(outDir, "tools", "find-errors.js"))};
    import { getLogs } from ${JSON.stringify(join(outDir, "tools", "logs.js"))};
    import { getCollectionIssues } from ${JSON.stringify(join(outDir, "tools", "collection-issues.js"))};
    const [archive, op, arg] = process.argv.slice(2);
    const store = await BugReportStore.fromDirectory(archive);
    let out;
    if (op === "errors") out = { text: (await findErrors(store, arg ? JSON.parse(arg) : {})).content[0].text };
    else if (op === "issues") out = { issues: await getCollectionIssues(store) };
    else if (op === "logs") out = { text: (await getLogs(store, JSON.parse(arg))).content[0].text };
    out.maxRssMb = Math.round(process.resourceUsage().maxRSS / 1024);
    console.log(JSON.stringify(out));
  `);
  return script;
}

function runChild(script: string, args: string[], heapMb?: number): ChildResult {
  const flags = heapMb ? [`--max-old-space-size=${heapMb}`] : [];
  const child = spawnSync(process.execPath, [...flags, script, ...args], { encoding: "utf-8", timeout: 600_000, maxBuffer: 64 * MB });
  const last = child.stdout?.trim().split("\n").pop();
  return { status: child.status, signal: child.signal, stderr: child.stderr ?? "", out: child.status === 0 && last ? JSON.parse(last) : { maxRssMb: 0 } };
}

function expectOk(r: ChildResult) {
  expect(r.status, `child exited ${r.status} (signal ${r.signal})\nstderr:\n${r.stderr.slice(-2000)}`).toBe(0);
}

// Logs are scanned line by line, so a log many times the heap cap is still read whole.
describe("log tools on logs larger than the heap", () => {
  const HEAP_MB = 64;
  let tempDir: string;
  let archiveDir: string;
  let script: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "large-logs-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    const podDir = join(archiveDir, "proxies", "big", "big-pod-0");
    await mkdir(podDir, { recursive: true });
    await writeRepeatedLog(join(podDir, "istio-proxy.log"), 120 * MB, noisyProxyLogBlock(), RARE_ERROR);
    const istiodDir = join(archiveDir, "istio", "istio-system", "istiod-big-0");
    await mkdir(istiodDir, { recursive: true });
    await writeRepeatedLog(join(istiodDir, "discovery.log"), 60 * MB, INFO_BLOCK, "2026-01-01T01:00:00.000000Z\terror\tads\tSYNTHETIC-ISTIOD-ERROR push failed\n");
    await writeRepeatedLog(join(archiveDir, "bug-report.log"), 120 * MB, INFO_BLOCK, COLLECTION_FAILURE);
    script = await buildChild(tempDir);
  }, 180_000);

  afterAll(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it(`find_errors groups a 120MB proxy log within a ${HEAP_MB}MB heap`, () => {
    const r = runChild(script, [archiveDir, "errors"], HEAP_MB);
    expectOk(r);
    expect(r.out.text).toMatch(/^=== \d+ unique error patterns found \(\d+ total lines\) ===/);
    expect(r.out.text).toContain("[x");
    const rare = runChild(script, [archiveDir, "errors", JSON.stringify({ keyword: "synthetic-" })], HEAP_MB);
    expectOk(rare);
    expect(rare.out.text).toContain("SYNTHETIC-RARE-ERROR");
    expect(rare.out.text).toContain("SYNTHETIC-ISTIOD-ERROR");
  }, 180_000);

  it(`collection issues come from a 120MB bug-report.log within a ${HEAP_MB}MB heap`, () => {
    const r = runChild(script, [archiveDir, "issues"], HEAP_MB);
    expectOk(r);
    expect(r.out.issues?.map((i) => i.message)).toContain("SYNTHETIC-COLLECTION-FAILURE failed to fetch debug endpoint");
  }, 180_000);

  it(`get_logs finds a line in a 120MB proxy log within a ${HEAP_MB}MB heap`, () => {
    const r = runChild(script, [archiveDir, "logs", JSON.stringify({ component: "proxy", pod: "big-pod-0", keyword: "SYNTHETIC-RARE" })], HEAP_MB);
    expectOk(r);
    expect(r.out.text).toContain("=== Logs (1 of 1 lines) ===");
    expect(r.out.text).toContain("SYNTHETIC-RARE-ERROR");
  }, 180_000);

  it(`get_logs returns the most recent lines of a 60MB discovery log within a ${HEAP_MB}MB heap`, () => {
    const r = runChild(script, [archiveDir, "logs", JSON.stringify({ component: "istiod", limit: 5 })], HEAP_MB);
    expectOk(r);
    expect(r.out.text).toContain("SYNTHETIC-ISTIOD-ERROR");
    expect(r.out.text).toMatch(/=== Logs \(5 of \d+ lines\) ===/);
  }, 180_000);
});

// Files past V8's ~512 MiB string limit, and a proxy log set over 1.5 GB. Several GB of
// disk and a few minutes, so opt-in: RUN_LARGE=1 npx vitest run tests/integration/large-logs.test.ts
describe.skipIf(!RUN_LARGE)("log tools on files past the V8 string limit (RUN_LARGE=1)", () => {
  const POD_LOG_MB = 520;
  const PODS = 3;
  let tempDir: string;
  let archiveDir: string;
  let script: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "large-logs-xl-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    for (let i = 0; i < PODS; i++) {
      const podDir = join(archiveDir, "proxies", "big", `big-pod-${i}`);
      await mkdir(podDir, { recursive: true });
      await writeRepeatedLog(join(podDir, "istio-proxy.log"), POD_LOG_MB * MB, noisyProxyLogBlock(), i === PODS - 1 ? RARE_ERROR : "");
    }
    await writeRepeatedLog(join(archiveDir, "bug-report.log"), 600 * MB, INFO_BLOCK, COLLECTION_FAILURE);
    script = await buildChild(tempDir);
  }, 900_000);

  afterAll(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it(`find_errors on ${PODS * POD_LOG_MB}MB of proxy logs stays under 1GB RSS on the default heap`, () => {
    const r = runChild(script, [archiveDir, "errors", JSON.stringify({ component: "proxy" })]);
    expectOk(r);
    console.log(`find_errors over ${PODS * POD_LOG_MB}MB of proxy logs: peak RSS ${r.out.maxRssMb}MB`);
    expect(r.out.maxRssMb).toBeLessThan(1024);
    expect(r.out.text).toMatch(/^=== \d+ unique error patterns found \(\d+ total lines\) ===/);
    // The one real error outranks millions of noise lines.
    const blocks = r.out.text!.split("\n\n");
    expect(blocks[1]).toContain("SYNTHETIC-RARE-ERROR");
  }, 900_000);

  it("a 600MB bug-report.log yields its collection issues", () => {
    const r = runChild(script, [archiveDir, "issues"]);
    expectOk(r);
    expect(r.out.issues?.map((i) => i.message)).toContain("SYNTHETIC-COLLECTION-FAILURE failed to fetch debug endpoint");
  }, 900_000);

  it(`get_logs reads a ${POD_LOG_MB}MB proxy log`, () => {
    const r = runChild(script, [archiveDir, "logs", JSON.stringify({ component: "proxy", pod: `big-pod-${PODS - 1}`, keyword: "SYNTHETIC-RARE" })]);
    expectOk(r);
    expect(r.out.text).toContain("SYNTHETIC-RARE-ERROR");
  }, 900_000);
});

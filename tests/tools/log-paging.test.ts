import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getLogs } from "../../src/tools/logs.js";
import { findErrors } from "../../src/tools/find-errors.js";
import { getProxyConfig } from "../../src/tools/proxy-config.js";
import { MAX_LINE_CHARS, OUTPUT_BUDGET_CHARS } from "../../src/tools/output-budget.js";

const textOf = (r: { content: { type: string; text: string }[] }) => r.content[0].text;
const LINES = 3000;
const PATTERNS = 120;

describe("log and error output budget", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "log-paging-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);

    // ~120 chars per line: 3,000 lines are ~360k chars, well past the budget.
    const noisy = join(archiveDir, "proxies", "synthetic", "noisy-pod-0");
    await mkdir(noisy, { recursive: true });
    const lines = Array.from({ length: LINES }, (_, i) => `2026-01-01T00:00:00Z\tinfo\tline-${i} ${"p".repeat(80)}`);
    lines.push(`2026-01-01T00:00:01Z\tinfo\thuge ${"h".repeat(10_000)}`);
    await writeFile(join(noisy, "istio-proxy.log"), lines.join("\n") + "\n");
    await writeFile(join(noisy, "config_dump"), JSON.stringify({ configs: Array.from({ length: 4000 }, (_, i) => ({ name: `listener-${i}`, filler: "f".repeat(40) })) }));

    // Distinct error patterns ("kind-N" survives normalization), the first with a huge sample line.
    const errors = join(archiveDir, "proxies", "synthetic", "errors-pod-0");
    await mkdir(errors, { recursive: true });
    const errLines = Array.from({ length: PATTERNS }, (_, i) => `2026-01-01T00:00:00Z\terror\tfailure kind-${"q".repeat(i + 1)}`);
    errLines.unshift(...Array.from({ length: 3 }, () => `2026-01-01T00:00:00Z\terror\tgiant ${"g".repeat(5000)}`));
    await writeFile(join(errors, "istio-proxy.log"), errLines.join("\n") + "\n");

    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("get_logs", () => {
    it("keeps the most recent lines that fit the budget and clamps huge lines", async () => {
      const text = textOf(await getLogs(store, { component: "proxy", pod: "noisy-pod-0", limit: LINES + 1 }));
      expect(text.length).toBeLessThanOrEqual(OUTPUT_BUDGET_CHARS);
      expect(text).toContain("huge ");
      expect(text).not.toContain("h".repeat(MAX_LINE_CHARS + 1));
      expect(text).toContain(`line-${LINES - 1} `);
      expect(text).not.toContain("line-0 ");
      expect(text).toMatch(new RegExp(`Showing lines \\d+-${LINES + 1} of ${LINES + 1}\\.`));
      expect(text).toContain("output budget");
      expect(text).toContain("pass offset=0 to page from the oldest");
    });

    it("pages forward from an offset", async () => {
      const text = textOf(await getLogs(store, { component: "proxy", pod: "noisy-pod-0", offset: 10, limit: 5 }));
      expect(text).toContain("line-10 ");
      expect(text).toContain("line-14 ");
      expect(text).not.toContain("line-15 ");
      expect(text).toContain(`Showing lines 11-15 of ${LINES + 1}. Pass offset=15 for more, or use keyword/pod to narrow.`);
    });

    it("stops a forward page at the budget", async () => {
      const text = textOf(await getLogs(store, { component: "proxy", pod: "noisy-pod-0", offset: 0, limit: LINES }));
      expect(text.length).toBeLessThanOrEqual(OUTPUT_BUDGET_CHARS);
      const next = Number(/Pass offset=(\d+)/.exec(text)![1]);
      expect(next).toBeGreaterThan(100);
      expect(next).toBeLessThan(LINES);
      expect(text).toContain(`line-${next - 1} `);
      expect(text).not.toContain(`line-${next} `);
    });

    it("reports an offset past the end", async () => {
      const text = textOf(await getLogs(store, { component: "proxy", pod: "noisy-pod-0", offset: 1_000_000 }));
      expect(text).toContain("No log lines at offset");
    });
  });

  describe("find_errors", () => {
    it("pages patterns with a footer and clamps sample lines", async () => {
      const text = textOf(await findErrors(store, { component: "proxy" }));
      const total = Number(/=== (\d+) unique error patterns/.exec(text)![1]);
      expect(total).toBeGreaterThan(PATTERNS);
      expect(text).toContain(`Showing patterns 1-50 of ${total}. Pass offset=50 for more, or filter by component/keyword.`);
      expect(text).toContain("giant ");
      expect(text).not.toContain("g".repeat(501));
      expect(text).toContain("more chars]");
    });

    it("serves a later page with offset/limit", async () => {
      const first = textOf(await findErrors(store, { component: "proxy", limit: 1 }));
      expect(first).toContain("[x3]");
      const second = textOf(await findErrors(store, { component: "proxy", offset: 1, limit: 2 }));
      expect(second).not.toContain("[x3]");
      expect(second).toMatch(/Showing patterns 2-3 of \d+\. Pass offset=3 for more/);
    });

    it("reports an offset past the end", async () => {
      const text = textOf(await findErrors(store, { component: "proxy", offset: 10_000 }));
      expect(text).toContain("No patterns at offset 10000.");
    });
  });

  describe("get_proxy_config", () => {
    it("pages a large config dump by character offset", async () => {
      const first = textOf(getProxyConfig(store, { namespace: "synthetic", pod: "noisy-pod-0" }));
      expect(first.length).toBeLessThanOrEqual(OUTPUT_BUDGET_CHARS);
      const next = Number(/Showing chars 1-\d+ of \d+\. Pass offset=(\d+) for more\./.exec(first)![1]);
      const second = textOf(getProxyConfig(store, { namespace: "synthetic", pod: "noisy-pod-0", offset: next }));
      expect(second).toMatch(new RegExp(`Showing chars ${next + 1}-\\d+ of \\d+\\.`));
      // Pages are line-aligned, so the second starts on a fresh line of the pretty-printed JSON.
      expect(second.startsWith(" ")).toBe(true);
    });
  });
});

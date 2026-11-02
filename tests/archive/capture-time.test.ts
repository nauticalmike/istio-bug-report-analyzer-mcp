import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function archive(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "capture-time-"));
  dirs.push(dir);
  const archiveDir = join(dir, "bug-report");
  await createMinimalArchive(archiveDir);
  return archiveDir;
}

describe("BugReportStore.getCaptureTime", () => {
  it("is the newest log timestamp across proxy, istiod and bug-report logs", async () => {
    const dir = await archive();
    await writeFile(join(dir, "istio", "istio-system", "istiod-abc", "discovery.log"), "2026-05-02T11:15:00.000Z\tinfo\tads\tpush\n");
    await writeFile(join(dir, "bug-report.log"), "2026-05-02T11:20:30.123456Z\tinfo\tDone.\n");
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureTime()?.toISOString()).toBe("2026-05-02T11:20:30.123Z");
  });

  it("reads the end of large logs, where the newest lines are", async () => {
    const dir = await archive();
    const old = "2025-01-01T00:00:00.000Z\tinfo\tstartup\n";
    await writeFile(join(dir, "proxies", "default", "test-pod-abc123", "istio-proxy.log"), old + "x".repeat(2_000_000) + "\n2026-06-30T23:59:59.000Z\tinfo\tlast line\n");
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureTime()?.toISOString()).toBe("2026-06-30T23:59:59.000Z");
  });

  it("ignores timestamps in the future (clock skew, cert expiries)", async () => {
    const dir = await archive();
    await writeFile(join(dir, "bug-report.log"), "2099-01-01T00:00:00Z\tinfo\tbogus\n");
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureTime()?.toISOString()).toBe("2026-03-18T10:00:02.000Z");
  });

  it("is null when no log carries a timestamp", async () => {
    const dir = await archive();
    await writeFile(join(dir, "proxies", "default", "test-pod-abc123", "istio-proxy.log"), "plain\n");
    await writeFile(join(dir, "istio", "istio-system", "istiod-abc", "discovery.log"), "plain\n");
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureTime()).toBeNull();
  });
});

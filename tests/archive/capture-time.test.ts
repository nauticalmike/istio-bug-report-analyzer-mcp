import { describe, it, expect, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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

  it("uses line timestamps (plain, bracketed access log, JSON time field), not dates inside messages", async () => {
    const dir = await archive();
    await writeFile(join(dir, "bug-report.log"), [
      '{"level":"info","time":"2026-03-18T11:00:00.000000Z","msg":"done"}',
      "[2026-03-18T10:30:00.000Z] \"GET / HTTP/1.1\" 200",
      "2026-03-18T10:15:00.000Z\tinfo\tcertificate valid until 2026-09-01T00:00:00Z",
    ].join("\n"));
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureTime()?.toISOString()).toBe("2026-03-18T11:00:00.000Z");
  });

  /** An archive whose collected logs carry no timestamp. */
  async function withoutLogTimes(): Promise<string> {
    const dir = await archive();
    await writeFile(join(dir, "proxies", "default", "test-pod-abc123", "istio-proxy.log"), "plain\n");
    await writeFile(join(dir, "istio", "istio-system", "istiod-abc", "discovery.log"), "plain\n");
    return dir;
  }

  it("is null when nothing in the archive carries a timestamp", async () => {
    const store = await BugReportStore.fromDirectory(await withoutLogTimes());
    expect(store.getCaptureTime()).toBeNull();
    expect(store.getCaptureInfo()).toBeNull();
  });

  it("says a log timestamp was the source", async () => {
    const store = await BugReportStore.fromDirectory(await archive());
    expect(store.getCaptureInfo()?.source).toBe("log");
  });

  it("reads *.log files outside the usual directories", async () => {
    const dir = await withoutLogTimes();
    await mkdir(join(dir, "extra", "node-1"), { recursive: true });
    await writeFile(join(dir, "extra", "node-1", "kubelet.log"), "2026-04-01T12:00:00Z\tinfo\tsynced\n");
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureInfo()).toEqual({ time: new Date("2026-04-01T12:00:00Z"), source: "log" });
  });

  it("falls back to the log lines istioctl writes in front of istiod debug output", async () => {
    const dir = await withoutLogTimes();
    await writeFile(join(dir, "istio", "istio-system", "istiod-abc", "debug", "syncz"), "2026-04-02T08:00:00.000000Z\tinfo\tfetching\n[]");
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureInfo()).toEqual({ time: new Date("2026-04-02T08:00:00Z"), source: "debug" });
  });

  it("falls back to the newest event in cluster/events", async () => {
    const dir = await withoutLogTimes();
    await writeFile(
      join(dir, "cluster", "events"),
      [
        "apiVersion: v1\nkind: Event\nmetadata:\n  name: a\n  creationTimestamp: \"2026-04-03T09:00:00Z\"\nlastTimestamp: \"2026-04-03T10:00:00Z\"",
        "apiVersion: v1\nkind: Event\nmetadata:\n  name: b\neventTime: \"2026-04-03T11:30:00.123456Z\"\nlastTimestamp: null",
      ].join("\n---\n"),
    );
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureInfo()).toEqual({ time: new Date("2026-04-03T11:30:00.123Z"), source: "events" });
  });

  it("falls back to the newest pod creation or start time in the pod dump", async () => {
    const dir = await withoutLogTimes();
    await writeFile(
      join(dir, "cluster", "pods"),
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\n  creationTimestamp: \"2026-04-04T07:00:00Z\"\nstatus:\n  startTime: \"2026-04-04T07:05:00Z\"\n",
    );
    const store = await BugReportStore.fromDirectory(dir);
    expect(store.getCaptureInfo()).toEqual({ time: new Date("2026-04-04T07:05:00Z"), source: "pods" });
  });
});

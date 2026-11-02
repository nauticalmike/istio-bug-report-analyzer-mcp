import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import {
  EXTRACT_DIR_PREFIX,
  ExtractionTracker,
  checkFreeSpace,
  estimateExpandedSize,
  installExitCleanup,
} from "../../src/archive/extraction.js";

describe("estimateExpandedSize", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "estimate-test-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("reads the exact expanded size of a small gzip from its trailer", async () => {
    const file = join(dir, "a.tar.gz");
    await writeFile(file, gzipSync(Buffer.alloc(1_000_000, "a")));
    const est = await estimateExpandedSize(file);
    expect(est.exact).toBe(true);
    expect(est.expandedBytes).toBe(1_000_000);
    expect(est.upperBytes).toBe(1_000_000);
  });

  it("marks the estimate inexact when the 32-bit trailer could have wrapped", async () => {
    const file = join(dir, "big.tar.gz");
    await writeFile(file, gzipSync(Buffer.alloc(1000, "a")));
    // Pretend the compressed file is 1 GB: its true expanded size may exceed 4 GiB.
    const est = await estimateExpandedSize(file, { compressedBytes: 1e9 });
    expect(est.exact).toBe(false);
    expect(est.expandedBytes).toBeGreaterThanOrEqual(1e9);
    expect(est.upperBytes).toBeGreaterThanOrEqual(26e9);
  });
});

describe("checkFreeSpace", () => {
  const exact = { compressedBytes: 1e6, expandedBytes: 2e9, upperBytes: 2e9, exact: true };

  it("refuses with a clear message when the expanded size does not fit", () => {
    const res = checkFreeSpace(exact, 1e9, "/tmp", "x.tar.gz");
    expect(res.ok).toBe(false);
    expect(res.message).toMatch(/Not enough free space in \/tmp/);
    expect(res.message).toMatch(/extract_dir/);
  });

  it("passes when there is room", () => {
    expect(checkFreeSpace(exact, 10e9, "/tmp", "x.tar.gz")).toEqual({ ok: true });
  });

  it("warns but proceeds when only the inexact upper bound does not fit", () => {
    const inexact = { compressedBytes: 1e9, expandedBytes: 2e9, upperBytes: 30e9, exact: false };
    const res = checkFreeSpace(inexact, 10e9, "/tmp", "x.tar.gz");
    expect(res.ok).toBe(true);
    expect(res.message).toMatch(/may need up to/);
  });
});

describe("ExtractionTracker", () => {
  let parent: string;
  beforeEach(async () => { parent = await mkdtemp(join(tmpdir(), "tracker-test-")); });
  afterEach(async () => { await rm(parent, { recursive: true, force: true }); });

  it("creates prefixed dirs and removes only the ones it created", async () => {
    const tracker = new ExtractionTracker();
    const created = await tracker.create(parent);
    expect(created.startsWith(join(parent, EXTRACT_DIR_PREFIX))).toBe(true);

    const userDir = join(parent, "user-extracted");
    await mkdir(userDir);
    expect(await tracker.remove(userDir)).toBe(false);
    expect(existsSync(userDir)).toBe(true);

    expect(await tracker.remove(created)).toBe(true);
    expect(existsSync(created)).toBe(false);
    expect(existsSync(parent)).toBe(true);
  });

  it("releases the dir attached to an owner, and nothing for an owner without one", async () => {
    const tracker = new ExtractionTracker();
    const owner = {};
    const dir = await tracker.create(parent);
    tracker.attach(owner, dir);
    await tracker.release({});
    expect(existsSync(dir)).toBe(true);
    await tracker.release(owner);
    expect(existsSync(dir)).toBe(false);
  });

  it("removeAllSync deletes every dir it still owns", async () => {
    const tracker = new ExtractionTracker();
    const a = await tracker.create(parent);
    const b = await tracker.create(parent);
    tracker.removeAllSync();
    expect(existsSync(a)).toBe(false);
    expect(existsSync(b)).toBe(false);
    expect(tracker.size).toBe(0);
  });
});

describe("installExitCleanup", () => {
  let parent: string;
  beforeEach(async () => { parent = await mkdtemp(join(tmpdir(), "exit-cleanup-test-")); });
  afterEach(async () => { await rm(parent, { recursive: true, force: true }); });

  function fakeProcess() {
    const emitter = new EventEmitter() as EventEmitter & { exit: (code?: number) => void; exitCode?: number };
    emitter.exit = (code?: number) => { emitter.exitCode = code; };
    return emitter;
  }

  for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
    it(`removes extracted dirs and exits ${code} on ${signal}`, async () => {
      const tracker = new ExtractionTracker();
      const dir = await tracker.create(parent);
      const proc = fakeProcess();
      installExitCleanup(tracker, proc);
      proc.emit(signal);
      expect(existsSync(dir)).toBe(false);
      expect(proc.exitCode).toBe(code);
    });
  }

  it("removes extracted dirs on a normal exit", async () => {
    const tracker = new ExtractionTracker();
    const dir = await tracker.create(parent);
    const proc = fakeProcess();
    installExitCleanup(tracker, proc);
    proc.emit("exit", 0);
    expect(existsSync(dir)).toBe(false);
  });

  // A real process: the module uses only node: imports, so Node runs the .ts source directly.
  it("cleans up in a real process killed with SIGTERM", async () => {
    const moduleUrl = pathToFileURL(resolve("src/archive/extraction.ts")).href;
    const script = [
      `const { ExtractionTracker, installExitCleanup } = await import(${JSON.stringify(moduleUrl)});`,
      "const tracker = new ExtractionTracker();",
      `const dir = await tracker.create(${JSON.stringify(parent)});`,
      "installExitCleanup(tracker);",
      "console.log(dir);",
      "setInterval(() => {}, 1000);",
    ].join("\n");
    const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => { stderr += d; });
    const dir = await new Promise<string>((res, rej) => {
      child.stdout.once("data", (d) => res(String(d).trim()));
      child.once("exit", () => rej(new Error(`child exited early: ${stderr}`)));
    });
    expect(existsSync(dir)).toBe(true);
    const exited = new Promise<number | null>((res) => child.once("exit", (code) => res(code)));
    child.kill("SIGTERM");
    expect(await exited).toBe(143);
    expect(existsSync(dir)).toBe(false);
  });
});

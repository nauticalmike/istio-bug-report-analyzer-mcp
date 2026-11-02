import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanFileLines } from "../../src/archive/line-scanner.js";

async function collect(path: string, opts?: Parameters<typeof scanFileLines>[2]) {
  const lines: { line: string; bytes: number }[] = [];
  const stats = await scanFileLines(path, (line, bytes) => { lines.push({ line, bytes }); }, opts);
  return { lines, stats };
}

describe("scanFileLines", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "line-scanner-test-"));
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("yields every line, strips CR, and keeps a last line without a newline", async () => {
    const file = join(dir, "basic.log");
    await writeFile(file, "one\r\ntwo\n\nthree");
    const { lines, stats } = await collect(file);
    expect(lines.map((l) => l.line)).toEqual(["one", "two", "", "three"]);
    expect(stats).toEqual({ bytes: 15, lines: 4, longLines: 0, stopped: false });
  });

  it("joins lines and multi-byte characters split across chunk boundaries", async () => {
    const file = join(dir, "chunks.log");
    const text = Array.from({ length: 200 }, (_, i) => `línea-${i} ✓ ${"x".repeat(i % 13)}`).join("\n") + "\n";
    await writeFile(file, text);
    const { lines } = await collect(file, { chunkBytes: 7 });
    expect(lines.map((l) => l.line)).toEqual(text.split("\n").slice(0, -1));
  });

  it("cuts lines over maxLineBytes but reports their full byte length", async () => {
    const file = join(dir, "long.log");
    await writeFile(file, `short\n${"a".repeat(5000)}\nafter\n`);
    const { lines, stats } = await collect(file, { maxLineBytes: 100, chunkBytes: 64 });
    expect(lines.map((l) => l.line.length)).toEqual([5, 100, 5]);
    expect(lines[1].bytes).toBe(5000);
    expect(lines[2].line).toBe("after");
    expect(stats.longLines).toBe(1);
  });

  it("never splits a multi-byte character when cutting a long line", async () => {
    const file = join(dir, "long-utf8.log");
    await writeFile(file, `${"é".repeat(100)}\n`);
    const { lines } = await collect(file, { maxLineBytes: 51 });
    expect(lines[0].line).toBe("é".repeat(25));
  });

  it("stops when the handler returns false", async () => {
    const file = join(dir, "stop.log");
    await writeFile(file, "a\nb\nc\n");
    const seen: string[] = [];
    const stats = await scanFileLines(file, (line) => { seen.push(line); return line !== "b"; });
    expect(seen).toEqual(["a", "b"]);
    expect(stats.stopped).toBe(true);
  });

  it("rejects when the file cannot be read", async () => {
    await expect(scanFileLines(join(dir, "missing.log"), () => {})).rejects.toThrow();
  });
});

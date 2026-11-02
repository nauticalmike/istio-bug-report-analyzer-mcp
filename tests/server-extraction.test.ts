import { describe, it, expect, afterAll } from "vitest";
import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as tar from "tar";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";
import { createMinimalArchive } from "./fixtures/create-fixture.js";
import { EXTRACT_DIR_PREFIX } from "../src/archive/extraction.js";

describe("load_bug_report over MCP", () => {
  let tempDir: string;

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("extracts into extract_dir and deletes the previous extraction when another archive is loaded", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "server-extraction-test-"));
    const extractDir = join(tempDir, "extract");
    await mkdir(extractDir);
    const tarballs: string[] = [];
    for (const name of ["a", "b"]) {
      const src = join(tempDir, `${name}-src`);
      await createMinimalArchive(join(src, "bug-report"));
      const file = join(tempDir, `${name}.tar.gz`);
      await tar.create({ gzip: true, file, cwd: src }, ["bug-report"]);
      tarballs.push(file);
    }

    const { server } = createServer({ soloMode: false });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test", version: "0" });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const extracted = async () => (await readdir(extractDir)).filter((n) => n.startsWith(EXTRACT_DIR_PREFIX));

    const first = await client.callTool({ name: "load_bug_report", arguments: { path: tarballs[0], extract_dir: extractDir } });
    expect(first.isError).toBeFalsy();
    const [firstDir] = await extracted();
    expect(firstDir).toBeDefined();

    await client.callTool({ name: "load_bug_report", arguments: { path: tarballs[1], extract_dir: extractDir } });
    const now = await extracted();
    expect(now).toHaveLength(1);
    expect(now[0]).not.toBe(firstDir);

    await client.close();
  });
});

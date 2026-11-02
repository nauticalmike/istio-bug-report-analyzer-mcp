import { describe, it, expect, afterEach } from "vitest";
import { chmod, mkdtemp, rm, truncate } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { MAX_STRING_BYTES } from "../../src/archive/namespace-scan.js";
import { getIstiodDebug } from "../../src/tools/istiod-debug.js";
import { getProxyConfig } from "../../src/tools/proxy-config.js";

const textOf = (r: { content: { type: string; text?: string }[] }) => (r.content[0] as { text: string }).text;
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function archive(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "oversized-"));
  dirs.push(dir);
  const a = join(dir, "bug-report");
  await createMinimalArchive(a);
  return a;
}

// Sparse files: the size is all the tools look at before reading.
describe("files over V8's string limit", () => {
  it("get_istiod_debug says the endpoint file is too large and how to read it", async () => {
    const a = await archive();
    await truncate(join(a, "istio", "istio-system", "istiod-abc", "debug", "configz"), MAX_STRING_BYTES + 1);
    const result = await getIstiodDebug(await BugReportStore.fromDirectory(a), { endpoint: "configz" });
    const text = textOf(result);
    expect(result.isError).toBe(true);
    expect(text).not.toBe("null");
    expect(text).toMatch(/istio\/istio-system\/istiod-abc\/debug\/configz is [\d,]+ MB, too large to parse; read it with get_raw_file offset\/length/);
  });

  it("get_proxy_config says the config dump is too large instead of not available", async () => {
    const a = await archive();
    await truncate(join(a, "proxies", "default", "test-pod-abc123", "config_dump?include_eds"), MAX_STRING_BYTES + 1);
    const result = getProxyConfig(await BugReportStore.fromDirectory(a), { namespace: "default", pod: "test-pod-abc123" });
    const text = textOf(result);
    expect(result.isError).toBe(true);
    expect(text).not.toMatch(/not available/);
    expect(text).toMatch(/proxies\/default\/test-pod-abc123\/config_dump\?include_eds is [\d,]+ MB, too large to parse; read it with get_raw_file offset\/length/);
  });

  it("get_proxy_config reports an oversized section the same way", async () => {
    const a = await archive();
    await truncate(join(a, "proxies", "default", "test-pod-abc123", "clusters"), MAX_STRING_BYTES + 1);
    const text = textOf(getProxyConfig(await BugReportStore.fromDirectory(a), { namespace: "default", pod: "test-pod-abc123", section: "clusters" }));
    expect(text).toMatch(/clusters is [\d,]+ MB, too large to parse/);
  });

  it.skipIf(process.getuid?.() === 0)("get_istiod_debug says an unreadable endpoint could not be read instead of printing null", async () => {
    const a = await archive();
    await chmod(join(a, "istio", "istio-system", "istiod-abc", "debug", "configz"), 0o000);
    const result = await getIstiodDebug(await BugReportStore.fromDirectory(a), { endpoint: "configz" });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/debug\/configz could not be read/);
  });
});

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getProxyConfig } from "../../src/tools/proxy-config.js";

describe("getProxyConfig", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "proxy-config-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    // ztunnel (Rust) writes only a plain config_dump and its log, no Envoy admin sections.
    const ztunnelDir = join(archiveDir, "proxies", "istio-system", "ztunnel-abcde");
    await mkdir(ztunnelDir, { recursive: true });
    await writeFile(join(ztunnelDir, "config_dump"), JSON.stringify({ certificates: [], services: [] }));
    await writeFile(join(ztunnelDir, "istio-proxy.log"), "2026-10-20T20:22:53Z\tinfo\taccess\tconnection complete\n");
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns config_dump for a proxy pod", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "test-pod-abc123" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("BootstrapConfigDump");
  });

  it("returns specific section", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "test-pod-abc123", section: "listeners" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("LISTENER");
  });

  it("returns error for unknown pod", () => {
    const result = getProxyConfig(store, { namespace: "default", pod: "nonexistent" });
    expect(result.isError).toBe(true);
    expect((result.content[0] as { type: "text"; text: string }).text).toContain("Proxy not found");
  });

  it("returns the ztunnel config dump", () => {
    const result = getProxyConfig(store, { namespace: "istio-system", pod: "ztunnel-abcde" });
    expect(result.isError).toBeUndefined();
    expect((result.content[0] as { type: "text"; text: string }).text).toContain("certificates");
  });

  it("says which sections exist when a known pod lacks the requested one", () => {
    const result = getProxyConfig(store, { namespace: "istio-system", pod: "ztunnel-abcde", section: "listeners" });
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(result.isError).toBe(true);
    expect(text).not.toContain("Proxy not found");
    expect(text).toContain('Section "listeners" is not available');
    expect(text).toContain("ztunnel");
    expect(text).toContain("config_dump");
  });
});

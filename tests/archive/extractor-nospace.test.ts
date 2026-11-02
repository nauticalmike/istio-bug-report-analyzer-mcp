import { describe, it, expect, vi } from "vitest";

// node-tar reports a failed entry write as a warning, not an error, unless strict; a full
// disk would otherwise leave a silently truncated extraction.
vi.mock("tar", () => ({
  extract: async (opts: { onwarn?: (code: string, message: string, data: Record<string, unknown>) => void }) => {
    opts.onwarn?.("TAR_ENTRY_ERROR", "ENOSPC: no space left on device, write", { code: "ENOSPC", file: "proxies/x/config_dump" });
  },
}));

const { extractArchive } = await import("../../src/archive/extractor.js");

describe("extractArchive on a full disk", () => {
  it("rejects with ENOSPC instead of returning a truncated extraction", async () => {
    await expect(extractArchive("/does/not/matter.tar.gz", "/tmp")).rejects.toMatchObject({ code: "ENOSPC" });
  });
});

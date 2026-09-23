import { describe, it, expect, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

const { execFileCalls } = vi.hoisted(() => ({
  execFileCalls: [] as { file: string; args: string[] }[],
}));

// Fake istioctl: record the invocation and drop an archive where the real
// binary would — in --output-dir. (--dir is only temporary storage that
// istioctl deletes when it finishes.)
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFile: (
      file: string,
      args: string[],
      _opts: unknown,
      cb: (err: Error | null, out?: { stdout: string; stderr: string }) => void,
    ) => {
      execFileCalls.push({ file, args });
      const outputDir = args.find((a) => a.startsWith("--output-dir="))?.slice("--output-dir=".length);
      if (!outputDir) {
        cb(new Error("fake istioctl: --output-dir not passed, archive would land in cwd"));
        return;
      }
      writeFile(join(outputDir, "bug-report.tar.gz"), "").then(
        () => cb(null, { stdout: "", stderr: "" }),
        (err) => cb(err),
      );
    },
  };
});

import { runBugReport } from "../../src/cli/bootstrap.js";

describe("runBugReport", () => {
  it("asks istioctl to write the archive into --output-dir and returns the archive path", async () => {
    const outputDir = join(await mkdtemp(join(tmpdir(), "run-bug-report-test-")), "out");
    try {
      const archive = await runBugReport("/fake/bin/istioctl", {
        context: "kind-test",
        namespaces: ["apps", "istio-system"],
        exclude: ["kube-system"],
        outputDir,
      });

      expect(archive).toBe(join(outputDir, "bug-report.tar.gz"));

      const call = execFileCalls.find((c) => c.args[0] === "bug-report");
      expect(call?.file).toBe("/fake/bin/istioctl");
      expect(call?.args).toContain(`--output-dir=${outputDir}`);
      expect(call?.args.some((a) => a.startsWith("--dir="))).toBe(false);
      expect(call?.args).toContain("--full-secrets");
      expect(call?.args.slice(call.args.indexOf("--context"), call.args.indexOf("--context") + 2)).toEqual(["--context", "kind-test"]);
      expect(call?.args.slice(call.args.indexOf("--include"), call.args.indexOf("--include") + 2)).toEqual(["--include", "apps,istio-system"]);
      expect(call?.args.slice(call.args.indexOf("--exclude"), call.args.indexOf("--exclude") + 2)).toEqual(["--exclude", "kube-system"]);
    } finally {
      await rm(dirname(outputDir), { recursive: true, force: true });
    }
  });
});

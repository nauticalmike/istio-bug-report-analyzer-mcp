import { describe, it, expect } from "vitest";
import type { BugReportStore } from "../../src/archive/store.js";
import { withClusterWarnings } from "../../src/tools/cluster-warnings.js";

const storeWith = (issues: string[]) => ({ getClusterLoadIssues: () => issues }) as unknown as BugReportStore;
const result = { content: [{ type: "text" as const, text: "Diagnostic scan complete. No issues detected by built-in templates." }] };

describe("withClusterWarnings", () => {
  it("leaves results alone when every dump parsed", () => {
    expect(withClusterWarnings(storeWith([]), result)).toBe(result);
  });

  it("appends skipped dumps so an empty result is not read as a clean cluster", () => {
    const out = withClusterWarnings(storeWith(["cluster/k8s-resources (1,219 MB) was not parsed"]), result);
    expect(out.content).toHaveLength(2);
    expect(out.content[1].text).toContain("may be incomplete");
    expect(out.content[1].text).toContain("cluster/k8s-resources (1,219 MB) was not parsed");
  });
});

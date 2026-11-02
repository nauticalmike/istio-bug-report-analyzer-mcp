import { describe, it, expect } from "vitest";
import { HEAP_PER_DUMP_BYTE, planClusterDumpLoad } from "../../src/archive/heap-guard.js";

const GiB = 2 ** 30;
const MB = 1e6;

describe("planClusterDumpLoad", () => {
  const roomy = { heap_size_limit: 8 * GiB, used_heap_size: 100 * MB };

  it("skips nothing when every dump fits", () => {
    const plan = planClusterDumpLoad([{ file: "cluster/k8s-resources", bytes: 500 * MB }], roomy);
    expect(plan.skipped).toEqual([]);
    expect(plan.needBytes).toBe(500 * MB * HEAP_PER_DUMP_BYTE);
  });

  it("skips the largest dumps first until the rest fit", () => {
    // 4 GiB heap: ~3.87 GB usable minus 100 MB used. 1.2 GB needs 3.6 GB on its own.
    const heap = { heap_size_limit: 4 * GiB, used_heap_size: 100 * MB };
    const plan = planClusterDumpLoad(
      [
        { file: "cluster/k8s-resources", bytes: 1200 * MB },
        { file: "cluster/crs", bytes: 300 * MB },
        { file: "cluster/pods", bytes: 10 * MB },
      ],
      heap,
    );
    expect(plan.skipped.map((s) => s.file)).toEqual(["cluster/k8s-resources"]);
    // (1510 MB * 3 + 100 MB) / 0.9 = ~4.8 GiB, rounded up to 5 GiB.
    expect(plan.suggestedHeapMb).toBe(5120);
    expect(plan.skipped[0].message).toBe(
      "cluster/k8s-resources (1,200 MB) was not parsed: the cluster dumps need ~4,530 MB of heap and " +
        "~3,765 MB is available. Restart the server with NODE_OPTIONS=--max-old-space-size=5120 to load all cluster dumps.",
    );
  });

  it("words the pre-check in the future tense with the same numbers", () => {
    const heap = { heap_size_limit: 1 * GiB, used_heap_size: 0 };
    const dumps = [{ file: "cluster/k8s-resources", bytes: 600 * MB }];
    const planned = planClusterDumpLoad(dumps, heap, "planned");
    const parsed = planClusterDumpLoad(dumps, heap, "skipped");
    expect(planned.skipped[0].message).toContain("will not be parsed");
    expect(planned.skipped[0].message.replace("will not be parsed", "was not parsed")).toBe(parsed.skipped[0].message);
  });

  it("reports the available heap as zero, not negative, when it is already exhausted", () => {
    const plan = planClusterDumpLoad([{ file: "cluster/crs", bytes: 1 * MB }], { heap_size_limit: 100 * MB, used_heap_size: 200 * MB });
    expect(plan.availableBytes).toBe(0);
    expect(plan.skipped[0].message).toContain("~0 MB is available");
  });

  it("notes dumps over the string limit that will be parsed leniently, but not skipped ones", () => {
    const limit = 512 * 2 ** 20;
    const plan = planClusterDumpLoad(
      [
        { file: "cluster/k8s-resources", bytes: 600 * MB },
        { file: "cluster/crs", bytes: 10 * MB },
      ],
      roomy,
      "planned",
      limit,
    );
    expect(plan.lenient.map((l) => l.file)).toEqual(["cluster/k8s-resources"]);
    expect(plan.lenient[0].message).toContain("over the 512 MiB string limit");
    expect(plan.lenient[0].message).toContain("parsed item by item");

    const tight = planClusterDumpLoad([{ file: "cluster/k8s-resources", bytes: 600 * MB }], { heap_size_limit: GiB, used_heap_size: 0 }, "planned", limit);
    expect(tight.skipped).toHaveLength(1);
    expect(tight.lenient).toEqual([]);
  });
});

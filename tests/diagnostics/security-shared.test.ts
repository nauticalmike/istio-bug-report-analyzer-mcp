import { describe, it, expect } from "vitest";
import { formatMs, parseGoBool, parseGoDuration } from "../../src/diagnostics/mesh-checks/security-shared.js";

describe("Go value parsing (as istiod reads env flags)", () => {
  it("parses booleans like strconv.ParseBool", () => {
    for (const v of ["1", "t", "T", "TRUE", "true", "True"]) expect(parseGoBool(v)).toBe(true);
    for (const v of ["0", "f", "F", "FALSE", "false", "False"]) expect(parseGoBool(v)).toBe(false);
    for (const v of ["yes", "on", "", " true", undefined, null]) expect(parseGoBool(v)).toBeNull();
  });

  it("parses durations like time.ParseDuration, in ms", () => {
    expect(parseGoDuration("100ms")).toBe(100);
    expect(parseGoDuration("10s")).toBe(10_000);
    expect(parseGoDuration("1m30s")).toBe(90_000);
    expect(parseGoDuration("1.5s")).toBe(1500);
    expect(parseGoDuration(".5s")).toBe(500);
    expect(parseGoDuration("0")).toBe(0);
    expect(parseGoDuration("2h")).toBe(7_200_000);
    for (const v of ["10", "s", "10 s", "abc", "", "1x"]) expect(parseGoDuration(v)).toBeNull();
  });

  it("formats durations compactly", () => {
    expect(formatMs(30_000)).toBe("30s");
    expect(formatMs(120_000)).toBe("2m");
    expect(formatMs(100)).toBe("100ms");
  });
});

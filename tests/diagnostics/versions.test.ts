import { describe, it, expect } from "vitest";
import { findVersionSkew, findUnsupportedVersions, parseMinor } from "../../src/diagnostics/versions.js";
import type { VersionInfo } from "../../src/types.js";

function info(cp: (string | [string, string])[], dp: string[], client: string | null = null): VersionInfo {
  return {
    raw: "",
    clientVersion: client,
    controlPlaneVersions: cp.map((v) => (Array.isArray(v) ? { revision: v[0], version: v[1] } : { revision: "default", version: v })),
    proxyVersions: dp.map((version) => ({ version, count: 3 })),
  };
}

describe("parseMinor", () => {
  it("extracts major.minor from release, suffixed and dev strings", () => {
    expect(parseMinor("1.31.2")).toEqual({ major: 1, minor: 31 });
    expect(parseMinor("1.31.2-solo")).toEqual({ major: 1, minor: 31 });
    expect(parseMinor("1.32-dev")).toEqual({ major: 1, minor: 32 });
  });

  it("returns null for unknown or missing versions", () => {
    expect(parseMinor("unknown")).toBeNull();
    expect(parseMinor(null)).toBeNull();
    expect(parseMinor(undefined)).toBeNull();
  });
});

describe("findVersionSkew", () => {
  it("returns nothing without versions or without a parsable control plane", () => {
    expect(findVersionSkew(null)).toEqual([]);
    expect(findVersionSkew(info(["unknown"], ["1.29.1"]))).toEqual([]);
  });

  it("classifies one-behind, more-than-one-behind and ahead", () => {
    const kinds = findVersionSkew(info(["1.31.2"], ["1.30.6", "1.28.1", "1.32.0"])).map((i) => i.kind);
    expect(kinds).toEqual(["data-plane-behind", "unsupported-skew", "data-plane-ahead"]);
  });

  it("treats proxies matching any revision as unskewed during a canary upgrade", () => {
    expect(findVersionSkew(info([["1-30", "1.30.6"], ["1-31", "1.31.2"]], ["1.30.6", "1.31.2"]))).toEqual([]);
  });

  it("prefers the newer revision when a proxy sits between two control planes", () => {
    const issues = findVersionSkew(info([["1-30", "1.30.6"], ["1-32", "1.32.0"]], ["1.31.2"]));
    expect(issues.map((i) => i.kind)).toEqual(["data-plane-behind"]);
  });

  it("names the proxy count and versions in the detail", () => {
    expect(findVersionSkew(info(["1.31.2"], ["1.30.6"]))[0].detail).toContain("3 proxies on 1.30.6, control plane 1.31");
  });

  it("omits the proxy count when the archive does not record it", () => {
    const versions = info(["1.31.2"], ["1.30.6"]);
    versions.proxyVersions[0].count = 0;
    const detail = findVersionSkew(versions)[0].detail;
    expect(detail).toContain("proxies on 1.30.6, control plane 1.31");
    expect(detail).not.toMatch(/\b0 prox/);
  });
});

describe("findUnsupportedVersions", () => {
  const supported = ["1.30", "1.31"];

  it("flags an end-of-life control plane and client", () => {
    const issues = findUnsupportedVersions(info(["1.29.9"], ["1.29.9"], "1.28.3"), supported);
    expect(issues.map((i) => i.detail)).toEqual([
      expect.stringContaining("client (istioctl) 1.28.3"),
      expect.stringContaining("control plane (default) 1.29.9"),
    ]);
  });

  it("does not flag minors newer than the window (newer than our data, not EOL)", () => {
    expect(findUnsupportedVersions(info(["1.32.0", "2.0.0"], [], "1.32.0"), supported)).toEqual([]);
  });

  it("does not apply the upstream window to Solo builds", () => {
    expect(findUnsupportedVersions(info(["1.28.4-solo"], [], "1.28.4-solo"), supported)).toEqual([]);
  });

  describe("with a Solo (n-4) window", () => {
    const solo = ["1.27", "1.28", "1.29", "1.30", "1.31"];

    it("accepts a Solo build inside the Solo window but outside the upstream one", () => {
      expect(findUnsupportedVersions(info(["1.27.9-solo"], [], "1.28.4-solo"), supported, solo)).toEqual([]);
    });

    it("flags a Solo build older than the Solo window, citing the Solo list", () => {
      const issues = findUnsupportedVersions(info(["1.26.8-solo"], []), supported, solo);
      expect(issues).toHaveLength(1);
      expect(issues[0].detail).toContain("control plane (default) 1.26.8-solo");
      expect(issues[0].detail).toContain("Solo distribution");
      expect(issues[0].detail).toContain("1.27, 1.28, 1.29, 1.30, 1.31");
    });

    it("does not flag Solo builds newer than the Solo window", () => {
      expect(findUnsupportedVersions(info(["1.32.0-solo", "2.0.0-solo"], []), supported, solo)).toEqual([]);
    });

    it("still holds community builds to the upstream window", () => {
      expect(findUnsupportedVersions(info(["1.28.10"], []), supported, solo).map((i) => i.kind)).toEqual(["unsupported-version"]);
    });
  });

  it("ignores supported and unparsable versions", () => {
    expect(findUnsupportedVersions(info(["1.31.2", "unknown"], [], "1.30.6"), supported)).toEqual([]);
  });
});

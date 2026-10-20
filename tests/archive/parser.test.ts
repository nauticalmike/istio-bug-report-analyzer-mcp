import { describe, it, expect } from "vitest";
import {
  parseYamlMultiDoc,
  parseAnalyzeOutput,
  parseVersionsFile,
  tryParseJson,
} from "../../src/archive/parser.js";

describe("parseYamlMultiDoc", () => {
  it("parses multiple YAML documents separated by ---", () => {
    const input = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: default\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: istio-system\n";
    const docs = parseYamlMultiDoc(input);
    expect(docs).toHaveLength(2);
    expect(docs[0].kind).toBe("Namespace");
    expect(docs[1].metadata.name).toBe("istio-system");
  });

  it("handles single document", () => {
    const input = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n";
    const docs = parseYamlMultiDoc(input);
    expect(docs).toHaveLength(1);
  });

  it("skips empty documents", () => {
    const input = "---\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n---\n";
    const docs = parseYamlMultiDoc(input);
    expect(docs).toHaveLength(1);
  });
});

describe("parseAnalyzeOutput", () => {
  it("parses Error, Warning, and Info lines", () => {
    const input = [
      'Error [IST0101] (VirtualService default/broken-vs) Referenced host not found: "missing-host"',
      "Warning [IST0107] (Deployment default/my-app) Misplaced annotation: sidecar.istio.io/proxyMemory",
      "Info [IST0118] (Service default/my-svc) Port name is not following Istio conventions",
    ].join("\n");
    const results = parseAnalyzeOutput(input);
    expect(results).toHaveLength(3);
    expect(results[0]).toEqual({
      severity: "Error",
      code: "IST0101",
      resource: "VirtualService default/broken-vs",
      message: 'Referenced host not found: "missing-host"',
    });
    expect(results[1].severity).toBe("Warning");
    expect(results[2].severity).toBe("Info");
  });

  it("returns empty array for empty input", () => {
    expect(parseAnalyzeOutput("")).toEqual([]);
  });
});

const bi = (v: string, golang = "") =>
  `version.BuildInfo{Version:"${v}", GitRevision:"0000000000000000000000000000000000000000", GolangVersion:"${golang}", BuildStatus:"Clean", GitTag:"${v}"}`;

describe("parseVersionsFile", () => {
  it("parses istioctl 1.31 bug-report output with revisions and replicas", () => {
    const input = [
      "CLI version:",
      bi("1.31.2", "go1.25.1"),
      "",
      "✅ The following Istio control plane revisions/versions were found in the cluster:",
      "Revision 1-31:",
      `&version.MeshInfo{version.ServerInfo{Component:"pilot", Revision:"1-31", Info:${bi("1.31.2")}}, version.ServerInfo{Component:"pilot", Revision:"1-31", Info:${bi("1.31.2")}}}`,
      "",
      "Revision 1-30:",
      `&version.MeshInfo{version.ServerInfo{Component:"pilot", Revision:"1-30", Info:${bi("1.30.6")}}}`,
      "",
      "✅ The following proxy revisions/versions were found in the cluster:",
      "Revision 1-31: Versions {1.31.2, 1.30.6}",
      "Revision 1-30: Versions {1.30.6}",
      "",
    ].join("\n");
    const v = parseVersionsFile(input);
    expect(v.clientVersion).toBe("1.31.2");
    expect(v.controlPlaneVersions).toEqual([
      { revision: "1-31", version: "1.31.2" },
      { revision: "1-30", version: "1.30.6" },
    ]);
    expect(v.proxyVersions).toEqual([
      { version: "1.31.2", count: 0 },
      { version: "1.30.6", count: 0 },
    ]);
  });

  it("parses pre-1.30 output with pretty-printed MeshInfo and error revisions", () => {
    const input = [
      "CLI version:",
      bi("1.30.2-solo", "go1.24.6"),
      "",
      "The following Istio control plane revisions/versions were found in the cluster:",
      "Revision default:",
      "&version.MeshInfo{",
      "    {",
      '        Component: "pilot",',
      '        Revision:  "default",',
      `        Info:      ${bi("1.29.9-solo")},`,
      "    },",
      "}",
      "",
      "Revision canary:",
      'no running Istio pods in namespace "istio-system"',
      "",
      "The following proxy revisions/versions were found in the cluster:",
      "Revision default: Versions {1.29.9-solo}",
    ].join("\r\n");
    const v = parseVersionsFile(input);
    expect(v.clientVersion).toBe("1.30.2-solo");
    expect(v.controlPlaneVersions).toEqual([{ revision: "default", version: "1.29.9-solo" }]);
    expect(v.proxyVersions).toEqual([{ version: "1.29.9-solo", count: 0 }]);
  });

  it("extracts versions from the legacy single-line format", () => {
    const input = "client version: 1.29.1\ncontrol plane version: 1.29.1\ndata plane version: 1.29.1 (2 proxies)\n";
    const v = parseVersionsFile(input);
    expect(v.clientVersion).toBe("1.29.1");
    expect(v.controlPlaneVersions).toEqual([{ revision: "default", version: "1.29.1" }]);
    expect(v.proxyVersions).toEqual([{ version: "1.29.1", count: 2 }]);
  });
});

describe("tryParseJson", () => {
  it("parses valid JSON", () => {
    expect(tryParseJson('{"key":"value"}')).toEqual({ key: "value" });
  });

  it("returns null for invalid JSON", () => {
    expect(tryParseJson("not json")).toBeNull();
  });
});

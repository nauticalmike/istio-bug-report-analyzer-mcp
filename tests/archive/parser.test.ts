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

describe("parseVersionsFile", () => {
  it("extracts client, control plane, and data plane versions", () => {
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

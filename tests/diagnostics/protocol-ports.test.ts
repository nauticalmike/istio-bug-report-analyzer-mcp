import { describe, it, expect } from "vitest";
import { declaredProtocol } from "../../src/diagnostics/protocol-ports.js";

// istiod's protocol.Parse (pkg/config/protocol/instance.go) knows no "hbone" name: a port named
// hbone-* (or appProtocol hbone) is unsupported, so istiod sniffs it like an unnamed port.
describe("declaredProtocol", () => {
  it("treats hbone as unrecognized (sniffed)", () => {
    expect(declaredProtocol("hbone", undefined)).toBeNull();
    expect(declaredProtocol("hbone-15008", undefined)).toBeNull();
    expect(declaredProtocol(undefined, "HBONE")).toBeNull();
  });

  it("keeps the names protocol.Parse recognizes", () => {
    expect(declaredProtocol("http-web", undefined)).toBe("http");
    expect(declaredProtocol("tcp-db", undefined)).toBe("other");
    expect(declaredProtocol("grpc-web-api", undefined)).toBe("http");
    expect(declaredProtocol("web", undefined)).toBeNull();
  });
});

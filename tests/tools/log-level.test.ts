import { describe, it, expect } from "vitest";
import { logLevel } from "../../src/tools/log-level.js";

describe("logLevel", () => {
  it.each([
    ["2026-10-20T20:21:37.443747Z\terror\tcontrollers\terror handling istio-validator, retrying", "error"],
    ["2026-10-20T20:21:37.207788Z\twarn\tNo CRL file found", "warn"],
    ["2026-10-20T20:22:24.123456Z\twarning\tenvoy config\tgRPC config stream closed", "warn"],
    ["2026-10-20T20:22:24.123456Z  ERROR ztunnel::proxy: connection failed", "error"],
    ["2026-10-20T20:22:24.123456Z\tfatal\tfailed to start", "error"],
    ["[2026-10-20 20:22:25.123][15][warning][config] [source/common/config/grpc_stream.h:191] stream closed", "warn"],
    ["[2026-10-20 20:22:25.123][15][critical][main] [source/server/server.cc:100] error initializing", "error"],
    ['{"level":"error","time":"2026-10-20T20:22:25Z","msg":"boom"}', "error"],
    ['{"level":"warn","msg":"slow"}', "warn"],
    ["E1020 20:23:09.123456       1 reflector.go:150] failed to list", "error"],
    ["W1020 20:23:09.123456       1 warnings.go:70] deprecated", "warn"],
    ["panic: runtime error: invalid memory address", "error"],
  ])("classifies %j as %s", (line, expected) => {
    expect(logLevel(line)).toBe(expected);
  });

  it.each([
    '2026-10-20T20:22:24.038239Z\tinfo\tFLAG: --proxyComponentLogLevel="misc:error"',
    '2026-10-20T20:22:24.038240Z\tinfo\tFLAG: --proxyLogLevel="warning"',
    "  try_tcp_on_error: false",
    '[2026-10-20T20:22:30.000Z] "GET /status/500 HTTP/1.1" 500 - via_upstream - "-" 0 0 1 0',
    "2026-10-20T20:21:49.802224Z\tinfo\twatch error resolved",
  ])("does not flag %j", (line) => {
    expect(logLevel(line)).toBeNull();
  });
});

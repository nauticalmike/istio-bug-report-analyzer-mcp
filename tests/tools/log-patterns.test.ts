import { describe, it, expect } from "vitest";
import { noiseKind, normalizeLogLine, normalizePorts } from "../../src/tools/log-patterns.js";

describe("normalizeLogLine", () => {
  const same = (a: string, b: string) => expect(normalizeLogLine(a)).toBe(normalizeLogLine(b));

  it("drops Istio, Envoy and klog timestamps and thread ids", () => {
    same("2026-01-01T00:00:00.123456Z\terror\tads\tpush failed", "2026-02-03T04:05:06.000001Z\terror\tads\tpush failed");
    same("[2026-01-01 00:00:00.123][15][warning][config] stream closed", "[2026-01-02 10:11:12.999][27][warning][config] stream closed");
    same("E1020 20:23:09.123456   12345 reflector.go:150] watch failed", "E1021 21:00:00.000001    6789 reflector.go:150] watch failed");
    expect(normalizeLogLine("2026-01-01T00:00:00Z\terror\tads\tpush failed")).toBe("error ads push failed");
  });

  it("collapses durations, including compound ones", () => {
    same("retry after 1.5s", "retry after 250ms");
    same("took 2m30s", "took 1h2m3.5s");
    same("waited 10µs", "waited 900us");
  });

  it("collapses decimals and long numbers but keeps short codes", () => {
    same("ratio=0.45 exceeded", "ratio=12.5 exceeded");
    same("ratio=0.35 exceeded", "ratio=0.44999999999999996 exceeded");
    same("dropped 123456 bytes", "dropped 98765 bytes");
    expect(normalizeLogLine("status code 503")).not.toBe(normalizeLogLine("status code 404"));
  });

  it("collapses IPv4 and IPv6 addresses with or without ports", () => {
    same("dial 10.0.0.1:8080 refused", "dial 192.168.1.20:15012 refused");
    same("dial [fd00:10:96::a]:15012 refused", "dial [2001:db8::1]:80 refused");
    same("peer fe80::1 gone", "peer fd00:1:2:3:4:5:6:7 gone");
    same("peer fe80::1 gone", "peer 10.1.2.3 gone");
    expect(normalizeLogLine("at 12:34:56 something")).toContain("12:34:56");
  });

  it("collapses ports on host names", () => {
    same("connect to istiod.istio-system.svc:15012 failed", "connect to istiod.istio-system.svc:15010 failed");
  });

  it("collapses UUIDs and hex ids", () => {
    same("request 123e4567-e89b-42d3-a456-426614174000 failed", "request 00000000-0000-4000-8000-000000000001 failed");
    same("object deadbeef01 missing", "object 0123456789abcdef missing");
  });

  it("collapses pod-hash suffixes from Deployments and DaemonSets", () => {
    same("pod reviews-v1-7d9f8b6c5d-x2k4p not ready", "pod reviews-v1-5b4c7f9d84-q9zt7 not ready");
    same("node agent istio-cni-node-x7k2p failed", "node agent istio-cni-node-4bz9m failed");
    expect(normalizeLogLine("pod reviews-v1-7d9f8b6c5d-x2k4p not ready")).toContain("reviews-v1-");
    // Ordinary hyphenated words are not pod hashes.
    expect(normalizeLogLine("the foo-backend-error path")).toContain("foo-backend-error");
  });

  it("collapses key=value identifiers", () => {
    same("lookup ns=team-a name=svc-1 id=17 failed", "lookup ns=team-b name=other id=4242 failed");
    same("deny src.workload=a src.namespace=x dst.service=b.svc", "deny src.workload=c src.namespace=y dst.service=d.svc");
    same("[C12][S3456] upstream reset", "[C99999][S1] upstream reset");
  });

  it("collapses JSON time, caller and thread fields", () => {
    same(
      '{"level":"error","time":"2026-01-01T00:00:00Z","caller":"a/b.go:10","thread":17,"msg":"push failed"}',
      '{"level":"error","time":"2026-01-02T00:00:00Z","caller":"a/b.go:99","thread":4,"msg":"push failed"}',
    );
  });

  it("keeps distinct messages distinct", () => {
    expect(normalizeLogLine("error\tfailure kind-qq")).not.toBe(normalizeLogLine("error\tfailure kind-qqq"));
    expect(normalizeLogLine("error\tca\tcertificate signing failed")).not.toBe(normalizeLogLine("error\tca\tcertificate rotation failed"));
  });
});

describe("noiseKind", () => {
  it("tags known noise", () => {
    expect(noiseKind('warn\tRequest to probe app failed: Get "http://10.0.0.1:8080/ready"')).toBe("probe");
    expect(noiseKind("Readiness probe failed: HTTP probe failed with statuscode: 503")).toBe("probe");
    expect(noiseKind("error\tfailed scraping application metrics: connection refused")).toBe("metrics scrape");
    expect(noiseKind("warning envoy main overload.global_downstream_max_connections is not set")).toBe("overload config");
    expect(noiseKind("error\tAborting proxy")).toBe("proxy shutdown");
    expect(noiseKind('error\tunable to get node "": nodes "" not found')).toBe("empty node name");
    expect(noiseKind("warning envoy config field is work-in-progress and may change")).toBe("work-in-progress API");
  });

  it("leaves real errors untagged", () => {
    expect(noiseKind("error\tca\tcertificate signing failed")).toBeNull();
    expect(noiseKind("error\tcni\tfailed to add iptables rules")).toBeNull();
  });
});

describe("normalizePorts", () => {
  it("collapses ports only", () => {
    expect(normalizePorts("port-forward 127.0.0.1:34567 -> 15000 failed")).toBe(normalizePorts("port-forward 127.0.0.1:41234 -> 15000 failed"));
    expect(normalizePorts("forwarding from localhost:40001")).toBe(normalizePorts("forwarding from localhost:40002"));
    expect(normalizePorts("pod istiod-a failed")).not.toBe(normalizePorts("pod istiod-b failed"));
  });
});

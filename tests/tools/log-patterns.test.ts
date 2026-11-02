import { describe, it, expect } from "vitest";
import { LogLineNormalizer, noiseKind, normalizeLogLine } from "../../src/tools/log-patterns.js";

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

  it("keeps an HTTP status after code: or status: (403 and 404 stay apart)", () => {
    expect(normalizeLogLine("request failed code:403 forbidden")).not.toBe(normalizeLogLine("request failed code:404 forbidden"));
    expect(normalizeLogLine("upstream status:503")).not.toBe(normalizeLogLine("upstream status:404"));
    expect(normalizeLogLine("upstream Status:503")).toContain("Status:503");
    // A port on a host name still collapses.
    same("connect to istiod.istio-system.svc:15012 failed", "connect to istiod.istio-system.svc:443 failed");
  });

  it("keeps name= values when asked (collection-issue keys), and collapses the other ids", () => {
    const opts = { keepNames: true };
    expect(normalizeLogLine("list pods name=istiod failed", opts)).not.toBe(normalizeLogLine("list pods name=ztunnel failed", opts));
    expect(normalizeLogLine("list pods ns=a name=istiod id=1 failed", opts)).toBe(normalizeLogLine("list pods ns=b name=istiod id=2 failed", opts));
    // Without the option, name= still collapses (find_errors).
    same("lookup name=istiod failed", "lookup name=ztunnel failed");
  });

  it("normalizes pod-hash and DaemonSet suffixes inside kept name= values, even without a digit", () => {
    const opts = { keepNames: true };
    const key = (l: string) => normalizeLogLine(l, opts);
    expect(key("exec failed name=ztunnel-bcdfg")).toBe(key("exec failed name=ztunnel-x7k2p"));
    expect(key('exec failed name="ztunnel-bcdfg"')).toBe(key('exec failed name="ztunnel-hjklm"'));
    expect(key("exec failed name=cart-bcdfghjk-mnpqr")).toBe(key("exec failed name=cart-7d9f8b6c4d-x2k9p"));
    // The workload part stays apart.
    expect(key("exec failed name=ztunnel-bcdfg")).not.toBe(key("exec failed name=istio-cni-node-bcdfg"));
    expect(key("exec failed name=istio-proxy")).not.toBe(key("exec failed name=istio-other"));
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


describe("LogLineNormalizer", () => {
  const lines = [
    "2026-01-01T00:00:00.123456Z\terror\tads\tpush failed for app-7d9f8b6c4d-x2k9p",
    "2026-02-03T04:05:06Z\terror\tads\tpush failed for app-7d9f8b6c4d-x2k9p",
    "2026-02-03 04:05:06,123+02:00 warn retry after 1.5s",
    "[2026-01-01 00:00:00.123][15][warning][config] stream closed",
    "[2026-01-02 10:11:12.999][27][warning][config] stream closed",
    "[C12] upstream reset",
    "E1020 20:23:09.123456   12345 reflector.go:150] watch failed",
    '{"level":"error","time":"2026-01-01T00:00:00Z","msg":"boom"}',
    "2026-01-01T00:00:00Z[bracket right after the time] x",
    `2026-01-01T00:00:00Z\terror\t${"x".repeat(2_100)}`,
  ];

  it("gives exactly what normalizeLogLine gives, on first sight and from the cache", () => {
    const n = new LogLineNormalizer();
    for (const pass of [1, 2]) {
      for (const line of lines) expect(n.normalize(line), `pass ${pass}: ${line.slice(0, 60)}`).toBe(normalizeLogLine(line));
    }
  });

  it("stays correct once the memo is full", () => {
    const n = new LogLineNormalizer(3);
    for (let i = 0; i < 20; i++) {
      const line = `2026-01-01T00:00:${String(i % 60).padStart(2, "0")}Z\terror\tmessage ${i % 7}`;
      expect(n.normalize(line)).toBe(normalizeLogLine(line));
    }
  });
});

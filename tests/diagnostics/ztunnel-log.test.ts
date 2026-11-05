import { describe, it, expect, afterEach } from "vitest";
import { classifyZtunnelEvent, isPublicIp, parseZtunnelLine, ztunnelLogScan, type ZtunnelPeer, type ZtunnelResolver } from "../../src/diagnostics/sources/ztunnel-log.js";
import { buildStore, cleanupArchives } from "./template-harness.js";
import { ALLOW_GAP, CNI_AGENT_LINE, STRICT_DENY, WDS_LAG_LINE, accessLine, healthCheckLine, jsonAccessLine, logOf, plainLine, ztunnelPodResource } from "./ztunnel-log-fixtures.js";

afterEach(cleanupArchives);

function classOf(line: string, resolve?: ZtunnelResolver) {
  const e = parseZtunnelLine(line);
  return e ? classifyZtunnelEvent(e, resolve) : null;
}

function peer(o: Partial<ZtunnelPeer>): ZtunnelPeer {
  return { kind: "pod", label: "shop/cart", namespace: "shop", scraper: false, metricsPorts: new Set(), ...o };
}

describe("parseZtunnelLine", () => {
  it("parses the plain access format: time, level, target, message, then k=v fields", () => {
    const e = parseZtunnelLine(accessLine({ error: ALLOW_GAP }));
    expect(e).toMatchObject({
      time: "2026-03-18T10:00:01.000000Z",
      level: "error",
      target: "access",
      message: "connection complete",
    });
    expect(e!.fields["dst.service"]).toBe("cart.shop.svc.cluster.local");
    expect(e!.fields["src.addr"]).toBe("10.0.1.4:43210");
    expect(e!.fields.direction).toBe("inbound");
    expect(e!.fields.error).toBe(ALLOW_GAP);
    expect(e!.fields.bytes_sent).toBe("0");
  });

  it("unescapes quoted values with embedded quotes", () => {
    const e = parseZtunnelLine(accessLine({ error: 'unknown service "x" in network "n"' }));
    expect(e!.fields.error).toBe('unknown service "x" in network "n"');
  });

  it("parses the JSON format", () => {
    const e = parseZtunnelLine(jsonAccessLine({ error: "http status: 401 Unauthorized" }));
    expect(e).toMatchObject({ level: "error", target: "access", message: "connection complete" });
    expect(e!.fields.error).toBe("http status: 401 Unauthorized");
    expect(e!.fields.direction).toBe("outbound");
  });

  it("skips info and debug lines without parsing them", () => {
    expect(parseZtunnelLine(accessLine({ level: "info" }))).toBeNull();
    expect(parseZtunnelLine(plainLine(1, "info", "ztunnel", "version: 1.31.2"))).toBeNull();
    expect(parseZtunnelLine("not a log line")).toBeNull();
  });
});

describe("classifyZtunnelEvent", () => {
  it("labels an ALLOW policy gap", () => {
    expect(classOf(accessLine({ error: ALLOW_GAP }))).toMatchObject({ id: "policy-allow-gap", severity: "warning", noise: false });
  });

  it("labels STRICT PeerAuthentication denials apart from other explicit denies", () => {
    expect(classOf(accessLine({ error: STRICT_DENY }))?.id).toBe("policy-strict-plaintext");
    expect(classOf(accessLine({ error: "connection closed due to policy rejection: explicitly denied by: shop/converted_peer_authentication_shop-strict" }))?.id).toBe("policy-strict-plaintext");
    const deny = classOf(accessLine({ error: "connection closed due to policy rejection: explicitly denied by: shop/deny-legacy" }));
    expect(deny).toMatchObject({ id: "policy-explicit-deny", severity: "info", detail: "shop/deny-legacy" });
  });

  it("labels the reason-less policy rejection of older ztunnel", () => {
    expect(classOf(accessLine({ error: "connection closed due to policy rejection" }))?.id).toBe("policy-rejection");
  });

  it("labels HBONE NetworkPolicy timeouts, 401s and other http statuses", () => {
    expect(classOf(accessLine({ direction: "outbound", error: "connection timed out, maybe a NetworkPolicy is blocking HBONE port 15008: deadline has elapsed" }))?.id).toBe("networkpolicy-hbone");
    expect(classOf(accessLine({ direction: "outbound", error: "http status: 401 Unauthorized" }))?.id).toBe("http-401");
    expect(classOf(accessLine({ direction: "outbound", error: "http status: 503 Service Unavailable" }))).toMatchObject({ id: "http-503", severity: "warning" });
  });

  it("labels LB health checks on 15008 as noise", () => {
    expect(classOf(healthCheckLine())).toMatchObject({ id: "hbone-health-check", noise: true, severity: "info" });
    expect(classOf(accessLine({ message: "connection failed", error: "invalid CONNECT address /healthz" }))).toMatchObject({ id: "hbone-health-check", noise: true });
  });

  it("does not call a TLS EOF on an application port a health check", () => {
    const c = classOf(accessLine({ message: "connection failed", dst: "10.0.2.7:8443", error: "tls handshake eof" }));
    expect(c?.noise).toBe(false);
  });

  it("labels client disconnects as noise", () => {
    expect(classOf(accessLine({ error: "client disconnected before all data was written" }))).toMatchObject({ noise: true });
  });

  it("labels ztunnel's own warnings: WDS lag, certificate fetch, oversized xDS", () => {
    expect(classOf(WDS_LAG_LINE())).toMatchObject({ id: "wds-lag", severity: "warning" });
    expect(classOf(plainLine(1, "warn", "identity::manager", "id=spiffe://cluster.local/ns/shop/sa/cart certificate fetch failed (connection refused) and no valid existing certificate; will retry in 1s"))?.id).toBe("cert-fetch");
    expect(classOf(plainLine(1, "warn", "xds::client", "XDS client connection error: gRPC connection error:status: OutOfRange, message: \"decoded message length too large: found 5242880 bytes, the limit is: 4194304 bytes\", retrying in 1s"))).toMatchObject({ id: "xds-message-too-large", severity: "critical" });
    expect(classOf(plainLine(1, "warn", "xds::client", "XDS client connection error: gRPC connection error:status: Unavailable, retrying in 1s"))?.id).toBe("xds-connection");
  });

  it("leaves the istio-cni connection line to DIAG-030", () => {
    expect(classOf(CNI_AGENT_LINE())?.id).toBe("cni-agent-connect");
  });

  it("groups unknown errors by their text with addresses and numbers masked", () => {
    const a = classOf(accessLine({ error: "connection failed: Connection refused (os error 111)" }));
    expect(a?.id).toBe("connection-refused");
    const b = classOf(accessLine({ error: "something odd happened to 10.0.3.3:9090 after 42ms" }));
    const c = classOf(accessLine({ error: "something odd happened to 10.0.4.4:9191 after 7ms" }));
    expect(b?.id).toMatch(/^other:/);
    expect(b?.id).toBe(c?.id);
    expect(b?.id).not.toMatch(/10\.0\./);
  });
});

describe("classifyZtunnelEvent", () => {
  it("words HTTP 401 as the destination ztunnel's authorization deny, paired with the policy rejection", () => {
    const c = classOf(accessLine({ direction: "outbound", error: "http status: 401 Unauthorized" }));
    expect(c?.guidance).toMatch(/authorization/);
    expect(c?.guidance).toMatch(/policy rejection/);
    expect(c?.guidance).not.toMatch(/not trusted there/);
  });

  it("reads `grpc: received message larger than max` as istiod refusing ztunnel's request (ISTIO_GPRC_MAXRECVMSGSIZE on istiod)", () => {
    const c = classOf(plainLine(1, "warn", "xds::client", 'XDS client connection error: gRPC connection error:status: ResourceExhausted, message: "grpc: received message larger than max (5242880 vs. 4194304)", retrying in 1s'));
    expect(c).toMatchObject({ id: "xds-request-too-large", severity: "critical" });
    expect(c?.guidance).toContain("ISTIO_GPRC_MAXRECVMSGSIZE");
    expect(c?.guidance).toMatch(/istiod's environment/);
    expect(c?.guidance).toMatch(/not in proxyMetadata/);
  });

  it("marks certificate fetch and xDS rate-limit lines as owned by DIAG-023 and DIAG-020", () => {
    expect(classOf(plainLine(1, "warn", "identity::manager", "id=spiffe://cluster.local/ns/shop/sa/cart certificate fetch failed (connection refused) and no valid existing certificate; will retry in 1s"))?.ownedBy).toBe("DIAG-023");
    expect(classOf(plainLine(1, "warn", "xds::client", 'XDS client connection error: gRPC connection error:status: ResourceExhausted, message: "request rate limit exceeded: rate: Wait(n=1) would exceed context deadline", retrying in 1s'))).toMatchObject({ id: "xds-rate-limit", ownedBy: "DIAG-020" });
  });

  it("splits `identity error: signing` from TLS failures and points at DIAG-023", () => {
    const c = classOf(accessLine({ direction: "outbound", error: "identity error: signing gRPC error (Unavailable): connection refused" }));
    expect(c?.id).toBe("identity-signing");
    expect(c?.guidance).toContain("DIAG-023");
    expect(classOf(accessLine({ error: "tls handshake error: invalid peer certificate: UnknownIssuer" }))?.id).toBe("tls-identity");
  });

  it("labels connection drain as noise", () => {
    expect(classOf(accessLine({ error: "connection closed due to connection drain" }))).toMatchObject({ id: "connection-drain", noise: true, severity: "info" });
  });

  it("points WDS lag at DIAG-020 and STRICT denials at port-level PeerAuthentication, which ztunnel honours", () => {
    expect(classOf(WDS_LAG_LINE())?.guidance).toContain("DIAG-020");
    const strict = classOf(accessLine({ error: STRICT_DENY }));
    expect(strict?.guidance).toMatch(/portLevelMtls/);
    expect(strict?.guidance).not.toMatch(/on a sidecar workload/);
  });

  it("redacts credentials in unclassified error texts", () => {
    const c = classOf(accessLine({ error: "upstream said no to authorization: Bearer abcDEFghiJKLmnoPQRstu.vwxYZ0123456789 for client_secret=supersecretvalue" }));
    expect(c?.id).toMatch(/^other:/);
    expect(c?.label).not.toContain("abcDEFghiJKLmnoPQRstu");
    expect(c?.label).not.toContain("supersecretvalue");
  });

  it("ranks refused or timed-out scrapes of metrics ports from a scraper as noise", () => {
    const scraper = new Map<string, ZtunnelPeer>([["10.0.5.5", peer({ label: "monitoring/prometheus-0", namespace: "monitoring", scraper: true })], ["10.0.2.7", peer({ metricsPorts: new Set(["8081"]) })]]);
    const resolve: ZtunnelResolver = (ip) => scraper.get(ip);
    expect(classOf(accessLine({ src: "10.0.5.5:40000", hbone: "10.0.2.7:15020", error: "connection failed: Connection refused (os error 111)" }), resolve)).toMatchObject({ id: "scrape-noise", noise: true });
    expect(classOf(accessLine({ src: "10.0.5.5:40000", hbone: "10.0.2.7:8081", error: "connection timed out" }), resolve)?.id).toBe("scrape-noise");
    // Not a metrics port, or not a scraper: the plain class.
    expect(classOf(accessLine({ src: "10.0.5.5:40000", hbone: "10.0.2.7:8080", error: "connection failed: Connection refused (os error 111)" }), resolve)?.id).toBe("connection-refused");
    expect(classOf(accessLine({ src: "10.0.1.4:40000", hbone: "10.0.2.7:15020", error: "connection failed: Connection refused (os error 111)" }), resolve)?.id).toBe("connection-refused");
  });

  it("tells public from private addresses", () => {
    expect(isPublicIp("203.0.113.10")).toBe(true);
    expect(isPublicIp("2001:db8::1")).toBe(true);
    for (const ip of ["10.0.2.7", "172.20.0.1", "192.168.1.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "fd00::1", "fe80::1"]) expect(isPublicIp(ip)).toBe(false);
  });
});

describe("ztunnelLogScan", () => {
  it("reads each ztunnel log once per store and keeps counters, not lines", async () => {
    const store = await buildStore({ resources: [ztunnelPodResource("ztunnel-a1b2c")], files: { "proxies/istio-system/ztunnel-a1b2c/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP }), accessLine({ at: 2, error: ALLOW_GAP, src: "10.0.1.9:1" }), CNI_AGENT_LINE()]) } });
    const first = ztunnelLogScan(store);
    expect(ztunnelLogScan(store)).toBe(first);
    const scan = await first;
    expect(scan.scan.components.ztunnel).toMatchObject({ files: 1, read: 1 });
    const gap = scan.classes.get("policy-allow-gap")!;
    expect(gap.count).toBe(2);
    expect(gap.sourceAddrs.size).toBe(2);
    expect(gap.byDirection.get("inbound")).toBe(2);
    expect(scan.classes.get("cni-agent-connect")?.count).toBe(1);
  });
});

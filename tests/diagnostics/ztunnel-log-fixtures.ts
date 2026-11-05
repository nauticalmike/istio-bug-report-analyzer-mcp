// Synthetic ztunnel log lines in the formats ztunnel writes (src/telemetry.rs IstioFormat and
// IstioJsonFormat; access fields from src/proxy/metrics.rs). Addresses, names and identities
// are made up (shop, cart, payments, example.com).

export const TS = (s: number): string => `2026-03-18T10:${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}.000000Z`;

interface AccessOpts {
  at?: number;
  level?: "error" | "warn" | "info";
  message?: "connection complete" | "connection failed";
  direction?: "inbound" | "outbound";
  src?: string;
  dst?: string;
  hbone?: string;
  service?: string;
  workload?: string;
  dstNamespace?: string;
  error?: string;
}

/** A plain-format access line: `<time>\t<level>\taccess\t<message>\tk=v ...`. */
export function accessLine(o: AccessOpts = {}): string {
  const fields: string[] = [`src.addr=${o.src ?? "10.0.1.4:43210"}`];
  if (o.message !== "connection failed") {
    fields.push('src.workload="checkout-7d9f8b6c5-abcde"', 'src.namespace="shop"', 'src.identity="spiffe://cluster.local/ns/shop/sa/checkout"');
  }
  fields.push(`dst.addr=${o.dst ?? "10.0.2.7:15008"}`);
  if (o.message !== "connection failed") {
    if (o.hbone !== "") fields.push(`dst.hbone_addr=${o.hbone ?? "10.0.2.7:8080"}`);
    if (o.service !== "") fields.push(`dst.service="${o.service ?? "cart.shop.svc.cluster.local"}"`);
    if (o.workload !== "") fields.push(`dst.workload="${o.workload ?? "cart-6d8f9c7b5-x2x4q"}"`);
    fields.push(`dst.namespace="${o.dstNamespace ?? "shop"}"`);
  }
  fields.push(`direction="${o.direction ?? "inbound"}"`);
  if (o.message !== "connection failed") fields.push("bytes_sent=0", "bytes_recv=0", 'duration="1ms"');
  if (o.error !== undefined) fields.push(`error="${o.error.replace(/"/g, '\\"')}"`);
  const level = o.level ?? (o.message === "connection failed" ? "warn" : "error");
  return `${TS(o.at ?? 1)}\t${level}\taccess\t${o.message ?? "connection complete"}\t${fields.join(" ")}`;
}

export const ALLOW_GAP = "connection closed due to policy rejection: allow policies exist, but none allowed";
export const STRICT_DENY = "connection closed due to policy rejection: explicitly denied by: istio-system/istio_converted_static_strict";

/** LB health checks on 15008: TCP connect and close before TLS (inbound early deny). */
export function healthCheckLine(at = 2, src = "10.0.9.1:51000"): string {
  return accessLine({ at, message: "connection failed", src, dst: "10.0.2.7:15008", error: "tls handshake eof" });
}

export function plainLine(at: number, level: string, target: string, message: string, fields = ""): string {
  return `${TS(at)}\t${level}\t${target}\t${message}${fields ? `\t${fields}` : ""}`;
}

export const CNI_AGENT_LINE = (at = 3): string =>
  plainLine(at, "warn", "inpod::workloadmanager", 'failed to connect to the Istio CNI node agent over "/var/run/ztunnel/ztunnel.sock", is the node agent healthy? details: Os { code: 2, kind: NotFound, message: "No such file or directory" }. retrying in 20ms');

export const WDS_LAG_LINE = (at = 4): string => plainLine(at, "warn", "state", "timed out waiting for workload 'shop/cart-6d8f9c7b5-x2x4q' from xds");

/** A JSON-format (LOG_FORMAT=json) access line. */
export function jsonAccessLine(o: { at?: number; error: string; direction?: string; service?: string; namespace?: string }): string {
  return JSON.stringify({
    level: "error",
    time: TS(o.at ?? 5),
    scope: "access",
    message: "connection complete",
    "src.addr": "10.0.1.4:43210",
    "dst.addr": "10.0.3.3:15008",
    "dst.service": o.service ?? "payments.payments.svc.cluster.local",
    "dst.namespace": o.namespace ?? "payments",
    direction: o.direction ?? "outbound",
    bytes_sent: 0,
    bytes_recv: 0,
    duration: "3ms",
    error: o.error,
  });
}

export function logOf(lines: string[]): string {
  return `${lines.join("\n")}\n`;
}

/**
 * A running ztunnel pod for cluster/k8s-resources: ztunnel logs of pods missing from a pod
 * dump that covers istio-system are stale and skipped (logFilesOf).
 */
export function ztunnelPodResource(name: string, node = "node-1"): Record<string, unknown> {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: "istio-system", labels: { app: "ztunnel" }, ownerReferences: [{ kind: "DaemonSet", name: "ztunnel" }] },
    spec: { nodeName: node, containers: [{ name: "istio-proxy", image: "registry.example.com/ztunnel:1.31.2" }] },
    status: { phase: "Running" },
  };
}

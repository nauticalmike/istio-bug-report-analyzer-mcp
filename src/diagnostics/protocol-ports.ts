// Protocol selection for Service ports, as istiod does it (pkg/config/kube/conversion.go
// ConvertProtocol, pkg/config/protocol/instance.go Parse): appProtocol, else the port name up to
// its first "-"; an unrecognized name leaves the port to protocol sniffing, except on the ports
// istiod defaults to TCP (25, 53, 3306, 27017). Shared by DIAG-032 (IST0118) and DIAG-035.

/** Ports istiod treats as TCP when the name gives no protocol (wellKnownPorts in pkg/config/kube/conversion.go). */
export const ISTIO_DEFAULT_TCP_PORTS: ReadonlySet<number> = new Set([25, 53, 3306, 27017]);

/**
 * Well-known ports of server-first protocols: the server speaks first, so a sniffing proxy
 * (sidecar, gateway, waypoint) waits for client bytes that never come and the connection
 * stalls (protocolDetectionTimeout is off by default).
 */
export const SERVER_FIRST_PORTS: ReadonlyMap<number, string> = new Map([
  [21, "FTP"],
  [25, "SMTP"],
  [110, "POP3"],
  [143, "IMAP"],
  [587, "SMTP"],
  [3306, "MySQL"],
  [4222, "NATS"],
]);

/** Well-known ports of client-first, non-HTTP protocols: sniffing works, but adds detection to every connection. */
export const CLIENT_FIRST_PORTS: ReadonlyMap<number, string> = new Map([
  [2181, "ZooKeeper"],
  [5432, "PostgreSQL"],
  [5672, "AMQP"],
  [6379, "Redis"],
  [9042, "Cassandra"],
  [9092, "Kafka"],
  [11211, "Memcached"],
  [27017, "MongoDB"],
]);

/** Ports of protocols that are never HTTP (server- and client-first above, SSH and DNS). */
function nonHttpProtocol(port: number | undefined): string | undefined {
  if (port === undefined) return undefined;
  return SERVER_FIRST_PORTS.get(port) ?? CLIENT_FIRST_PORTS.get(port) ?? (port === 22 ? "SSH" : port === 53 ? "DNS" : undefined);
}

/** Protocol names istiod recognizes (protocol.Parse, case-insensitive), with whether they are HTTP. */
const KNOWN_PROTOCOLS: Record<string, "http" | "other"> = {
  tcp: "other",
  udp: "other",
  grpc: "http",
  "grpc-web": "http",
  http: "http",
  http_proxy: "http",
  http2: "http",
  https: "other",
  tls: "other",
  mongo: "other",
  redis: "other",
  mysql: "other",
};

/**
 * The protocol a port declares: "http" or "other" for a recognized name or appProtocol, null
 * when istiod falls back to sniffing (or its TCP default on well-known ports).
 */
export function declaredProtocol(name: string | undefined, appProtocol: string | undefined): "http" | "other" | null {
  let n = appProtocol ?? name ?? "";
  if (appProtocol !== undefined) {
    if (n === "kubernetes.io/h2c" || n === "kubernetes.io/ws") return "http";
    if (n === "kubernetes.io/wss") return "other";
  }
  n = n.toLowerCase();
  if (n.startsWith("grpc-web")) return "http";
  const dash = n.indexOf("-");
  if (dash >= 0) n = n.slice(0, dash);
  return KNOWN_PROTOCOLS[n] ?? null;
}

export interface ServicePortSpec {
  port: number;
  targetPort?: number | string;
  name?: string;
  appProtocol?: string;
  protocol?: string;
}

export type PortClass =
  /** A server-first protocol port that proxies sniff. */
  | { kind: "server-first"; protocol: string }
  /** A client-first, non-HTTP protocol port that proxies sniff. */
  | { kind: "client-first"; protocol: string }
  /** A port named or declared HTTP that serves a non-HTTP protocol. */
  | { kind: "http-on-non-http"; protocol: string };

/**
 * What is wrong with a Service port's protocol selection, judged by the well-known protocol of
 * its port or numeric targetPort; null when nothing (or when the port is UDP or unknown).
 */
export function classifyServicePort(p: ServicePortSpec): PortClass | null {
  if (p.protocol && p.protocol.toUpperCase() === "UDP") return null;
  const target = typeof p.targetPort === "number" ? p.targetPort : typeof p.targetPort === "string" && /^\d+$/.test(p.targetPort) ? Number(p.targetPort) : undefined;
  const declared = declaredProtocol(p.name, p.appProtocol);
  if (declared === "http") {
    const protocol = nonHttpProtocol(p.port) ?? nonHttpProtocol(target);
    return protocol ? { kind: "http-on-non-http", protocol } : null;
  }
  if (declared !== null || ISTIO_DEFAULT_TCP_PORTS.has(p.port)) return null;
  const serverFirst = SERVER_FIRST_PORTS.get(p.port) ?? (target !== undefined ? SERVER_FIRST_PORTS.get(target) : undefined);
  if (serverFirst) return { kind: "server-first", protocol: serverFirst };
  const clientFirst = CLIENT_FIRST_PORTS.get(p.port) ?? (target !== undefined ? CLIENT_FIRST_PORTS.get(target) : undefined);
  return clientFirst ? { kind: "client-first", protocol: clientFirst } : null;
}

/**
 * Data-plane ports the Istio proxy and agent own (istioReservedPorts in
 * pilot/cmd/pilot-agent/status/server.go). A Service port on one of them collides with the
 * proxy's own listeners on its clients or backends.
 */
export const ISTIO_RESERVED_PORTS: ReadonlyMap<number, string> = new Map([
  [15000, "Envoy admin"],
  [15001, "outbound traffic capture"],
  [15004, "pilot debug"],
  [15006, "inbound traffic capture"],
  [15008, "HBONE tunnel"],
  [15020, "pilot-agent status / merged Prometheus"],
  [15021, "Envoy health"],
  [15053, "DNS proxy"],
  [15090, "Envoy Prometheus"],
]);

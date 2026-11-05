import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import type { Severity } from "../checks.js";
import { logFilesOf, logRuleGap, type LogComponentStats, type LogRule, type LogRuleScan } from "../log-rules.js";
import { livePods } from "../mesh-model.js";
import { redactSecretsInText } from "../redact.js";

// ztunnel logs (proxies/<ns>/<ztunnel-pod>/istio-proxy.log) parsed line by line into error
// classes: DIAG-031 groups ztunnel's access-log errors and its own warnings by class,
// direction and destination; DIAG-030 reads the istio-cni connection line from the same pass.
// One streamed pass per store (memoized), whatever the log size: only warn and error lines
// are parsed, and every class keeps counters, never the lines.
//
// Formats (istio/ztunnel):
// - plain (src/telemetry.rs IstioFormat): `<RFC3339>\t<level>\t<target>\t<message>\t<k=v ...>`,
//   string values Debug-quoted (`dst.service="cart.shop.svc.cluster.local"`), Display values
//   bare (`src.addr=10.0.1.4:43210`);
// - JSON (LOG_FORMAT=json, IstioJsonFormat): {"level","time","scope","message",<fields>}.
// Access lines (src/proxy/metrics.rs) have target `access`: "connection complete" (ERROR with
// error=... when the connection failed) and "connection failed" (WARN, log_early_deny, before
// the workload is known: only src.addr, dst.addr, direction, error). Error texts come from
// proxy::Error (src/proxy.rs), e.g. "connection closed due to policy rejection: allow policies
// exist, but none allowed" (before 1.23 the reason was not appended).

export interface ZtunnelEvent {
  time?: string;
  level: string;
  target: string;
  message: string;
  fields: Record<string, string>;
}

const PARSED_LEVELS = new Set(["warn", "error"]);

/** The value of a Debug-quoted field ("..." with backslash escapes). */
function unquote(raw: string): string {
  if (!raw.startsWith('"')) return raw;
  try {
    return JSON.parse(raw) as string;
  } catch {
    // Rust Debug escapes JSON does not know (\u{1f600}, \'): keep the text between the quotes.
    return raw.slice(1, raw.endsWith('"') ? -1 : undefined).replace(/\\(["\\])/g, "$1");
  }
}

const FIELD_RE = /([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S*)/g;

function parseFields(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of text.matchAll(FIELD_RE)) out[m[1]] = unquote(m[2]);
  return out;
}

/**
 * A ztunnel warn or error line as an event, or null (other levels, other formats). Info and
 * debug lines are rejected from the level column alone, without parsing.
 */
export function parseZtunnelLine(line: string): ZtunnelEvent | null {
  if (line.startsWith("{")) {
    if (!line.includes('"level":"error"') && !line.includes('"level":"warn"')) return null;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      return null;
    }
    if (!raw || typeof raw !== "object") return null;
    const o = raw as Record<string, unknown>;
    const fields: Record<string, string> = {};
    for (const [k, v] of Object.entries(o)) {
      if (["level", "time", "scope", "message"].includes(k)) continue;
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") fields[k] = String(v);
    }
    const target = String(o.scope ?? "").replace(/^ztunnel::/, "");
    return { ...(typeof o.time === "string" ? { time: o.time } : {}), level: String(o.level), target, message: String(o.message ?? ""), fields };
  }
  const t1 = line.indexOf("\t");
  if (t1 < 0) return null;
  const t2 = line.indexOf("\t", t1 + 1);
  if (t2 < 0) return null;
  const level = line.slice(t1 + 1, t2);
  if (!PARSED_LEVELS.has(level)) return null;
  const t3 = line.indexOf("\t", t2 + 1);
  const target = (t3 < 0 ? line.slice(t2 + 1) : line.slice(t2 + 1, t3)).replace(/^ztunnel::/, "");
  const rest = t3 < 0 ? "" : line.slice(t3 + 1);
  const t4 = rest.indexOf("\t");
  const message = t4 < 0 ? rest : rest.slice(0, t4);
  const fieldText = t4 < 0 ? "" : rest.slice(t4 + 1);
  const time = line.slice(0, t1);
  return { ...(/^\d{4}-\d{2}-\d{2}T/.test(time) ? { time } : {}), level, target, message, fields: parseFields(fieldText) };
}

// --- Classes ------------------------------------------------------------------

export interface ZtunnelClass {
  /** Grouping key; `other:<masked text>` for unclassified errors. */
  id: string;
  /** Human label, printed at the start of the line. */
  label: string;
  severity: Severity;
  /** Known benign traffic: printed as noise and ranked last. */
  noise: boolean;
  guidance: string;
  /** A per-line detail to tally (the denying policy, the HTTP status). */
  detail?: string;
  /** Reported by another check (e.g. "DIAG-023"): DIAG-031 only cross-references it. */
  ownedBy?: string;
}

interface ClassDef {
  id: string;
  label: string;
  severity: Severity;
  noise?: boolean;
  ownedBy?: string;
  guidance: string;
  test: (error: string, e: ZtunnelEvent) => boolean | string;
}

function port(addr: string | undefined): string | undefined {
  return addr ? /:(\d+)$/.exec(addr)?.[1] : undefined;
}

// --- Address resolution (from the archive's Services and pods) ------------------

/** What an IP address in a ztunnel line is in the archive: a Service clusterIP or a pod IP. */
export interface ZtunnelPeer {
  kind: "service" | "pod" | "node";
  /** Printed label: `<name>.<ns>.svc` for a Service, `<ns>/<pod>` for a pod, the name for a Node. */
  label: string;
  /** Empty for a Node. */
  namespace: string;
  /** A metrics scraper (Prometheus and the like), by pod name, labels or service account. */
  scraper: boolean;
  /** Ports that serve metrics there (named for metrics, or prometheus.io/port). */
  metricsPorts: Set<string>;
}

export type ZtunnelResolver = ((ip: string) => ZtunnelPeer | undefined) & {
  /** Node objects in the archive (a kubelet address that resolves to none of them is a node no longer in the dump). */
  nodes?: number;
};

/** The kubelet API port (metrics-server and node-exporter style scrapes, logs and exec). */
const KUBELET_PORT = "10250";

/** Workload, identity or pod names of metrics scrapers. */
const SCRAPER_RE = /prometheus|vmagent|victoria-?metrics|otel-?collector|opentelemetry-collector|datadog|grafana-agent|\balloy\b|telegraf|metricbeat/i;
/** Port names that serve metrics. */
const METRICS_PORT_NAME_RE = /metric|prom|monitor|stats|scrape/i;
/** Istio's own metrics ports (pilot-agent 15020 merged metrics, Envoy 15090) and common exporter ports. */
const WELL_KNOWN_METRICS_PORTS = new Set(["15020", "15090", "9090", "9091", "9100", "9102", "9153"]);

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function scraperPod(p: ParsedResource): boolean {
  const labels = p.metadata.labels ?? {};
  const names = [p.metadata.name, labels.app, labels["app.kubernetes.io/name"], str(p.spec?.serviceAccountName)];
  return names.some((n) => typeof n === "string" && SCRAPER_RE.test(n));
}

/** IP -> Service (clusterIP) or pod (podIP, not hostNetwork) of the archive's cluster resources. */
export function buildZtunnelResolver(store: BugReportStore): ZtunnelResolver {
  const byIp = new Map<string, ZtunnelPeer>();
  for (const s of store.getClusterResources({ kind: "Service", group: "" })) {
    const ns = s.metadata.namespace ?? "default";
    const metricsPorts = new Set<string>();
    for (const p of list(s.spec?.ports).map(obj)) {
      if (!p || typeof p.name !== "string" || !METRICS_PORT_NAME_RE.test(p.name)) continue;
      if (typeof p.port === "number") metricsPorts.add(String(p.port));
      if (typeof p.targetPort === "number") metricsPorts.add(String(p.targetPort));
    }
    const ips = new Set([str(s.spec?.clusterIP), ...list(s.spec?.clusterIPs).map(str)].filter((ip): ip is string => !!ip && ip !== "None"));
    for (const ip of ips) byIp.set(ip, { kind: "service", label: `${s.metadata.name}.${ns}.svc`, namespace: ns, scraper: SCRAPER_RE.test(s.metadata.name), metricsPorts });
  }
  for (const p of livePods(store)) {
    if (p.spec?.hostNetwork === true) continue;
    const ns = p.metadata.namespace ?? "default";
    const metricsPorts = new Set<string>();
    for (const c of list(p.spec?.containers).map(obj)) {
      for (const cp of list(c?.ports).map(obj)) {
        if (cp && typeof cp.name === "string" && METRICS_PORT_NAME_RE.test(cp.name) && typeof cp.containerPort === "number") metricsPorts.add(String(cp.containerPort));
      }
    }
    const annotated = p.metadata.annotations?.["prometheus.io/port"];
    if (annotated && /^\d+$/.test(annotated)) metricsPorts.add(annotated);
    const status = obj(p.status);
    const ips = new Set([str(status?.podIP), ...list(status?.podIPs).map((x) => str(obj(x)?.ip))].filter((ip): ip is string => !!ip));
    const peer: ZtunnelPeer = { kind: "pod", label: `${ns}/${p.metadata.name}`, namespace: ns, scraper: scraperPod(p), metricsPorts };
    for (const ip of ips) if (!byIp.has(ip)) byIp.set(ip, peer);
  }
  let nodes = 0;
  for (const n of store.getClusterResources({ kind: "Node" })) {
    nodes++;
    for (const a of list(obj(n.status)?.addresses).map(obj)) {
      const ip = str(a?.address);
      if (!ip || (a?.type !== "InternalIP" && a?.type !== "ExternalIP")) continue;
      // A node IP is also each hostNetwork pod's IP: the Node wins.
      byIp.set(ip, { kind: "node", label: n.metadata.name, namespace: "", scraper: false, metricsPorts: new Set() });
    }
  }
  const resolve: ZtunnelResolver = (ip) => byIp.get(ip);
  resolve.nodes = nodes;
  return resolve;
}

/** A routable address outside the private, shared, loopback and link-local ranges. */
export function isPublicIp(host: string): boolean {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    return true;
  }
  if (!host.includes(":")) return false;
  const h = host.toLowerCase();
  return !(h === "::1" || h === "::" || /^f[cd]/.test(h) || /^fe[89ab]/.test(h) || h.startsWith("::ffff:"));
}

function hostOf(addr: string | undefined): string | undefined {
  if (!addr) return undefined;
  const m = /^\[([^\]]+)\]:\d+$/.exec(addr) ?? /^([^:]+):\d+$/.exec(addr);
  return m ? m[1] : addr;
}

/** The application port of the destination: the HBONE inner address first, then dst.addr unless it is 15008. */
function appPort(e: ZtunnelEvent): string | undefined {
  const inner = port(e.fields["dst.hbone_addr"]);
  if (inner) return inner;
  const p = port(e.fields["dst.addr"]);
  return p === "15008" ? undefined : p;
}

/** The source of an access line is a metrics scraper (by workload, identity or resolved address). */
function fromScraper(e: ZtunnelEvent, resolve?: ZtunnelResolver): boolean {
  const f = e.fields;
  const srcHost = hostOf(f["src.addr"]);
  return [f["src.workload"], f["src.identity"]].some((v) => !!v && SCRAPER_RE.test(v)) || (!!srcHost && !!resolve?.(srcHost)?.scraper);
}

/** A metrics scrape: the source is a scraper and the destination port serves metrics. */
function isScrape(e: ZtunnelEvent, resolve?: ZtunnelResolver): boolean {
  const f = e.fields;
  if (!fromScraper(e, resolve)) return false;
  const p = appPort(e);
  if (!p) return false;
  if (WELL_KNOWN_METRICS_PORTS.has(p)) return true;
  const dstHost = hostOf(f["dst.hbone_addr"]) ?? hostOf(f["dst.addr"]);
  return !!dstHost && !!resolve?.(dstHost)?.metricsPorts.has(p);
}

const KUBELET_NOISE: ZtunnelClass = {
  id: "kubelet-noise",
  label: "connections to the kubelet port 10250 refused or timed out",
  severity: "info",
  noise: true,
  guidance: "Clients reaching a node's kubelet API on 10250 (metrics-server or Prometheus scraping kubelets, log and exec requests) were refused or timed out: a node that is gone (scaled down) or a kubelet that does not answer from the pod network; application traffic is not affected. Check the scraper's node list if it continues",
};

const SCRAPE_NOISE: ZtunnelClass = {
  id: "scrape-noise",
  label: "metrics scrapes refused or timed out",
  severity: "info",
  noise: true,
  guidance: "A metrics scraper (Prometheus or the like, by workload, identity or pod) reached a metrics port (15020, 15090, a common exporter port or one named for metrics) that refused or did not answer: a scrape target that is down or does not serve metrics there; application traffic is not affected. Fix the scrape configuration or the target's metrics port",
};

/** Early-denied inbound connection on the HBONE port (log_early_deny, before TLS completed). */
function hboneEarlyDeny(e: ZtunnelEvent): boolean {
  return e.message === "connection failed" && e.fields.direction === "inbound" && port(e.fields["dst.addr"]) === "15008";
}

// Order matters: the first matching class wins.
const ACCESS_CLASSES: ClassDef[] = [
  {
    id: "policy-allow-gap",
    label: "policy rejection (allow policies exist, but none allowed)",
    severity: "warning",
    guidance: "An ALLOW AuthorizationPolicy selects the destination and no rule matches the caller: add the missing principal or namespace. Callers without a mesh identity (Prometheus scrapes, clients outside the mesh) match no principal rule and are denied too. ALLOW rules with HTTP fields never match on ztunnel (see DIAG-009)",
    test: (err) => err.includes("allow policies exist, but none allowed"),
  },
  {
    id: "policy-strict-plaintext",
    label: "policy rejection (STRICT PeerAuthentication against a plaintext client)",
    severity: "warning",
    guidance: "istiod turns STRICT PeerAuthentication into the DENY policy named here, so plaintext callers are refused: clients outside the mesh, hostNetwork pods and nodes, or sidecars that do not use mTLS. Enroll the clients, or set PERMISSIVE for them, mesh-wide, per namespace or per port: ztunnel honours a workload-selector PeerAuthentication's portLevelMtls too (see DIAG-011 for the PeerAuthentication settings ztunnel drops)",
    test: (err) => {
      const m = /explicitly denied by: (\S*(?:istio_converted_static_strict|converted_peer_authentication)\S*)/.exec(err);
      return m ? m[1] : false;
    },
  },
  {
    id: "policy-explicit-deny",
    label: "policy rejection (explicitly denied)",
    severity: "info",
    guidance: "A DENY AuthorizationPolicy matched (the policies are named): expected when the policy does what it was written for; check the callers if they should be allowed",
    test: (err) => {
      const m = /explicitly denied by: (\S+)/.exec(err);
      return m ? m[1] : false;
    },
  },
  {
    id: "policy-change",
    label: "connection closed due to policy change",
    severity: "info",
    guidance: "An AuthorizationPolicy change closed connections that were open when it took effect: expected after a policy rollout",
    test: (err) => err.includes("connection closed due to policy change"),
  },
  {
    id: "policy-rejection",
    label: "policy rejection",
    severity: "warning",
    guidance: "An AuthorizationPolicy denied the connection (this ztunnel version does not log why): check the ALLOW and DENY policies selecting the destination, and PeerAuthentication STRICT against plaintext callers",
    test: (err) => err.includes("policy rejection"),
  },
  {
    id: "networkpolicy-hbone",
    label: "connection timed out, maybe a NetworkPolicy is blocking HBONE port 15008",
    severity: "warning",
    guidance: "The destination's port 15008 did not answer: a NetworkPolicy (or a cloud firewall or security group) that does not allow TCP 15008 between nodes and pods (see DIAG-018 for the NetworkPolicies in the archive)",
    test: (err) => err.includes("maybe a NetworkPolicy is blocking HBONE"),
  },
  {
    id: "hbone-health-check",
    label: "inbound connections to 15008 dropped before TLS",
    severity: "info",
    noise: true,
    guidance: "Load balancer or scanner health checks against the HBONE port (TCP connect and close, or plain HTTP): harmless, but they flood the log; point the health checks at 15021 (/healthz/ready) instead",
    test: (err, e) =>
      err.startsWith("invalid CONNECT address") || err.startsWith("expected method CONNECT") ||
      (hboneEarlyDeny(e) && /tls handshake eof|unexpected end of file|connection reset by peer|early eof/i.test(err)),
  },
  {
    id: "connection-drain",
    label: "connection closed due to connection drain",
    severity: "info",
    noise: true,
    guidance: "ztunnel closed connections it was draining (its pod or the workload was shutting down, or a ztunnel restart): expected during rollouts and node drains",
    test: (err) => err.includes("connection closed due to connection drain"),
  },
  {
    id: "client-disconnected",
    label: "peer disconnected before all data was written",
    severity: "info",
    noise: true,
    guidance: "One side closed the connection mid-transfer (client timeouts, cancelled requests, pod shutdown): usually harmless unless it matches application errors",
    test: (err) => /client disconnected before all data was written|broken pipe/i.test(err),
  },
  {
    id: "http-status",
    label: "http status",
    severity: "warning",
    guidance: "",
    test: (err) => {
      const m = /http status: (\d{3})/.exec(err);
      return m ? m[1] : false;
    },
  },
  {
    id: "identity-signing",
    label: "identity error: no workload certificate from the CA",
    severity: "warning",
    guidance: "The source ztunnel could not get a certificate for the calling workload (the CA signing request failed), so these connections failed before any peer was involved: a CA failure, not a trust mismatch between peers. DIAG-023 groups the certificate errors by cause (CA unreachable, request rejected)",
    test: (err) => /identity error: (signing gRPC error|failed to create CSR|certificate for workload is not yet available)/.test(err),
  },
  {
    id: "tls-identity",
    label: "TLS or identity failure",
    severity: "warning",
    guidance: "mTLS between the ztunnels (or with a waypoint) failed: different root certificates or trust domains (cross-cluster, a CA rotation in progress), or a revoked or expired workload certificate",
    test: (err) => /tls handshake error|tls error|certificate|identity error|UnknownIssuer|BadCertificate|trust domain/i.test(err),
  },
  {
    id: "unknown-waypoint",
    label: "unknown waypoint",
    severity: "warning",
    guidance: "The destination names a waypoint ztunnel has no workload for: the waypoint is missing, not ready or not programmed (see DIAG-012)",
    test: (err) => err.includes("unknown waypoint"),
  },
  {
    id: "no-healthy-upstream",
    label: "no healthy upstream or endpoints",
    severity: "warning",
    guidance: "The destination Service had no healthy endpoints in ztunnel's view: pods not ready, or endpoints missing from WDS",
    test: (err) => /no healthy upstream|no endpoints for workload|no ip addresses were resolved/.test(err),
  },
  {
    id: "no-service",
    label: "no service or workload for the destination",
    severity: "warning",
    guidance: "ztunnel did not know the destination: a ServiceEntry or Service missing from WDS, a port the Service does not expose, or WDS lag",
    test: (err) => /no service or workload for hostname|no service for target address|found, but cannot resolve port|found, but has no IP addresses|unknown service .* in network/.test(err),
  },
  {
    id: "connection-refused",
    label: "connection refused by the destination",
    severity: "warning",
    guidance: "The destination pod refused the connection: nothing listens on the target port (targetPort mismatch, app not started, app bound to localhost only)",
    test: (err) => /connection refused/i.test(err),
  },
  {
    id: "timeout",
    label: "connection timed out",
    severity: "warning",
    guidance: "The connection did not complete in time: an unreachable node or pod, a firewall, or an overloaded destination",
    test: (err) => /timed out|deadline has elapsed/i.test(err),
  },
];

const HTTP_GUIDANCE: Record<string, string> = {
  "401": "The destination ztunnel's authorization check denied the HBONE CONNECT (an AuthorizationPolicy, or the DENY policy of STRICT PeerAuthentication): the source ztunnel logs 401, the destination logs the matching policy rejection with the policy named (see the policy rejection lines). A certificate the peer does not trust fails the TLS handshake instead (TLS or identity failure)",
  "403": "The peer refused the HBONE CONNECT as forbidden: an AuthorizationPolicy at a waypoint or the destination",
  "503": "The waypoint or peer could not reach the destination (no healthy upstream behind it)",
};

// ztunnel's own warnings and errors (not access lines). Message text in src/state.rs,
// src/identity/manager.rs, src/xds/client.rs, src/inpod/workloadmanager.rs.
const OWN_CLASSES: ClassDef[] = [
  {
    id: "cni-agent-connect",
    label: "failed to connect to the Istio CNI node agent",
    severity: "critical",
    guidance: "",
    test: (_e, ev) => ev.message.includes("failed to connect to the Istio CNI node agent"),
  },
  {
    id: "xds-request-too-large",
    label: "istiod rejected ztunnel's xDS request as over its gRPC receive limit",
    severity: "critical",
    guidance: "\"grpc: received message larger than max (N vs. M)\" is istiod's gRPC server refusing a request from ztunnel (the delta xDS request on reconnect lists every resource ztunnel holds, so it grows with the WDS size): the stream fails and ztunnel keeps stale workload and policy data. Raise ISTIO_GPRC_MAXRECVMSGSIZE (bytes, default 4194304) in istiod's environment (istiod Helm chart env, values.pilot.env with istioctl), not in proxyMetadata, which istiod does not read; setting it on the ztunnel DaemonSet does not raise istiod's limit either (ztunnel does not read it). Or shrink what istiod sends ztunnel (discoverySelectors)",
    test: (_e, ev) => /received message larger than max/.test(`${ev.message} ${Object.values(ev.fields).join(" ")}`),
  },
  {
    id: "xds-rate-limit",
    label: "xDS request rate limit exceeded",
    severity: "warning",
    ownedBy: "DIAG-020",
    guidance: "",
    test: (_e, ev) => /request rate limit exceeded/.test(`${ev.message} ${Object.values(ev.fields).join(" ")}`),
  },
  {
    id: "xds-message-too-large",
    label: "xDS response over the gRPC message size limit",
    severity: "critical",
    guidance: "A WDS or authorization response from istiod was larger than ztunnel's own gRPC decode limit, so the stream fails and ztunnel keeps stale workload and policy data. The limit is fixed in ztunnel's xDS client (200 MiB in current releases, src/xds/client.rs; older releases used gRPC's 4 MiB default) and no setting raises it (ISTIO_GPRC_MAXRECVMSGSIZE is istiod's receive limit): reduce what istiod sends ztunnel (discoverySelectors, fewer or smaller AuthorizationPolicies), or upgrade an older ztunnel",
    test: (_e, ev) => /message length too large/.test(ev.message),
  },
  {
    id: "wds-lag",
    label: "timed out waiting for workload from xds",
    severity: "warning",
    guidance: "ztunnel learned about a pod's traffic before istiod sent it the workload (WDS lag): new pods' first connections fail or are denied. Check istiod load and push times (DIAG-020)",
    test: (_e, ev) => ev.message.includes("timed out waiting for workload"),
  },
  {
    id: "cert-fetch",
    label: "certificate fetch failed",
    severity: "warning",
    ownedBy: "DIAG-023",
    guidance: "ztunnel could not get a workload certificate from the CA (istiod or an external CA): pods without a valid certificate cannot send or accept mesh traffic. Check CA_ADDRESS, the CA's logs and its reachability on 15012",
    test: (_e, ev) => ev.message.includes("certificate fetch failed"),
  },
  {
    id: "cert-prefetch",
    label: "unable to prefetch certificates",
    severity: "warning",
    ownedBy: "DIAG-023",
    guidance: "",
    test: (_e, ev) => ev.message.includes("unable to prefetch cert"),
  },
  {
    id: "xds-connection",
    label: "XDS client connection error",
    severity: "warning",
    guidance: "ztunnel lost or could not open its xDS stream to istiod: it keeps serving with the last config and retries. Check istiod availability and XDS_ADDRESS",
    test: (_e, ev) => /XDS client (connection )?error/.test(ev.message),
  },
  {
    id: "dns-id-mismatch",
    label: "DNS proxy: response with an unexpected message id",
    severity: "info",
    guidance: "An upstream DNS server answered with a different id than asked: the reply is dropped and the client retries; usually harmless",
    test: (_e, ev) => ev.message.includes("expected message id"),
  },
  {
    id: "otel-dns",
    label: "tracing exporter DNS errors",
    severity: "info",
    guidance: "The OpenTelemetry exporter cannot resolve its collector: tracing data is lost, traffic is not affected",
    test: (_e, ev) => /opentelemetry|otel/i.test(`${ev.target} ${ev.message}`) && /dns|resolve|lookup/i.test(ev.message),
  },
];

/** Masks addresses, numbers and quoted names so one unclassified error text is one group. */
export function maskErrorText(text: string): string {
  return text
    .replace(/\[[0-9a-f:]+\](:\d+)?/gi, "<addr>")
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, "<addr>")
    .replace(/spiffe:\/\/\S+/g, "<identity>")
    .replace(/"[^"]*"|'[^']*'/g, "<name>")
    .replace(/\b0x[0-9a-f]+\b/gi, "<n>")
    .replace(/\b\d+(?:\.\d+)?(ms|s|µs|ns|m|h)?\b/g, "<n>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
}

/**
 * The class of a parsed ztunnel event, or null when it is neither an access error nor a known
 * warning. `resolve` (the archive's Services and pods by IP) recognises metrics scrapers.
 */
export function classifyZtunnelEvent(e: ZtunnelEvent, resolve?: ZtunnelResolver): ZtunnelClass | null {
  if (e.target === "access") {
    const error = e.fields.error;
    if (!error) return null;
    for (const c of ACCESS_CLASSES) {
      const hit = c.test(error, e);
      if (!hit) continue;
      if (c.id === "connection-refused" || c.id === "timeout") {
        if (appPort(e) === KUBELET_PORT) return { ...KUBELET_NOISE };
        if (isScrape(e, resolve)) return { ...SCRAPE_NOISE };
      }
      if (c.id === "http-status") {
        const code = hit as string;
        return { id: `http-${code}`, label: `http status: ${code}`, severity: "warning", noise: false, guidance: HTTP_GUIDANCE[code] ?? `The peer ztunnel or waypoint answered the HBONE CONNECT with HTTP ${code}` };
      }
      return { id: c.id, label: c.label, severity: c.severity, noise: !!c.noise, guidance: c.guidance, ...(typeof hit === "string" ? { detail: hit } : {}) };
    }
    const masked = redactSecretsInText(maskErrorText(redactSecretsInText(error)));
    return { id: `other:${masked}`, label: masked, severity: "info", noise: false, guidance: "" };
  }
  for (const c of OWN_CLASSES) {
    if (c.test("", e)) return { id: c.id, label: c.label, severity: c.severity, noise: !!c.noise, guidance: c.guidance, ...(c.ownedBy ? { ownedBy: c.ownedBy } : {}) };
  }
  return null;
}

// --- Memoized scan ------------------------------------------------------------

export interface ZtunnelClassAgg {
  cls: ZtunnelClass;
  count: number;
  byDirection: Map<string, number>;
  /** Destination label (Service host, ns/workload, or "port N") -> count. */
  byDestination: Map<string, number>;
  /** Destination namespaces seen (dst.namespace, or the Service host's namespace). */
  namespaces: Set<string>;
  /** Per detail (denying policy, ...) -> count. */
  byDetail: Map<string, number>;
  /** ztunnel log source -> count. */
  bySource: Map<string, number>;
  /** Distinct source addresses without the port, up to MAX_DISTINCT_SOURCES. */
  sourceAddrs: Set<string>;
  sourceAddrsCapped: boolean;
  /** Access lines whose source is a metrics scraper (by workload, identity or address). */
  scraperLines: number;
  first: number;
  last: number;
}

export interface ZtunnelLogScan {
  /** A LogRuleScan shell (components and failed files only) for logRuleGap. */
  scan: LogRuleScan;
  /** By class id. Unclassified errors beyond MAX_OTHER_CLASSES are merged into "other:*". */
  classes: Map<string, ZtunnelClassAgg>;
  /** ztunnel pod of each source label (proxy pods are ztunnel/<ns>/<pod>). */
  pods: Map<string, { namespace: string; pod: string }>;
  /** Log files of pods no longer in the pod dump (LogFile.stale): not read at all. */
  staleFiles: number;
  /** Distinct pods of those files. */
  staleSources: number;
  /** Per live source: the first and last timestamp in its log (ms), when it has any. */
  spans: Map<string, { first: number; last: number }>;
  /** Per live source with "failed to connect to the Istio CNI node agent" lines (DIAG-030). */
  cniConnect: Map<string, CniConnectHits>;
}

export interface CniConnectHits {
  count: number;
  /** Times (ms) of the first and last such line with a timestamp. */
  first: number;
  last: number;
  /** ztunnel logged "handling new stream" (connected to istio-cni) after the last such line. */
  connectedAfter: boolean;
  /**
   * Bursts of such lines: a gap longer than CNI_BURST_GAP_MS starts a new one (ztunnel retries
   * at least every 15 s while it cannot connect, src/inpod/workloadmanager.rs), and the
   * longest burst's span (ms). A pod that reconnects at every istio-cni restart has several
   * short bursts, not one long failure.
   */
  bursts: number;
  longestBurstMs: number;
  /**
   * The log has info-level lines. Without any (logs collected at warn or error level) the
   * info "handling new stream" line can never appear, so connectedAfter says nothing.
   */
  infoSeen: boolean;
}

export const MAX_OTHER_CLASSES = 200;
const MAX_DISTINCT_SOURCES = 10_000;
/** Unclassified texts can be many: keep fewer addresses each. */
const MAX_DISTINCT_SOURCES_OTHER = 500;
export const OTHER_OVERFLOW = "other:*";

function destinationOf(e: ZtunnelEvent, resolve?: ZtunnelResolver): { label: string; namespace?: string } {
  const f = e.fields;
  const svc = f["dst.service"];
  if (svc && svc !== "unknown") {
    const ns = /^[^.]+\.([^.]+)\.svc(\.|$)/.exec(svc)?.[1] ?? f["dst.namespace"];
    return { label: svc, ...(ns ? { namespace: ns } : {}) };
  }
  const workload = f["dst.workload"];
  const ns = f["dst.namespace"] && f["dst.namespace"] !== "unknown" ? f["dst.namespace"] : undefined;
  if (workload && workload !== "unknown") return { label: ns ? `${ns}/${workload}` : workload, ...(ns ? { namespace: ns } : {}) };
  const p = port(f["dst.hbone_addr"]) ?? port(f["dst.addr"]);
  const host = hostOf(f["dst.hbone_addr"]) ?? hostOf(f["dst.addr"]);
  const peer = host ? resolve?.(host) : undefined;
  if (peer) {
    if (peer.kind === "node") return { label: p ? `node ${peer.label}, port ${p}` : `node ${peer.label}` };
    return { label: peer.kind === "service" ? peer.label : `pod ${peer.label}`, namespace: peer.namespace };
  }
  if (p === KUBELET_PORT && host && !isPublicIp(host) && (resolve?.nodes ?? 0) > 0) return { label: `a node not in the dump (scaled down), port ${p}` };
  if (host && isPublicIp(host)) return { label: p ? `external address (no Service: passthrough), port ${p}` : "external address (no Service: passthrough)" };
  return { label: p ? `unknown destination, port ${p}` : "unknown destination", ...(ns ? { namespace: ns } : {}) };
}

function bump<K>(map: Map<K, number>, key: K, n = 1): void {
  map.set(key, (map.get(key) ?? 0) + n);
}

const memo = new WeakMap<BugReportStore, Promise<ZtunnelLogScan>>();

/** One streamed pass over every collected ztunnel log, memoized per store. */
export function ztunnelLogScan(store: BugReportStore): Promise<ZtunnelLogScan> {
  let p = memo.get(store);
  if (!p) {
    p = runScan(store);
    memo.set(store, p);
  }
  return p;
}

/** A gap between "failed to connect to the Istio CNI node agent" lines that ends a burst. */
export const CNI_BURST_GAP_MS = 60_000;

/** The timestamp of a plain or JSON ztunnel line (ms), or NaN. */
function lineTime(line: string): number {
  if (line.startsWith("{")) {
    const m = /"time":"([^"]+)"/.exec(line);
    return m ? Date.parse(m[1]) : Number.NaN;
  }
  // Plain format: `<RFC3339>\t...`; a cheap shape test before parsing.
  if (line.charCodeAt(4) !== 45 || line[10] !== "T") return Number.NaN;
  const tab = line.indexOf("\t");
  return Date.parse(tab < 0 ? line : line.slice(0, tab));
}

/** "handling new stream" (src/inpod/workloadmanager.rs): ztunnel connected to the istio-cni node agent. */
const CNI_STREAM = "handling new stream";

function plural(n: number, word: string, many = `${word}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? word : many}`;
}

/** The pseudo rule ztunnel log coverage is judged with (logRuleGap). */
const ZTUNNEL_RULE: LogRule = { id: "ztunnel-log-classes", components: ["ztunnel"], match: "" };

/**
 * Why the ztunnel logs cannot be judged, or null: none collected (or only config dumps of
 * ztunnel pods), every log is of a pod no longer in the dump, or none could be read.
 */
export function ztunnelLogGap(z: ZtunnelLogScan): string | null {
  const s = z.scan.components.ztunnel;
  if (s && s.files > 0 && s.read === 0 && (s.stale ?? 0) === s.files) {
    return s.files === 1 ? "not evaluated: the only ztunnel log is of a pod no longer in the dump" : `not evaluated: all ${s.files.toLocaleString("en-US")} ztunnel logs are of pods no longer in the dump`;
  }
  if (s && s.read === 0 && (s.stale ?? 0) > 0) {
    return `not evaluated: ${plural(s.files - s.stale!, "ztunnel log file")} could not be read and the other ${plural(s.stale!, "log")} ${s.stale === 1 ? "is" : "are"} of pods no longer in the dump`;
  }
  return logRuleGap(z.scan, ZTUNNEL_RULE);
}

/** "; 3 log files of 3 pods no longer in the dump ignored", or "". */
export function ztunnelStaleText(z: ZtunnelLogScan): string {
  return z.staleFiles > 0 ? `${plural(z.staleFiles, "log file")} of ${plural(z.staleSources, "pod")} no longer in the dump ignored` : "";
}

async function runScan(store: BugReportStore): Promise<ZtunnelLogScan> {
  const files = logFilesOf(store, "ztunnel");
  const stale = files.filter((f) => f.stale);
  let missing: string | undefined;
  if (files.length === 0) {
    const dirs = store.getProxyPods().filter((p) => p.proxyType === "ztunnel").length;
    missing = dirs > 0
      ? `ztunnel logs not collected (${plural(dirs, "ztunnel pod")} present, config_dump only)`
      : "no ztunnel logs were collected (proxies/<ns>/ztunnel-*/istio-proxy.log): ztunnel is not installed, or its namespace or pods were excluded from the bug report";
  }
  const stats: LogComponentStats = { files: files.length, read: 0, bytes: 0, ...(stale.length > 0 ? { stale: stale.length } : {}), ...(missing ? { missing } : {}) };
  const scan: LogRuleScan = { hits: new Map(), components: { ztunnel: stats }, failed: [], longLines: 0 };
  const classes = new Map<string, ZtunnelClassAgg>();
  const pods = new Map<string, { namespace: string; pod: string }>();
  const spans = new Map<string, { first: number; last: number }>();
  const cniConnect = new Map<string, CniConnectHits>();
  const live = files.filter((f) => !f.stale);
  const resolve = live.length > 0 ? buildZtunnelResolver(store) : undefined;
  let others = 0;

  // Logs of pods missing from a pod dump that covers their namespace (left by an earlier
  // collection or another cluster) are not read: only their files and pods are counted.
  for (const file of live) {
    pods.set(file.source, { namespace: file.namespace ?? "", pod: file.pod });
    let first = Number.NaN;
    let lastTimed: string | undefined;
    let cc: (Omit<CniConnectHits, "infoSeen"> & { lastHitLine: number; lastStreamLine: number; burstStart: number; prev: number }) | undefined;
    let n = 0;
    let infoSeen = false;
    const onLine = (line: string) => {
      n++;
      if (!infoSeen && (line.includes("\tinfo\t") || line.includes('"level":"info"'))) infoSeen = true;
      if (line.startsWith("{") || (line.charCodeAt(4) === 45 && line[10] === "T")) {
        lastTimed = line;
        if (Number.isNaN(first)) first = lineTime(line);
      }
      if (cc && line.includes(CNI_STREAM)) cc.lastStreamLine = n;
      const e = parseZtunnelLine(line);
      if (!e) return;
      let cls = classifyZtunnelEvent(e, resolve);
      if (!cls) return;
      if (cls.id === "cni-agent-connect") {
        if (!cc) {
          cc = { count: 0, first: Infinity, last: -Infinity, connectedAfter: false, bursts: 0, longestBurstMs: 0, lastHitLine: 0, lastStreamLine: 0, burstStart: Number.NaN, prev: Number.NaN };
        }
        cc.count++;
        cc.lastHitLine = n;
        const t = e.time ? Date.parse(e.time) : Number.NaN;
        if (Number.isFinite(t)) {
          if (t < cc.first) cc.first = t;
          if (t > cc.last) cc.last = t;
          if (!Number.isFinite(cc.prev) || t - cc.prev > CNI_BURST_GAP_MS) {
            cc.bursts++;
            cc.burstStart = t;
          }
          cc.prev = t;
          cc.longestBurstMs = Math.max(cc.longestBurstMs, t - cc.burstStart);
        }
      }
      let agg = classes.get(cls.id);
      if (!agg && cls.id.startsWith("other:")) {
        if (others >= MAX_OTHER_CLASSES) {
          cls = { id: OTHER_OVERFLOW, label: "other unclassified errors", severity: "info", noise: false, guidance: "" };
          agg = classes.get(OTHER_OVERFLOW);
        } else {
          others++;
        }
      }
      if (!agg) {
        agg = { cls, count: 0, byDirection: new Map(), byDestination: new Map(), namespaces: new Set(), byDetail: new Map(), bySource: new Map(), sourceAddrs: new Set(), sourceAddrsCapped: false, scraperLines: 0, first: Infinity, last: -Infinity };
        classes.set(cls.id, agg);
      }
      agg.count++;
      bump(agg.bySource, file.source);
      if (cls.detail) bump(agg.byDetail, cls.detail);
      if (e.target === "access") {
        bump(agg.byDirection, e.fields.direction ?? "unknown");
        const dst = destinationOf(e, resolve);
        bump(agg.byDestination, dst.label);
        if (dst.namespace) agg.namespaces.add(dst.namespace);
        const src = hostOf(e.fields["src.addr"]);
        if (src) {
          if (agg.sourceAddrs.size < (cls.id.startsWith("other:") ? MAX_DISTINCT_SOURCES_OTHER : MAX_DISTINCT_SOURCES)) agg.sourceAddrs.add(src);
          else if (!agg.sourceAddrs.has(src)) agg.sourceAddrsCapped = true;
        }
        if (fromScraper(e, resolve)) agg.scraperLines++;
      }
      const t = e.time ? Date.parse(e.time) : Number.NaN;
      if (Number.isFinite(t)) {
        if (t < agg.first) agg.first = t;
        if (t > agg.last) agg.last = t;
      }
    };
    try {
      const result = await store.scanFileLines(file.path, onLine);
      if (!result) {
        scan.failed.push({ path: file.path, error: "not in the archive" });
        continue;
      }
      stats.read++;
      stats.bytes += result.bytes;
      scan.longLines += result.longLines;
    } catch (e) {
      scan.failed.push({ path: file.path, error: e instanceof Error ? e.message : String(e) });
    }
    const last = lastTimed ? lineTime(lastTimed) : Number.NaN;
    if (Number.isFinite(first) && Number.isFinite(last)) spans.set(file.source, { first, last });
    const c = cc as (Omit<CniConnectHits, "infoSeen"> & { lastHitLine: number; lastStreamLine: number }) | undefined;
    if (c) cniConnect.set(file.source, { count: c.count, first: c.first, last: c.last, connectedAfter: c.lastStreamLine > c.lastHitLine, bursts: c.bursts, longestBurstMs: c.longestBurstMs, infoSeen });
  }
  const staleSources = new Set(stale.map((f) => `${f.namespace ?? ""}/${f.pod}`)).size;
  return { scan, classes, pods, staleFiles: stale.length, staleSources, spans, cniConnect };
}

import type { BugReportStore } from "../../archive/store.js";
import { tryParseJson } from "../../archive/parser.js";

// Envoy's admin /server_info (proxies/<ns>/<pod>/server_info): the worker thread count
// (command_line_options.concurrency), which sizes per-proxy memory, plus state and uptime.

export interface ServerInfo {
  /** Envoy worker threads; null when not listed. */
  concurrency: number | null;
  /** LIVE, DRAINING, PRE_INITIALIZING or INITIALIZING. */
  state: string | null;
  /** The Envoy release, e.g. 1.35.3, from `version` (<sha>/<release>/<status>/<type>/<ssl>). */
  envoyVersion: string | null;
  uptimeSeconds: number | null;
}

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

/** server_info as text (log lines ahead of the JSON are dropped) or parsed; null when it is not Envoy server_info. */
export function parseServerInfo(content: unknown): ServerInfo | null {
  const root = obj(typeof content === "string" ? tryParseJson(content) : content);
  if (!root) return null;
  const opts = obj(root.command_line_options);
  const concurrency = Number(opts?.concurrency);
  const version = typeof root.version === "string" ? root.version.split("/")[1] : undefined;
  const uptime = typeof root.uptime_current_epoch === "string" ? Number.parseFloat(root.uptime_current_epoch) : Number.NaN;
  const info: ServerInfo = {
    concurrency: opts?.concurrency !== undefined && Number.isFinite(concurrency) ? concurrency : null,
    state: typeof root.state === "string" ? root.state : null,
    envoyVersion: version && /^\d+\.\d+/.test(version) ? version : null,
    uptimeSeconds: Number.isFinite(uptime) ? uptime : null,
  };
  return Object.values(info).some((v) => v !== null) ? info : null;
}

/** A proxy's server_info from the archive; null when not collected or not parseable. */
export function proxyServerInfo(store: BugReportStore, namespace: string, pod: string): ServerInfo | null {
  const path = store.getProxySectionPath(namespace, pod, "server_info");
  if (!path || store.tooLargeToParse(path)) return null;
  return parseServerInfo(store.getProxyConfig(namespace, pod, "server_info"));
}

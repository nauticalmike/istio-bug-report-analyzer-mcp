export type LogLevel = "error" | "warn";

const ERROR_LEVELS = new Set(["error", "err", "fatal", "critical", "crit", "panic", "dpanic"]);
const WARN_LEVELS = new Set(["warn", "warning"]);

// Istio/ztunnel: "<RFC3339>\t<level>\t..." (ztunnel may use spaces and uppercase).
const ISTIO_RE = /^\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+([A-Za-z]+)(?:\s|$)/;
// Envoy native: "[<ts>][<thread>][<level>][<logger>] ..."
const ENVOY_RE = /^\[[^\]]+\](?:\[\d+\])?\[([a-z]+)\]/;
const JSON_RE = /"level"\s*:\s*"([A-Za-z]+)"/;
// klog: "E1020 20:23:09.123456 ..."
const KLOG_RE = /^([EWF])\d{4} \d{2}:\d{2}:\d{2}/;
const GO_CRASH_RE = /^(panic:|fatal error:)/;

function classify(level: string): LogLevel | null {
  const l = level.toLowerCase();
  if (ERROR_LEVELS.has(l)) return "error";
  if (WARN_LEVELS.has(l)) return "warn";
  return null;
}

// Classifies a line by its log-level field only, so messages that merely mention
// "error" (flags, config dumps, access logs) are not counted.
export function logLevel(line: string): LogLevel | null {
  const istio = ISTIO_RE.exec(line);
  if (istio) return classify(istio[1]);
  const envoy = ENVOY_RE.exec(line);
  if (envoy) return classify(envoy[1]);
  const json = JSON_RE.exec(line);
  if (json) return classify(json[1]);
  const klog = KLOG_RE.exec(line);
  if (klog) return klog[1] === "W" ? "warn" : "error";
  if (GO_CRASH_RE.test(line)) return "error";
  return null;
}

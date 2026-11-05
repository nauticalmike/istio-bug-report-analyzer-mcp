import type { BugReportStore } from "../../archive/store.js";
import { podLiveness, type NotEvaluated } from "../checks.js";

// The Prometheus text exposition format, as istiod writes it to istio/<ns>/<pod>/metrics and
// Envoy to proxies/<ns>/<pod>/stats/prometheus. One snapshot at collection time: counters
// are totals since the process started, not rates.

export interface PromSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

const NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*/;
const NUMBER_RE = /^(?:[+-]?Inf|NaN|[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)$/;

/** One sample line (`name{l="v",...} value [timestamp]`); null for comments, blanks and malformed lines. */
export function parsePrometheusLine(line: string): PromSample | null {
  const text = line.trim();
  if (text === "" || text.startsWith("#")) return null;
  const nameMatch = NAME_RE.exec(text);
  if (!nameMatch) return null;
  const name = nameMatch[0];
  let pos = name.length;
  const labels: Record<string, string> = {};
  if (text[pos] === "{") {
    pos++;
    for (;;) {
      while (text[pos] === " " || text[pos] === ",") pos++;
      if (text[pos] === "}") {
        pos++;
        break;
      }
      const key = /^[a-zA-Z_][a-zA-Z0-9_]*/.exec(text.slice(pos))?.[0];
      if (!key || text[pos + key.length] !== "=" || text[pos + key.length + 1] !== '"') return null;
      pos += key.length + 2;
      let value = "";
      for (;;) {
        const c = text[pos];
        if (c === undefined) return null;
        if (c === "\\") {
          const next = text[pos + 1];
          value += next === "n" ? "\n" : (next ?? "");
          pos += 2;
          continue;
        }
        pos++;
        if (c === '"') break;
        value += c;
      }
      labels[key] = value;
    }
  }
  const [valueText] = text.slice(pos).trim().split(/\s+/);
  if (!valueText || !NUMBER_RE.test(valueText)) return null;
  const value = valueText.endsWith("Inf") ? (valueText.startsWith("-") ? -Infinity : Infinity) : Number(valueText);
  return { name, labels, value };
}

/** Every sample in `text`, or only those whose name is in `names`. */
export function parsePrometheusText(text: string, names?: Iterable<string>): PromSample[] {
  const wanted = names ? new Set(names) : null;
  const out: PromSample[] = [];
  for (const line of text.split("\n")) {
    const sample = selected(line, wanted);
    if (sample) out.push(sample);
  }
  return out;
}

function selected(line: string, wanted: Set<string> | null): PromSample | null {
  // The name check first, on the raw line: most lines of a metrics file are not wanted.
  if (wanted) {
    const name = NAME_RE.exec(line.trimStart())?.[0];
    if (!name || !wanted.has(name)) return null;
  }
  return parsePrometheusLine(line);
}

/**
 * A metrics file of the archive streamed line by line (Envoy stats reach tens of MB), keeping
 * only the samples named in `names` (all when omitted). Null when the file is not in the
 * archive; rejects when it cannot be read.
 */
export async function scanPrometheusFile(store: BugReportStore, path: string, names?: Iterable<string>): Promise<PromSample[] | null> {
  const wanted = names ? new Set(names) : null;
  const out: PromSample[] = [];
  const stats = await store.scanFileLines(path, (line) => {
    const sample = selected(line, wanted);
    if (sample) out.push(sample);
  });
  return stats ? out : null;
}

/** The sum of the samples named `name` whose labels include `labels`; null when none matches. */
export function metricValue(samples: PromSample[], name: string, labels: Record<string, string> = {}): number | null {
  let sum: number | null = null;
  for (const s of samples) {
    if (s.name !== name) continue;
    if (!Object.entries(labels).every(([k, v]) => s.labels[k] === v)) continue;
    sum = (sum ?? 0) + s.value;
  }
  return sum;
}

export interface IstiodSamples {
  istiod: string;
  samples: PromSample[];
  /** Set only in the fallback: the istiod is no longer in the pod dump and no live one has a readable metrics file. */
  stale?: true;
}

/**
 * The named metrics of every istiod still in the pod dump with a metrics file
 * (istio/<ns>/<pod>/metrics), in archive order; those of istiods no longer in the pod dump
 * (podLiveness "stale") are read only when no live istiod has a readable one, and are then
 * flagged stale. Not evaluated when no istiod has one; an unreadable file is skipped.
 */
export async function istiodMetrics(store: BugReportStore, names: Iterable<string>): Promise<IstiodSamples[] | NotEvaluated> {
  const wanted = [...names];
  let failed = 0;
  const pods = store.getIstiodPods().filter((p) => store.hasFile(`istio/${p.namespace}/${p.podName}/metrics`));
  const live = pods.filter((p) => podLiveness(store, p.namespace, p.podName) !== "stale");
  const read = async (group: typeof pods, stale: boolean): Promise<IstiodSamples[]> => {
    const got: IstiodSamples[] = [];
    for (const pod of group) {
      try {
        const samples = await scanPrometheusFile(store, `istio/${pod.namespace}/${pod.podName}/metrics`, wanted);
        if (samples) got.push({ istiod: `${pod.namespace}/${pod.podName}`, samples, ...(stale ? { stale: true as const } : {}) });
      } catch {
        failed++;
      }
    }
    return got;
  };
  let out = await read(live, false);
  if (out.length === 0) out = await read(pods.filter((p) => !live.includes(p)), true);
  if (out.length > 0) return out;
  return { notEvaluated: failed > 0 ? `not evaluated: ${failed} istiod metrics file(s) could not be read` : "not evaluated: no istiod metrics were collected" };
}

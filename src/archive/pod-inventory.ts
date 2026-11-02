import { scanClusterDumpItems, type ItemScanInfo } from "./namespace-scan.js";
import type { HeapStats } from "./heap-guard.js";
import type { ParsedResource } from "../types.js";

/**
 * The live pods of the cluster dumps, reduced to what the completeness verdict and the
 * proxy-dir checks compare against: name, namespace, phase and whether an istio-proxy runs
 * in it. Built by one streaming item scan of the pod dumps (never the full parse), so the
 * answer is the same before and after another tool parsed the dumps, and memory stays small.
 */
export interface PodRecord {
  namespace: string;
  name: string;
  /** status.phase; Succeeded and Failed pods are not live. */
  phase: string | null;
  /** Has an istio-proxy container (or native-sidecar init container) that is not ztunnel's. */
  injected: boolean;
  /** The ztunnel or istio-cni-node DaemonSet pod this is, by name. */
  daemon: "ztunnel" | "cni" | null;
}

export interface PodInventory {
  /** False when no Pod was found in any pod dump: nothing can be compared. */
  available: boolean;
  /** Pods by "namespace/name". */
  pods: Map<string, PodRecord>;
  /**
   * Namespaces with any namespaced object in the pod dumps. A proxy dir elsewhere cannot be
   * judged: without cluster/k8s-resources, cluster/pods holds only the Istio namespace.
   */
  namespaces: Set<string>;
  /** False when cluster/k8s-resources gave no object, so the pod list is only cluster/pods. */
  wholeCluster: boolean;
  /**
   * "<file>: <reason>" for each pod dump the scan gave up on (YAML it does not model and too
   * large, or too large for the heap, to parse whole): the pod list lacks its pods.
   */
  gaveUp: string[];
  /** Parsed Pod items whose text passed the scan's `alsoKeep` test (none without one). */
  kept: ParsedResource[];
}

export interface PodScanOptions {
  /** Also parse and return (in `kept`) the Pod items whose raw text passes this test. */
  alsoKeep?: (itemText: string) => boolean;
  /** A whole parse of a dump already made (the cluster parse), by archive path, or null. */
  wholeParse?: (relativePath: string) => ParsedResource[] | null;
  heap?: HeapStats;
  maxWholeParseBytes?: number;
}

// Kubernetes generates pod-name suffixes from this alphabet (no vowels, no 0, 1 or 3).
const K8S = "[bcdfghjklmnpqrstvwxz2456789]";
export const ZTUNNEL_POD_RE = new RegExp(`^ztunnel-${K8S}{5}$`);
export const CNI_POD_RE = new RegExp(`^istio-cni-node-${K8S}{5}$`);

export function daemonKind(name: string): "ztunnel" | "cni" | null {
  if (ZTUNNEL_POD_RE.test(name)) return "ztunnel";
  if (CNI_POD_RE.test(name)) return "cni";
  return null;
}

export function isLive(p: PodRecord): boolean {
  return p.phase !== "Succeeded" && p.phase !== "Failed";
}

export const podKey = (namespace: string, name: string) => `${namespace}/${name}`;

/** A copy that shares no memory with the item text it was sliced from (which it would keep alive). */
const own = (v: string) => Buffer.from(v, "utf8").toString("utf8");

const unquote = (v: string) => v.trim().replace(/^(["'])(.*)\1$/, "$2");

/** Offset where a top-level `key:` line of a (dedented) List item starts, or -1. */
function topKey(text: string, key: string): number {
  const prefix = `${key}:`;
  if (text.startsWith(prefix)) return 0;
  const at = text.indexOf(`\n${prefix}`);
  return at === -1 ? -1 : at + 1;
}

/** The lines of a top-level `key:` block (up to the next line at column 0), or "" when it has none. */
function topBlock(text: string, key: string): string {
  const at = topKey(text, key);
  if (at === -1) return "";
  const start = text.indexOf("\n", at);
  if (start === -1) return "";
  let end = start;
  for (;;) {
    end = text.indexOf("\n", end + 1);
    if (end === -1) return text.slice(start + 1);
    const c = text.charCodeAt(end + 1);
    if (c !== 0x20 && c !== 0x0a && c !== 0x0d) return text.slice(start + 1, end);
  }
}

/** A scalar `key:` at the block's own indent (the indent of its first line). */
function blockScalar(block: string, key: string): string | null {
  let indent = 0;
  while (block.charCodeAt(indent) === 0x20) indent++;
  const prefix = `${" ".repeat(indent)}${key}:`;
  for (let at = 0; at !== -1 && at < block.length; ) {
    if (block.startsWith(prefix, at) && block.charCodeAt(at + indent) !== 0x20) {
      const end = block.indexOf("\n", at);
      const value = unquote(block.slice(at + prefix.length, end === -1 ? undefined : end).replace(/\s#.*$/, ""));
      return value ? own(value) : null;
    }
    at = block.indexOf("\n", at);
    if (at !== -1) at++;
  }
  return null;
}

// Anywhere in a Pod item: the container (and its status entry) or the ztunnel args/image.
const ISTIO_PROXY_RE = /(?:^|[ \t-])name:[ \t]*["']?istio-proxy["']?[ \t]*\r?$/m;
const ZTUNNEL_ARG_RE = /^\s*- ["']?ztunnel["']?\s*$/m;
const ZTUNNEL_IMAGE_RE = /image:\s*["']?[^\s"']*ztunnel[:@]/;

interface ItemSummary {
  kind: string | null;
  namespace: string | null;
  pod?: PodRecord;
}

/** Reads kind, namespace and (for a Pod) its record off a List item's YAML text, without parsing it. */
function summarizeText(text: string): ItemSummary {
  const kindAt = topKey(text, "kind");
  const kindEnd = kindAt === -1 ? -1 : text.indexOf("\n", kindAt);
  const kind = kindAt === -1 ? null : unquote(text.slice(kindAt + 5, kindEnd === -1 ? undefined : kindEnd).replace(/\s#.*$/, ""));
  const metadata = topBlock(text, "metadata");
  const namespace = blockScalar(metadata, "namespace");
  if (kind !== "Pod") return { kind, namespace };
  const name = blockScalar(metadata, "name");
  if (!name) return { kind, namespace };
  // The substring checks first: the regexes cost a scan of every line of every pod.
  const ztunnel = text.includes("ztunnel") && (ZTUNNEL_ARG_RE.test(text) || ZTUNNEL_IMAGE_RE.test(text));
  return {
    kind,
    namespace,
    pod: {
      namespace: namespace ?? "default",
      name,
      phase: blockScalar(topBlock(text, "status"), "phase"),
      injected: text.includes("istio-proxy") && ISTIO_PROXY_RE.test(text) && !ztunnel && !daemonKind(name),
      daemon: daemonKind(name),
    },
  };
}

type Obj = Record<string, unknown>;

/** The same summary from a parsed object (plain documents and dumps the scanner hands to the full parse). */
function summarizeObject(r: ParsedResource): ItemSummary {
  const kind = typeof r?.kind === "string" ? r.kind : null;
  const namespace = typeof r?.metadata?.namespace === "string" ? r.metadata.namespace : null;
  const name = r?.metadata?.name;
  if (kind !== "Pod" || typeof name !== "string") return { kind, namespace };
  const spec = (r.spec ?? {}) as Obj;
  const containers = [spec.containers, spec.initContainers].flatMap((c) => (Array.isArray(c) ? c : [])) as Obj[];
  const proxy = containers.find((c) => c?.name === "istio-proxy");
  const args = Array.isArray(proxy?.args) ? proxy.args : [];
  const ztunnel = args.includes("ztunnel") || (typeof proxy?.image === "string" && /ztunnel[:@]/.test(proxy.image));
  const phase = (r.status as Obj | undefined)?.phase;
  return {
    kind,
    namespace,
    pod: {
      namespace: namespace ?? "default",
      name,
      phase: typeof phase === "string" ? phase : null,
      injected: !!proxy && !ztunnel && !daemonKind(name),
      daemon: daemonKind(name),
    },
  };
}

/**
 * Scans the pod dumps item by item: each List item's text is summarized and dropped, so a
 * multi-GB cluster/k8s-resources costs a byte scan, not a parse. `files` maps an archive
 * path to its absolute path; `wholeCluster` is set when cluster/k8s-resources gave an object.
 */
export function scanPodInventory(files: { relativePath: string; absolutePath: string }[], opts: PodScanOptions = {}): PodInventory {
  const inventory: PodInventory = { available: false, pods: new Map(), namespaces: new Set(), wholeCluster: false, gaveUp: [], kept: [] };
  for (const file of files) {
    let objects = 0;
    const add = (s: ItemSummary) => {
      objects++;
      // Namespace objects are cluster-scoped: they say a namespace exists, not that its pods were dumped.
      if (s.namespace && s.kind !== "Namespace") inventory.namespaces.add(s.namespace);
      if (s.pod) {
        inventory.available = true;
        const key = podKey(s.pod.namespace, s.pod.name);
        if (!inventory.pods.has(key)) inventory.pods.set(key, s.pod);
      }
    };
    const info: ItemScanInfo = {};
    const parsed = scanClusterDumpItems(
      file.absolutePath,
      (text) => {
        // A dump the scanner hands to the full parse passes each object as JSON: keep it whole.
        if (text.startsWith("{")) return true;
        add(summarizeText(text));
        return opts.alsoKeep?.(text) ?? false;
      },
      { info, heap: opts.heap, maxWholeParseBytes: opts.maxWholeParseBytes, wholeParse: opts.wholeParse && (() => opts.wholeParse!(file.relativePath)) },
    );
    if (info.gaveUp) inventory.gaveUp.push(`${file.relativePath}: ${info.gaveUp}`);
    // Whole-parsed: every object. Item-scanned: plain documents, and the List items alsoKeep
    // passed (already summarized from their text; summarizing again changes nothing).
    for (const r of parsed) {
      add(summarizeObject(r));
      if (opts.alsoKeep && r?.kind === "Pod" && opts.alsoKeep(JSON.stringify(r))) inventory.kept.push(r);
    }
    if (file.relativePath === "cluster/k8s-resources" && objects > 0) inventory.wholeCluster = true;
  }
  return inventory;
}

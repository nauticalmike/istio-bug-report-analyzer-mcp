import { scanClusterDumpItems } from "./namespace-scan.js";
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

const unquote = (v: string) => v.trim().replace(/^(["'])(.*)\1$/, "$2");

/** The lines of a top-level `key:` block of a (dedented) List item, or "" when it has none. */
function topBlock(text: string, key: string): string {
  const m = new RegExp(`(?:^|\\n)${key}:[ \\t]*\\r?\\n`).exec(text);
  if (!m) return "";
  const start = m.index + m[0].length;
  // The block ends at the next line that starts at column 0.
  const end = /\n(?=\S)/.exec(text.slice(start));
  return text.slice(start, end ? start + end.index : text.length);
}

/** A scalar key at the block's own indent (the indent of its first line). */
function blockScalar(block: string, key: string): string | null {
  const indent = /^( *)/.exec(block)?.[1] ?? "";
  const m = new RegExp(`(?:^|\\n)${indent}${key}:[ \\t]*([^\\n#]+)`).exec(block);
  return m ? unquote(m[1]) || null : null;
}

const ISTIO_PROXY_RE = /^\s*(?:- )?name:\s*["']?istio-proxy["']?\s*$/m;
const ZTUNNEL_ARG_RE = /^\s*- ["']?ztunnel["']?\s*$/m;
const ZTUNNEL_IMAGE_RE = /image:\s*["']?[^\s"']*ztunnel[:@]/;

interface ItemSummary {
  kind: string | null;
  namespace: string | null;
  pod?: PodRecord;
}

/** Reads kind, namespace and (for a Pod) its record off a List item's YAML text, without parsing it. */
function summarizeText(text: string): ItemSummary {
  const kindLine = /(?:^|\n)kind:[ \t]*([^\n#]+)/.exec(text);
  const kind = kindLine ? unquote(kindLine[1]) : null;
  const metadata = topBlock(text, "metadata");
  const namespace = blockScalar(metadata, "namespace");
  if (kind !== "Pod") return { kind, namespace };
  const name = blockScalar(metadata, "name");
  if (!name) return { kind, namespace };
  const spec = topBlock(text, "spec");
  const ztunnel = ZTUNNEL_ARG_RE.test(spec) || ZTUNNEL_IMAGE_RE.test(spec);
  return {
    kind,
    namespace,
    pod: {
      namespace: namespace ?? "default",
      name,
      phase: blockScalar(topBlock(text, "status"), "phase"),
      injected: ISTIO_PROXY_RE.test(spec) && !ztunnel && !daemonKind(name),
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
export function scanPodInventory(files: { relativePath: string; absolutePath: string }[]): PodInventory {
  const inventory: PodInventory = { available: false, pods: new Map(), namespaces: new Set(), wholeCluster: false };
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
    const parsed = scanClusterDumpItems(file.absolutePath, (text) => {
      // A dump the scanner hands to the full parse passes each object as JSON: keep it whole.
      if (text.startsWith("{")) return true;
      add(summarizeText(text));
      return false;
    });
    for (const r of parsed) add(summarizeObject(r));
    if (file.relativePath === "cluster/k8s-resources" && objects > 0) inventory.wholeCluster = true;
  }
  return inventory;
}

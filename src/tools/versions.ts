import type { BugReportStore } from "../archive/store.js";
import { clientBehindControlPlane, findVersionSkew, releaseOf } from "../diagnostics/versions.js";
import type { ComponentVersion } from "../types.js";
import { imageTagNote } from "../archive/image-versions.js";


export function getVersions(store: BugReportStore) {
  // Falls back to pod image tags when the versions file is missing or has no versions.
  const versions = store.getEffectiveVersions();
  if (!versions) {
    return { content: [{ type: "text" as const, text: "No version information available." }] };
  }
  const FROM_IMAGES = imageTagNote(versions);
  const cpNote = versions.fromImages?.controlPlane ? FROM_IMAGES : "";
  const dpNote = versions.fromImages?.proxies ? FROM_IMAGES : "";
  // A count of 0 means the source did not record one.
  const counted = (list: ComponentVersion[], unit: (n: number) => string) =>
    list.map((v) => `  - ${v.version}${v.count > 0 ? ` (${v.count} ${unit(v.count)})` : ""}`);
  const proxies = () => "proxies";
  const pods = (n: number) => (n === 1 ? "pod" : "pods");

  const lines = [
    "=== Version Matrix ===",
    "",
    `Client Version: ${versions.clientVersion ?? "unknown"}`,
    "",
    "Control Plane Versions:",
    ...versions.controlPlaneVersions.map((v) => `  - ${v.version} (revision: ${v.revision})${cpNote}`),
  ];
  const errors = (versions.controlPlaneErrors ?? []).filter(
    (e) => !versions.controlPlaneVersions.some((v) => v.revision === e.revision),
  );
  if (errors.length > 0) {
    lines.push("", "Revisions without a control plane version:", ...errors.map((e) => `  - ${e.revision}: ${describeRevisionError(e.message)}`));
  }
  lines.push("", "Data Plane Versions:", ...counted(versions.proxyVersions, proxies).map((l) => `${l}${dpNote}`));
  if (versions.ztunnelVersions?.length) lines.push("", `ztunnel Versions:${FROM_IMAGES}`, ...counted(versions.ztunnelVersions, pods));
  if (versions.cniVersions?.length) lines.push("", `istio-cni Versions:${FROM_IMAGES}`, ...counted(versions.cniVersions, pods));

  // Same minor-level rule as DIAG-001: build suffixes (-solo, -distroless) and patch
  // differences are not skew.
  const skew = findVersionSkew(versions);
  if (skew.length > 0) {
    lines.push("", "⚠ VERSION SKEW DETECTED", ...skew.map((i) => `  - ${i.detail}`));
  } else {
    const releases = new Set([...versions.controlPlaneVersions, ...versions.proxyVersions].map((v) => releaseOf(v.version)));
    if (releases.size > 1) {
      const sorted = [...releases].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      lines.push("", `Patch-level differences only (supported): ${sorted.join(", ")}`);
    }
  }

  const behind = clientBehindControlPlane(versions);
  if (behind) {
    lines.push(
      "",
      `⚠ istioctl client ${behind.client} is older than the control plane (${behind.controlPlane}): it may not collect or parse everything the newer control plane exposes; re-collect the bug report with istioctl ${behind.controlPlane}.`,
    );
  }

  if (versions.raw) lines.push("", "Raw version output:", collapseMeshInfo(versions.raw));
  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}

function describeRevisionError(message: string): string {
  if (/no running Istio pods/i.test(message)) {
    return "no running istiod pods carry this revision (usually a revision tag or an idle revision; not missing data)";
  }
  return `could not be read (${message})`;
}

const SERVER_INFO_RE = /version\.ServerInfo\{[\s\S]*?\}\}/g;
// An entry of a multi-line (kr/pretty, istioctl up to ~1.19) MeshInfo ends on its own "    }," line.
const PRETTY_ENTRY_END_RE = /^ {4}\},?$/;

/** Identical ServerInfo entries of a one-line `%#v` MeshInfo, written once with a count. */
function collapseOneLine(line: string): string {
  const counts = new Map<string, number>();
  for (const m of line.matchAll(SERVER_INFO_RE)) counts.set(m[0], (counts.get(m[0]) ?? 0) + 1);
  if (counts.size === 0) return line;
  const entries = [...counts].map(([entry, n]) => (n > 1 ? `${entry} (x${n})` : entry));
  return `&version.MeshInfo{${entries.join(", ")}}`;
}

/** Identical entries of a multi-line MeshInfo (opening line, entries, closing "}"), written once with a count. */
function collapsePretty(block: string[]): string {
  const counts = new Map<string, number>();
  let entry: string[] = [];
  for (const line of block.slice(1, -1)) {
    entry.push(line);
    if (!PRETTY_ENTRY_END_RE.test(line)) continue;
    const text = entry.join("\n");
    counts.set(text, (counts.get(text) ?? 0) + 1);
    entry = [];
  }
  const entries = [...counts].map(([text, n]) => (n > 1 ? `${text} (x${n})` : text));
  return [block[0], ...entries, ...entry, block[block.length - 1]].join("\n");
}

/**
 * The lines of the versions file with each multi-line MeshInfo (from its opening line to the
 * "}" at column 0) joined into one element, so a block is handled like a one-line MeshInfo.
 */
function logicalLines(raw: string): string[] {
  const lines = raw.split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/^&version\.MeshInfo\{\s*$/.test(line)) {
      out.push(line);
      continue;
    }
    const end = lines.findIndex((l, j) => j > i && l === "}");
    if (end === -1) {
      out.push(line);
      continue;
    }
    out.push(collapsePretty(lines.slice(i, end + 1)));
    i = end;
  }
  return out;
}

/**
 * The raw versions file with each MeshInfo's identical istiod entries written once with a
 * count, and revisions whose (collapsed) MeshInfo is identical merged into one block.
 * A large control plane otherwise prints one ServerInfo per istiod pod per revision. Both
 * the one-line `%#v` MeshInfo and the multi-line kr/pretty one of older istioctl are handled.
 */
export function collapseMeshInfo(raw: string): string {
  if (!raw.includes("MeshInfo{")) return raw;
  const collapseLine = (line: string): string => {
    if (!line.includes("MeshInfo{")) return line;
    return line.includes("\n") ? line : collapseOneLine(line);
  };

  // Group "Revision X:" + MeshInfo pairs by their collapsed MeshInfo, keeping first-seen order.
  const lines = logicalLines(raw);
  const out: string[] = [];
  const groups = new Map<string, { revisions: string[]; index: number }>();
  for (let i = 0; i < lines.length; i++) {
    const rev = /^Revision (.+?):\s*$/.exec(lines[i]);
    const next = lines[i + 1];
    if (rev && next?.includes("MeshInfo{")) {
      const block = collapseLine(next);
      const group = groups.get(block);
      if (group) {
        group.revisions.push(rev[1]);
        // Drop the blank separator that followed this block.
        if (lines[i + 2] === "") i++;
      } else {
        groups.set(block, { revisions: [rev[1]], index: out.length });
        out.push(lines[i], block);
      }
      i++;
      continue;
    }
    out.push(collapseLine(lines[i]));
  }
  for (const { revisions, index } of groups.values()) {
    if (revisions.length > 1) out[index] = `Revisions ${revisions.join(", ")} (same MeshInfo, x${revisions.length}):`;
  }
  return out.join("\n");
}

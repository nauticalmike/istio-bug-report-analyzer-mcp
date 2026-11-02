import type { ComponentVersion, VersionInfo } from "../types.js";

export interface Minor {
  major: number;
  minor: number;
}

export interface VersionIssue {
  kind: "data-plane-ahead" | "data-plane-behind" | "unsupported-skew" | "unsupported-version";
  detail: string;
}

export function parseMinor(version: string | null | undefined): Minor | null {
  const match = version?.match(/(\d+)\.(\d+)/);
  return match ? { major: Number(match[1]), minor: Number(match[2]) } : null;
}

function label(m: Minor): string {
  return `${m.major}.${m.minor}`;
}

function distance(a: Minor, b: Minor): number {
  return (a.major - b.major) * 1000 + (a.minor - b.minor);
}

const FROM_IMAGES = " [versions from pod image tags]";

// Istio allows the control plane to be one minor ahead of the data plane, never behind.
// A proxy matching any control plane revision's minor is not skewed (canary upgrades).
// ztunnel and istio-cni follow the same rule against istiod.
export function findVersionSkew(versions: VersionInfo | null): VersionIssue[] {
  if (!versions) return [];
  const cpMinors = versions.controlPlaneVersions
    .map((v) => parseMinor(v.version))
    .filter((m): m is Minor => m !== null);
  if (cpMinors.length === 0) return [];

  const proxiesFromImages = versions.fromImages?.controlPlane || versions.fromImages?.proxies;
  const groups: { prefix: string; unit: [string, string]; list: ComponentVersion[]; note: string }[] = [
    { prefix: "", unit: ["proxy", "proxies"], list: versions.proxyVersions, note: proxiesFromImages ? FROM_IMAGES : "" },
    { prefix: "ztunnel: ", unit: ["pod", "pods"], list: versions.ztunnelVersions ?? [], note: FROM_IMAGES },
    { prefix: "istio-cni: ", unit: ["pod", "pods"], list: versions.cniVersions ?? [], note: FROM_IMAGES },
  ];

  const issues: VersionIssue[] = [];
  for (const { prefix, unit, list, note } of groups) {
    for (const component of list) {
      const dp = parseMinor(component.version);
      if (!dp) continue;
      const gaps = cpMinors.map((cp) => distance(cp, dp));
      if (gaps.includes(0)) continue;

      const closest = gaps.reduce((best, g) =>
        Math.abs(g) < Math.abs(best) || (Math.abs(g) === Math.abs(best) && g > 0) ? g : best,
      );
      const cp = cpMinors[gaps.indexOf(closest)];
      const who = component.count > 0 ? `${component.count} ${component.count === 1 ? unit[0] : unit[1]}` : unit[1];
      const subject = `${prefix}${who} on ${component.version}, control plane ${label(cp)}`;
      if (closest < 0) {
        issues.push({ kind: "data-plane-ahead", detail: `${subject}: data plane is ahead of the control plane (unsupported)${note}` });
      } else if (closest > 1) {
        issues.push({ kind: "unsupported-skew", detail: `${subject}: ${closest} minors behind (only 1 is supported)${note}` });
      } else {
        issues.push({ kind: "data-plane-behind", detail: `${subject}: 1 minor behind (supported, upgrade ${unit[1] === "proxies" ? "proxies" : "it"})${note}` });
      }
    }
  }
  return issues;
}

/**
 * Community builds are checked against the upstream window; `-solo` builds against Solo's
 * (longer, n-4) window when one is given, and are skipped otherwise.
 */
export function findUnsupportedVersions(
  versions: VersionInfo | null,
  supported: string[],
  supportedSolo?: string[],
): VersionIssue[] {
  if (!versions) return [];
  const checks: { role: string; version: string | null }[] = [
    { role: "client (istioctl)", version: versions.clientVersion },
    ...versions.controlPlaneVersions.map((v) => ({ role: `control plane (${v.revision})`, version: v.version })),
  ];

  const issues: VersionIssue[] = [];
  for (const { role, version } of checks) {
    const solo = version?.includes("-solo") ?? false;
    if (solo && !supportedSolo) continue;
    const window = solo ? supportedSolo! : supported;
    const m = parseMinor(version);
    if (!m || window.includes(label(m))) continue;
    // A minor newer than the window is newer than our data, not end of life.
    const newest = window.map(parseMinor).filter((w): w is Minor => w !== null).sort((a, b) => distance(b, a))[0];
    if (newest && distance(m, newest) > 0) continue;
    const scope = solo ? "Solo distribution of Istio minor" : "Istio minor";
    issues.push({
      kind: "unsupported-version",
      detail: `${role} ${version} is not a supported ${scope} (supported: ${window.join(", ")})`,
    });
  }
  return issues;
}

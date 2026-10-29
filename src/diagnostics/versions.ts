import type { VersionInfo } from "../types.js";

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

// Istio allows the control plane to be one minor ahead of the data plane, never behind.
// A proxy matching any control plane revision's minor is not skewed (canary upgrades).
export function findVersionSkew(versions: VersionInfo | null): VersionIssue[] {
  if (!versions) return [];
  const cpMinors = versions.controlPlaneVersions
    .map((v) => parseMinor(v.version))
    .filter((m): m is Minor => m !== null);
  if (cpMinors.length === 0) return [];

  const issues: VersionIssue[] = [];
  for (const proxy of versions.proxyVersions) {
    const dp = parseMinor(proxy.version);
    if (!dp) continue;
    const gaps = cpMinors.map((cp) => distance(cp, dp));
    if (gaps.includes(0)) continue;

    const closest = gaps.reduce((best, g) =>
      Math.abs(g) < Math.abs(best) || (Math.abs(g) === Math.abs(best) && g > 0) ? g : best,
    );
    const cp = cpMinors[gaps.indexOf(closest)];
    const proxies = proxy.count > 0 ? `${proxy.count} prox${proxy.count === 1 ? "y" : "ies"}` : "proxies";
    const subject = `${proxies} on ${proxy.version}, control plane ${label(cp)}`;
    if (closest < 0) {
      issues.push({ kind: "data-plane-ahead", detail: `${subject}: data plane is ahead of the control plane (unsupported)` });
    } else if (closest > 1) {
      issues.push({ kind: "unsupported-skew", detail: `${subject}: ${closest} minors behind (only 1 is supported)` });
    } else {
      issues.push({ kind: "data-plane-behind", detail: `${subject}: 1 minor behind (supported, upgrade proxies)` });
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

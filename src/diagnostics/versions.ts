import type { ComponentVersion, VersionInfo } from "../types.js";

export interface Minor {
  major: number;
  minor: number;
}

export interface VersionIssue {
  kind: "data-plane-ahead" | "data-plane-behind" | "unsupported-skew" | "unsupported-version";
  detail: string;
  severity?: "warning" | "info";
}

export function parseMinor(version: string | null | undefined): Minor | null {
  const match = version?.match(/(\d+)\.(\d+)/);
  return match ? { major: Number(match[1]), minor: Number(match[2]) } : null;
}

/** The release part of a version ("1.31.2-solo", "1.31.2-distroless" -> "1.31.2"); the input when it has none. */
export function releaseOf(version: string): string {
  return /^\d+\.\d+(?:\.\d+)?/.exec(version)?.[0] ?? version;
}

/**
 * The istioctl client minor is older than the newest control plane minor: the bug report
 * may miss or misread what the newer control plane exposes. Null when not older or unknown.
 */
export function clientBehindControlPlane(versions: VersionInfo | null): { client: string; controlPlane: string } | null {
  const client = parseMinor(versions?.clientVersion);
  const newest = (versions?.controlPlaneVersions ?? [])
    .map((v) => parseMinor(v.version))
    .filter((m): m is Minor => m !== null)
    .sort((a, b) => distance(b, a))[0];
  if (!client || !newest || distance(newest, client) <= 0) return null;
  return { client: versions!.clientVersion!, controlPlane: label(newest) };
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

export interface SupportDates {
  /** When the archive was captured; support is judged as of this day. Unset: today's windows, reported as info only. */
  asOf?: Date;
  /** Where asOf came from, as shown in the finding (default: the newest log timestamp in the archive). */
  asOfSource?: string;
  /** Upstream end-of-life day (YYYY-MM-DD) per minor that has left the supported list. */
  endOfLife?: Record<string, string>;
  /** Upstream release day (YYYY-MM-DD) per minor. */
  released?: Record<string, string>;
}

function newestMinor(minors: string[]): Minor | undefined {
  return minors.map(parseMinor).filter((w): w is Minor => w !== null).sort((a, b) => distance(b, a))[0];
}

function sortMinors(minors: Iterable<string>): string[] {
  return [...new Set(minors)].sort((a, b) => distance(parseMinor(a)!, parseMinor(b)!));
}

/**
 * The support window on `day`. `current` is today's window. Upstream: today's minors plus
 * those whose end of life was on or after the day. Solo (n-4): the four minors before the
 * newest one released by the day, unless that is already today's newest.
 */
function windowOn(current: string[], solo: boolean, day: string, dates: SupportDates): string[] {
  const releasedBy = (m: string) => !dates.released?.[m] || dates.released[m] <= day;
  if (!solo) {
    const stillSupported = Object.entries(dates.endOfLife ?? {}).filter(([m, eol]) => eol >= day && releasedBy(m)).map(([m]) => m);
    return sortMinors([...current.filter(releasedBy), ...stillSupported]);
  }
  const n = newestMinor(Object.keys(dates.released ?? {}).filter((m) => dates.released![m] <= day));
  const today = newestMinor(current);
  if (!n || (today && distance(n, today) >= 0)) return current;
  return Array.from({ length: 5 }, (_, i) => n.minor - 4 + i).filter((minor) => minor >= 0).map((minor) => `${n.major}.${minor}`);
}

/**
 * Community builds are checked against the upstream window; `-solo` builds against Solo's
 * (longer, n-4) window when one is given, and are skipped otherwise. With `dates.asOf`
 * (the capture date) the windows are those of that day. An unsupported istioctl client
 * alone is info (it only affects collection); an unsupported control plane is a warning.
 * Without a capture date every issue is info: today's window may postdate the archive.
 */
export function findUnsupportedVersions(
  versions: VersionInfo | null,
  supported: string[],
  supportedSolo?: string[],
  dates: SupportDates = {},
): VersionIssue[] {
  if (!versions) return [];
  const checks: { role: string; version: string | null; severity: "info" | "warning" }[] = [
    { role: "client (istioctl)", version: versions.clientVersion, severity: "info" },
    ...versions.controlPlaneVersions.map((v) => ({ role: `control plane (${v.revision})`, version: v.version, severity: "warning" as const })),
  ];
  const day = dates.asOf?.toISOString().slice(0, 10);

  const issues: VersionIssue[] = [];
  for (const { role, version, severity } of checks) {
    const solo = version?.includes("-solo") ?? false;
    if (solo && !supportedSolo) continue;
    const window = day ? windowOn(solo ? supportedSolo! : supported, solo, day, dates) : solo ? supportedSolo! : supported;
    const m = parseMinor(version);
    if (!m || window.includes(label(m))) continue;
    // A minor newer than the window is newer than our data, not end of life.
    const newest = newestMinor(window);
    if (newest && distance(m, newest) > 0) continue;
    const scope = solo ? "Solo distribution of Istio minor" : "Istio minor";
    const clientOnly = severity === "info" ? "; istioctl only, the mesh is not affected: collect with a supported istioctl" : "";
    const source = dates.asOfSource ?? "the newest log timestamp in the archive";
    const detail = day
      ? `${role} ${version} was not a supported ${scope} on ${day} (capture date, ${source}; supported then: ${window.join(", ")}${clientOnly})`
      : `${role} ${version} is not a supported ${scope} (supported: ${window.join(", ")}; as of today: no capture date found in the archive${clientOnly})`;
    issues.push({ kind: "unsupported-version", detail, severity: day ? severity : "info" });
  }
  return issues;
}

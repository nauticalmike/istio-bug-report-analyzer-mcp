// Only node: imports, so the exit-cleanup path can be exercised in a child process from the .ts source.
import { readFileSync, rmSync } from "node:fs";
import { hostname } from "node:os";
import { lstat, mkdtemp, open, readFile, readdir, realpath, rm, stat, statfs, writeFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";

export const EXTRACT_DIR_PREFIX = "bug-report-extract-";
/**
 * Written into every extraction dir with the creating process's pid, host name and (on Linux)
 * boot id, so a later server can tell its own leftovers (from a crash or SIGKILL) from
 * anything else named like them, and a pid of another host (a shared /tmp) or of an earlier
 * boot from a live process here. The archive index skips it.
 */
export const EXTRACT_MARKER_FILE = ".istio-bug-report-analyzer-owner";

// Bug-report archives are mostly text and compress well; assume they expand at most this much.
const MAX_EXPANSION_RATIO = 30;
// gzip records the expanded size modulo 2^32 in its last four bytes (ISIZE).
const ISIZE_MODULO = 2 ** 32;
// Headroom over the expanded size: tar headers, filesystem blocks, other writers.
const SPACE_MARGIN_FRACTION = 0.05;
const SPACE_MARGIN_MIN_BYTES = 64 * 2 ** 20;

export interface SizeEstimate {
  compressedBytes: number;
  /** Smallest expanded size consistent with the gzip trailer; exact when `exact`. */
  expandedBytes: number;
  /** Largest plausible expanded size; equals expandedBytes when `exact`. */
  upperBytes: number;
  /** False when the archive may expand past 4 GiB, where the 32-bit trailer wraps. */
  exact: boolean;
}

/**
 * Estimates the extracted size of a .tar.gz from its gzip trailer, without decompressing.
 * `compressedBytes` overrides the file size (tests).
 */
export async function estimateExpandedSize(archivePath: string, opts: { compressedBytes?: number } = {}): Promise<SizeEstimate> {
  const fileBytes = (await stat(archivePath)).size;
  const compressedBytes = opts.compressedBytes ?? fileBytes;
  const upperBound = compressedBytes * MAX_EXPANSION_RATIO;

  const isize = await readGzipIsize(archivePath, fileBytes);
  if (isize === null) {
    return { compressedBytes, expandedBytes: compressedBytes, upperBytes: upperBound, exact: false };
  }
  // A tar.gz never shrinks on expansion, so add wraps until the size is at least the compressed size.
  let expandedBytes = isize;
  while (expandedBytes < compressedBytes) expandedBytes += ISIZE_MODULO;
  const exact = upperBound < ISIZE_MODULO;
  return { compressedBytes, expandedBytes, upperBytes: exact ? expandedBytes : Math.max(expandedBytes, upperBound), exact };
}

async function readGzipIsize(archivePath: string, fileBytes: number): Promise<number | null> {
  if (fileBytes < 18) return null; // smaller than a gzip header plus trailer
  const fh = await open(archivePath, "r");
  try {
    const magic = Buffer.alloc(2);
    await fh.read(magic, 0, 2, 0);
    if (magic[0] !== 0x1f || magic[1] !== 0x8b) return null;
    const trailer = Buffer.alloc(4);
    await fh.read(trailer, 0, 4, fileBytes - 4);
    return trailer.readUInt32LE(0);
  } finally {
    await fh.close();
  }
}

/** Bytes available to this user on the filesystem holding `dir`. */
export async function freeBytes(dir: string): Promise<number> {
  const s = await statfs(dir);
  return s.bavail * s.bsize;
}

export interface SpaceCheck {
  ok: boolean;
  /** Why extraction is refused (ok: false) or a warning to show (ok: true). */
  message?: string;
}

function formatGB(bytes: number): string {
  return `${(bytes / 1e9).toFixed(1)} GB`;
}

const SPACE_HINT =
  "Free some space, pass extract_dir pointing at a larger volume, or extract the archive yourself and load the directory.";

export function checkFreeSpace(est: SizeEstimate, free: number, dir: string, archive: string): SpaceCheck {
  const margin = Math.max(SPACE_MARGIN_MIN_BYTES, est.expandedBytes * SPACE_MARGIN_FRACTION);
  if (free < est.expandedBytes + margin) {
    return {
      ok: false,
      message:
        `Not enough free space in ${dir} to extract ${archive}: it expands to ${est.exact ? "" : "at least "}~${formatGB(est.expandedBytes)} ` +
        `and ${formatGB(free)} is free. ${SPACE_HINT}`,
    };
  }
  if (!est.exact && free < est.upperBytes) {
    return {
      ok: true,
      message:
        `${archive} may expand past 4 GiB, so its size cannot be read exactly: it may need up to ~${formatGB(est.upperBytes)} ` +
        `and ${formatGB(free)} is free in ${dir}. If extraction runs out of space: ${SPACE_HINT}`,
    };
  }
  return { ok: true };
}

type ExitTarget = Pick<NodeJS.EventEmitter, "on"> & { exit: (code?: number) => void };

/**
 * Directories this process extracted archives into. Only directories created through
 * create() are ever deleted, so a directory the user loaded is never touched. A directory
 * is deleted on release only once no attached owner (store) reads from it any more.
 */
export class ExtractionTracker {
  private readonly owned = new Set<string>();
  private readonly byOwner = new WeakMap<object, string>();
  /** Owners attached per directory. */
  private readonly holders = new Map<string, number>();

  get size(): number {
    return this.owned.size;
  }

  /** A new `bug-report-extract-*` directory inside `parent`, holding only the ownership marker. */
  async create(parent: string): Promise<string> {
    const dir = await mkdtemp(join(parent, EXTRACT_DIR_PREFIX));
    this.owned.add(dir);
    try {
      await writeFile(join(dir, EXTRACT_MARKER_FILE), markerText(process.pid, thisHost()));
    } catch (e) {
      await this.remove(dir);
      throw e;
    }
    return dir;
  }

  owns(dir: string): boolean {
    return this.owned.has(dir);
  }

  /** The tracked directory that is `path` or contains it (symlinks resolved), if any. */
  async containing(path: string): Promise<string | undefined> {
    const candidates = new Set([resolve(path)]);
    const real = await realpath(path).catch(() => null);
    if (real) candidates.add(real);
    for (const dir of this.owned) {
      const dirs = new Set([dir]);
      const realDir = await realpath(dir).catch(() => null);
      if (realDir) dirs.add(realDir);
      for (const d of dirs) for (const p of candidates) if (p === d || p.startsWith(d + sep)) return dir;
    }
    return undefined;
  }

  /** Deletes `dir` if this tracker created it and no owner holds it; returns whether it did. */
  async remove(dir: string): Promise<boolean> {
    if (!this.owned.has(dir) || (this.holders.get(dir) ?? 0) > 0) return false;
    await rm(dir, { recursive: true, force: true });
    this.owned.delete(dir);
    return true;
  }

  /** Ties a created directory to the object (a store) that reads from it. */
  attach(owner: object, dir: string): void {
    if (!this.owned.has(dir) || this.byOwner.get(owner) === dir) return;
    this.byOwner.set(owner, dir);
    this.holders.set(dir, (this.holders.get(dir) ?? 0) + 1);
  }

  /** Detaches `owner`, deleting its directory once no other owner holds it. */
  async release(owner: object): Promise<void> {
    const dir = this.byOwner.get(owner);
    if (!dir) return;
    this.byOwner.delete(owner);
    const left = (this.holders.get(dir) ?? 1) - 1;
    if (left > 0) {
      this.holders.set(dir, left);
      return;
    }
    this.holders.delete(dir);
    await this.remove(dir);
  }

  /** Synchronous, for the process `exit` event, where async work never runs. */
  removeAllSync(): void {
    for (const dir of this.owned) {
      try {
        rmSync(dir, { recursive: true, force: true });
        this.owned.delete(dir);
        this.holders.delete(dir);
      } catch {
        // Best effort at exit: nothing can be reported any more.
      }
    }
  }
}

/** The machine a marker was written on: host name and, where the kernel gives one cheaply, boot id. */
export interface HostIdentity {
  hostname: string;
  bootId: string | null;
}

let cachedHost: HostIdentity | undefined;

/** This machine's identity (Linux boot id from /proc; null elsewhere, where it costs a subprocess). */
export function thisHost(): HostIdentity {
  if (!cachedHost) {
    let bootId: string | null = null;
    try {
      bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() || null;
    } catch {
      // Not Linux, or no /proc.
    }
    cachedHost = { hostname: hostname(), bootId };
  }
  return cachedHost;
}

function markerText(pid: number, host: HostIdentity): string {
  return [String(pid), `host=${host.hostname}`, ...(host.bootId ? [`boot=${host.bootId}`] : []), ""].join("\n");
}

/** Whether a process with this pid exists (EPERM: it does, owned by another user). */
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Deletes `bug-report-extract-*` directories in `parent` left by a server that died
 * without cleaning up (SIGKILL, crash). Only real directories (not symlinks) that hold our
 * marker with a valid pid, written on this host, where that process is gone (or the marker is
 * from an earlier boot) are deleted; anything else, including a directory without the marker
 * or one another host wrote, is left alone. Markers without a host line (older servers) are
 * judged by pid alone. Returns the deleted paths.
 */
export async function sweepStaleExtractions(
  parent: string,
  isAlive: (pid: number) => boolean = processAlive,
  self: HostIdentity = thisHost(),
): Promise<string[]> {
  const names = await readdir(parent).catch(() => [] as string[]);
  const removed: string[] = [];
  for (const name of names) {
    if (!name.startsWith(EXTRACT_DIR_PREFIX)) continue;
    const dir = join(parent, name);
    try {
      if (!(await lstat(dir)).isDirectory()) continue;
      const marker = join(dir, EXTRACT_MARKER_FILE);
      if (!(await lstat(marker)).isFile()) continue;
      const [pidLine, ...fields] = (await readFile(marker, "utf8")).trim().split("\n");
      if (!/^\d+$/.test(pidLine)) continue;
      const field = (key: string) => fields.find((f) => f.startsWith(`${key}=`))?.slice(key.length + 1);
      // A pid means nothing on another host (a /tmp shared across machines or containers).
      const host = field("host");
      if (host !== undefined && host !== self.hostname) continue;
      // Written in an earlier boot: its process is gone even if the pid is in use again.
      const boot = field("boot");
      const earlierBoot = boot !== undefined && self.bootId !== null && boot !== self.bootId;
      const pid = Number(pidLine);
      if (!earlierBoot && (pid === process.pid || isAlive(pid))) continue;
      await rm(dir, { recursive: true, force: true });
      removed.push(dir);
    } catch {
      // Unreadable, or removed meanwhile: leave it.
    }
  }
  return removed;
}

/** The tracker the server uses for every archive it extracts. */
export const extractionTracker = new ExtractionTracker();

const SIGNAL_EXIT_CODES = { SIGINT: 130, SIGTERM: 143, SIGHUP: 129 } as const;

/**
 * Deletes extracted directories when the process exits, including on SIGINT, SIGTERM and
 * SIGHUP. A signal handler replaces Node's default of exiting, so it exits with 128+signal.
 */
export function installExitCleanup(tracker: ExtractionTracker, target: ExitTarget = process): void {
  target.on("exit", () => tracker.removeAllSync());
  for (const [signal, code] of Object.entries(SIGNAL_EXIT_CODES)) {
    target.on(signal, () => {
      tracker.removeAllSync();
      target.exit(code);
    });
  }
}

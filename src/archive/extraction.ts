// Only node: imports, so the exit-cleanup path can be exercised in a child process from the .ts source.
import { readdirSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { hostname } from "node:os";
import { lstat, mkdtemp, open, readFile, readdir, realpath, rename, rm, stat, statfs, writeFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";

export const EXTRACT_DIR_PREFIX = "bug-report-extract-";
/** A doomed extraction dir is renamed to this prefix plus its name, then deleted in the background. */
const DELETING_PREFIX = ".deleting-";
/**
 * Written into every extraction dir with the creating process's pid, host name and (on Linux)
 * boot id and pid namespace, so a later server can tell its own leftovers (from a crash or
 * SIGKILL) from anything else named like them, and a pid of another host (a shared /tmp),
 * another pid namespace (a container sharing the host name) or an earlier boot from a live
 * process here. The archive index skips it.
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
 * Deletes an extraction dir with its marker last: every other child first, then the marker,
 * then the (empty) dir. A delete cut short (crash, SIGKILL, a child that cannot be removed)
 * thus leaves the marker in place, and the next startup sweep, which only touches marked dirs,
 * finishes it. A plain recursive rm may take the marker first and leak an unmarked dir forever.
 * Rejects (leaving the marker) when a child cannot be removed.
 */
export async function removeMarkedDir(dir: string): Promise<void> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
    throw e;
  }
  for (const name of names) if (name !== EXTRACT_MARKER_FILE) await rm(join(dir, name), { recursive: true, force: true });
  await rm(join(dir, EXTRACT_MARKER_FILE), { force: true });
  await rm(dir, { recursive: true, force: true });
}

/** removeMarkedDir, synchronous (for the process exit event). */
function removeMarkedDirSync(dir: string): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
    throw e;
  }
  for (const name of names) if (name !== EXTRACT_MARKER_FILE) rmSync(join(dir, name), { recursive: true, force: true });
  rmSync(join(dir, EXTRACT_MARKER_FILE), { force: true });
  rmSync(dir, { recursive: true, force: true });
}

/** A path inside a dir the startup sweep renamed for deletion (`.deleting-bug-report-extract-*`). */
export function insideSweptDir(path: string): boolean {
  return resolve(path).split(sep).some((part) => part.startsWith(DELETING_PREFIX + EXTRACT_DIR_PREFIX));
}

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
  /** Directories whose rm is under way: still owned (removeAllSync covers them), never handed out. */
  private readonly removing = new Set<string>();
  private readonly removeDir: (dir: string) => Promise<void>;

  /** `removeDir` replaces the marker-last delete (tests). */
  constructor(opts: { removeDir?: (dir: string) => Promise<void> } = {}) {
    this.removeDir = opts.removeDir ?? removeMarkedDir;
  }

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
    return this.find(path, false);
  }

  /** The tracked directory being deleted that is `path` or contains it, if any: a load refuses it. */
  async removingContaining(path: string): Promise<string | undefined> {
    return this.find(path, true);
  }

  private async find(path: string, removing: boolean): Promise<string | undefined> {
    const candidates = new Set([resolve(path)]);
    const real = await realpath(path).catch(() => null);
    if (real) candidates.add(real);
    for (const dir of this.owned) {
      if (this.removing.has(dir) !== removing) continue;
      const dirs = new Set([dir]);
      const realDir = await realpath(dir).catch(() => null);
      if (realDir) dirs.add(realDir);
      for (const d of dirs) for (const p of candidates) if (p === d || p.startsWith(d + sep)) return dir;
    }
    return undefined;
  }

  /** Deletes `dir` if this tracker created it and no owner holds it; returns whether it did. */
  async remove(dir: string): Promise<boolean> {
    if (!this.owned.has(dir) || this.removing.has(dir) || (this.holders.get(dir) ?? 0) > 0) return false;
    // Marked before the first await: a lookup meanwhile must not hold a dir being deleted.
    this.removing.add(dir);
    try {
      await this.removeDir(dir);
      this.owned.delete(dir);
      return true;
    } finally {
      this.removing.delete(dir);
    }
  }

  /**
   * The tracked directory that is `path` or contains it, held for the caller from the moment
   * it is found: a load that reads it can then not lose it to another load that releases its
   * last owner meanwhile. The returned `drop` gives the hold back (after attach() on success,
   * or on failure), deleting the directory when nothing else holds it.
   */
  async holdContaining(path: string): Promise<{ dir: string; drop: () => Promise<void> } | undefined> {
    const dir = await this.containing(path);
    // Synchronously after the lookup, so no release can run in between.
    if (!dir || !this.owned.has(dir) || this.removing.has(dir)) return undefined;
    this.holders.set(dir, (this.holders.get(dir) ?? 0) + 1);
    let dropped = false;
    const drop = async () => {
      if (dropped) return;
      dropped = true;
      const left = (this.holders.get(dir) ?? 1) - 1;
      if (left > 0) {
        this.holders.set(dir, left);
        return;
      }
      this.holders.delete(dir);
      await this.remove(dir);
    };
    return { dir, drop };
  }

  /** Ties a created directory to the object (a store) that reads from it. */
  attach(owner: object, dir: string): void {
    if (!this.owned.has(dir) || this.removing.has(dir) || this.byOwner.get(owner) === dir) return;
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
        removeMarkedDirSync(dir);
        this.owned.delete(dir);
        this.holders.delete(dir);
      } catch {
        // Best effort at exit: nothing can be reported any more.
      }
    }
  }
}

/**
 * The machine a marker was written on: host name and, where the kernel gives them cheaply,
 * boot id and pid namespace (Linux /proc). macOS has neither: pid and host name only.
 */
export interface HostIdentity {
  hostname: string;
  bootId: string | null;
  /** readlink /proc/self/ns/pid, e.g. "pid:[4026531836]"; null or absent where unknown. */
  pidNs?: string | null;
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
    let pidNs: string | null = null;
    try {
      pidNs = readlinkSync("/proc/self/ns/pid").trim() || null;
    } catch {
      // Not Linux, or no /proc.
    }
    cachedHost = { hostname: hostname(), bootId, pidNs };
  }
  return cachedHost;
}

function markerText(pid: number, host: HostIdentity): string {
  return [
    String(pid),
    `host=${host.hostname}`,
    ...(host.bootId ? [`boot=${host.bootId}`] : []),
    ...(host.pidNs ? [`pidns=${host.pidNs}`] : []),
    "",
  ].join("\n");
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

/** Our marker's fields, or null when `dir` is not a real directory holding a valid marker. */
async function readMarker(dir: string): Promise<{ pid: number; field: (key: string) => string | undefined } | null> {
  if (!(await lstat(dir)).isDirectory()) return null;
  const marker = join(dir, EXTRACT_MARKER_FILE);
  if (!(await lstat(marker)).isFile()) return null;
  const [pidLine, ...fields] = (await readFile(marker, "utf8")).trim().split("\n");
  if (!/^\d+$/.test(pidLine)) return null;
  return { pid: Number(pidLine), field: (key) => fields.find((f) => f.startsWith(`${key}=`))?.slice(key.length + 1) };
}

/** Whether a marked dir was left by a process of this machine that is gone. */
function deadOwner(m: { pid: number; field: (key: string) => string | undefined }, isAlive: (pid: number) => boolean, self: HostIdentity): boolean {
  // A pid means nothing on another host (a /tmp shared across machines or containers).
  const host = m.field("host");
  if (host !== undefined && host !== self.hostname) return false;
  // Nor in another pid namespace (a container that shares the host name and /tmp).
  const pidNs = m.field("pidns");
  const selfNs = self.pidNs ?? null;
  if (pidNs !== undefined && selfNs !== null && pidNs !== selfNs) return false;
  // Written in an earlier boot: its process is gone even if the pid is in use again. Proof
  // only on the same kernel's namespace (or, with no namespace either side, the same host).
  const boot = m.field("boot");
  const sameNs = pidNs !== undefined && pidNs === selfNs;
  const neitherNs = pidNs === undefined && selfNs === null && host !== undefined;
  const earlierBoot = boot !== undefined && self.bootId !== null && boot !== self.bootId && (sameNs || neitherNs);
  if (earlierBoot) return true;
  return m.pid !== process.pid && !isAlive(m.pid);
}

/**
 * Finds the `bug-report-extract-*` directories in `parent` left by a server that died without
 * cleaning up (SIGKILL, crash) and renames each out of the prefix (to `.deleting-<name>`), so
 * nothing loads it any more; `deleted` then removes them, with any `.deleting-` dir an
 * interrupted sweep left. Only real directories (not symlinks) that hold our marker with a
 * valid pid, written on this host and pid namespace, where that process is gone (or the marker
 * is from an earlier boot) are doomed; anything else, including a directory without the marker
 * or one another host wrote, is left alone. Markers without a host line (older servers) are
 * judged by pid alone. A host name that changed since (macOS renames hosts on network changes)
 * leaves a leftover in place: never wrongly deleted, only unswept.
 */
export async function sweepStaleExtractionsInBackground(
  parent: string,
  isAlive: (pid: number) => boolean = processAlive,
  self: HostIdentity = thisHost(),
): Promise<{ doomed: string[]; deleted: Promise<void> }> {
  const names = await readdir(parent).catch(() => [] as string[]);
  const doomed: string[] = [];
  const toDelete: string[] = [];
  for (const name of names) {
    const leftover = name.startsWith(DELETING_PREFIX + EXTRACT_DIR_PREFIX);
    if (!leftover && !name.startsWith(EXTRACT_DIR_PREFIX)) continue;
    const dir = join(parent, name);
    try {
      const marker = await readMarker(dir);
      if (!marker) continue;
      if (leftover) {
        // Renamed by an earlier sweep, which had judged it doomed.
        toDelete.push(dir);
        continue;
      }
      if (!deadOwner(marker, isAlive, self)) continue;
      const renamed = join(parent, DELETING_PREFIX + name);
      await rename(dir, renamed);
      doomed.push(dir);
      toDelete.push(renamed);
    } catch {
      // Unreadable, or removed meanwhile: leave it.
    }
  }
  const deleted = (async () => {
    for (const dir of toDelete) await removeMarkedDir(dir).catch(() => undefined);
  })();
  return { doomed, deleted };
}

/** sweepStaleExtractionsInBackground, waiting for the deletion too. Returns the doomed paths. */
export async function sweepStaleExtractions(
  parent: string,
  isAlive: (pid: number) => boolean = processAlive,
  self: HostIdentity = thisHost(),
): Promise<string[]> {
  const { doomed, deleted } = await sweepStaleExtractionsInBackground(parent, isAlive, self);
  await deleted;
  return doomed;
}

/** The tracker the server uses for every archive it extracts. */
export const extractionTracker = new ExtractionTracker();

let startupSweep: Promise<unknown> = Promise.resolve();

/**
 * Starts the server's sweep of `parent` for leftover extractions. Loads await only its
 * classification (startupSweepDone): by then every doomed dir is renamed out of the prefix, so
 * no load can be reading one, and the deletion runs on in the background. Resolves with the
 * doomed paths once they are deleted.
 */
export function runStartupSweep(parent: string): Promise<string[]> {
  const sweep = sweepStaleExtractionsInBackground(parent).catch(() => ({ doomed: [] as string[], deleted: Promise.resolve() }));
  startupSweep = sweep;
  return sweep.then(async ({ doomed, deleted }) => {
    await deleted;
    return doomed;
  });
}

/** Settles once the startup sweep (if one was started) has classified and renamed; never rejects. */
export function startupSweepDone(): Promise<unknown> {
  return startupSweep;
}

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

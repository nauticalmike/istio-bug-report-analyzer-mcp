// Only node: imports, so the exit-cleanup path can be exercised in a child process from the .ts source.
import { rmSync } from "node:fs";
import { mkdtemp, open, rm, stat, statfs } from "node:fs/promises";
import { join } from "node:path";

export const EXTRACT_DIR_PREFIX = "bug-report-extract-";

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
 * create() are ever deleted, so a directory the user loaded is never touched.
 */
export class ExtractionTracker {
  private readonly owned = new Set<string>();
  private readonly byOwner = new WeakMap<object, string>();

  get size(): number {
    return this.owned.size;
  }

  /** A new, empty `bug-report-extract-*` directory inside `parent`. */
  async create(parent: string): Promise<string> {
    const dir = await mkdtemp(join(parent, EXTRACT_DIR_PREFIX));
    this.owned.add(dir);
    return dir;
  }

  owns(dir: string): boolean {
    return this.owned.has(dir);
  }

  /** Deletes `dir` if this tracker created it; returns whether it did. */
  async remove(dir: string): Promise<boolean> {
    if (!this.owned.has(dir)) return false;
    await rm(dir, { recursive: true, force: true });
    this.owned.delete(dir);
    return true;
  }

  /** Ties a created directory to the object (a store) that reads from it. */
  attach(owner: object, dir: string): void {
    if (this.owned.has(dir)) this.byOwner.set(owner, dir);
  }

  /** Deletes the directory tied to `owner`, if any. */
  async release(owner: object): Promise<void> {
    const dir = this.byOwner.get(owner);
    if (!dir) return;
    this.byOwner.delete(owner);
    await this.remove(dir);
  }

  /** Synchronous, for the process `exit` event, where async work never runs. */
  removeAllSync(): void {
    for (const dir of this.owned) {
      try {
        rmSync(dir, { recursive: true, force: true });
        this.owned.delete(dir);
      } catch {
        // Best effort at exit: nothing can be reported any more.
      }
    }
  }
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

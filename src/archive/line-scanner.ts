import { open } from "node:fs/promises";

/**
 * Called once per line, without its "\n" or trailing "\r". `lineBytes` is the line's
 * full length in bytes, which is larger than the text when the line was cut at
 * `maxLineBytes`. Returning false stops the scan.
 */
export type LineHandler = (line: string, lineBytes: number) => void | boolean;

export interface LineScanOptions {
  /** Longest line handed over whole; the rest of a longer line is skipped (default 1 MiB). */
  maxLineBytes?: number;
  /** Bytes read per call (default 1 MiB). */
  chunkBytes?: number;
}

export interface LineScanStats {
  /** Bytes read from the file. */
  bytes: number;
  lines: number;
  /** Lines longer than maxLineBytes, handed over cut. */
  longLines: number;
  /** True when the handler returned false before the end of the file. */
  stopped: boolean;
}

export const DEFAULT_MAX_LINE_BYTES = 1024 * 1024;
const DEFAULT_CHUNK_BYTES = 1024 * 1024;

/**
 * Reads a file line by line in fixed-size chunks, so memory stays at about
 * chunkBytes + maxLineBytes whatever the file size. Log files in bug reports reach
 * several GB, far past V8's ~512 MiB string limit, so whole-file reads either throw
 * or exhaust the heap; every log reader goes through this instead.
 * Rejects when the file cannot be opened or read.
 */
export async function scanFileLines(absolutePath: string, onLine: LineHandler, opts: LineScanOptions = {}): Promise<LineScanStats> {
  const maxLineBytes = Math.max(1, opts.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES);
  const chunkBytes = Math.max(1, opts.chunkBytes ?? DEFAULT_CHUNK_BYTES);
  const stats: LineScanStats = { bytes: 0, lines: 0, longLines: 0, stopped: false };

  // The start of a line that spans chunks, kept up to maxLineBytes; `pendingBytes` counts all of it.
  let pending = Buffer.alloc(0);
  let pendingBytes = 0;

  // buf[start, end) holds the line (all of it, or its first maxLineBytes + 1 bytes); totalBytes is its full length.
  const emit = (buf: Buffer, start: number, end: number, totalBytes: number): boolean => {
    let hi = end;
    let bytes = totalBytes;
    if (hi - start === bytes && hi > start && buf[hi - 1] === 0x0d) {
      hi--;
      bytes--;
    }
    if (bytes > maxLineBytes) {
      stats.longLines++;
      hi = charBoundary(buf, start, start + maxLineBytes);
    }
    stats.lines++;
    return onLine(buf.toString("utf-8", start, hi), bytes) !== false;
  };

  const handle = await open(absolutePath, "r");
  try {
    const chunk = Buffer.alloc(chunkBytes);
    for (;;) {
      const { bytesRead } = await handle.read(chunk, 0, chunkBytes, null);
      if (bytesRead === 0) break;
      stats.bytes += bytesRead;
      let pos = 0;
      while (pos < bytesRead) {
        const nl = chunk.indexOf(0x0a, pos);
        const end = nl === -1 || nl >= bytesRead ? bytesRead : nl;
        const segment = end - pos;
        if (nl === -1 || nl >= bytesRead) {
          // No newline left in this chunk: keep what fits of the partial line.
          const room = Math.max(0, maxLineBytes + 1 - pending.length);
          if (room > 0) pending = Buffer.concat([pending, chunk.subarray(pos, pos + Math.min(room, segment))]);
          pendingBytes += segment;
          break;
        }
        let keepGoing: boolean;
        if (pendingBytes === 0) {
          keepGoing = emit(chunk, pos, end, segment);
        } else {
          const room = Math.max(0, maxLineBytes + 1 - pending.length);
          const line = room > 0 ? Buffer.concat([pending, chunk.subarray(pos, pos + Math.min(room, segment))]) : pending;
          keepGoing = emit(line, 0, line.length, pendingBytes + segment);
          pending = Buffer.alloc(0);
          pendingBytes = 0;
        }
        pos = nl + 1;
        if (!keepGoing) {
          stats.stopped = true;
          return stats;
        }
      }
    }
    if (pendingBytes > 0) {
      emit(pending, 0, pending.length, pendingBytes);
    }
    return stats;
  } finally {
    await handle.close();
  }
}

/** Moves `end` back so a cut never lands inside a multi-byte UTF-8 character. */
function charBoundary(buf: Buffer, start: number, end: number): number {
  let hi = end;
  while (hi > start && (buf[hi] & 0xc0) === 0x80) hi--;
  return hi;
}

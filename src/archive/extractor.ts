import { readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import * as tar from "tar";
import { EXTRACT_MARKER_FILE } from "./extraction.js";

export interface FileEntry {
  relativePath: string;
  absolutePath: string;
  size: number;
  /** Modification time (ms); tar extraction keeps the time each file was written at collection. */
  mtimeMs: number;
}

export interface ArchiveIndex {
  rootPath: string;
  files: FileEntry[];
  sections: {
    root: FileEntry[];
    cluster: FileEntry[];
    proxies: FileEntry[];
    istio: FileEntry[];
    operator: FileEntry[];
    cni: FileEntry[];
    analyze: FileEntry[];
  };
}

export async function readArchiveDirectory(dirPath: string): Promise<ArchiveIndex> {
  const files: FileEntry[] = [];
  await walkDir(dirPath, dirPath, files);

  const sections: ArchiveIndex["sections"] = {
    root: [],
    cluster: [],
    proxies: [],
    istio: [],
    operator: [],
    cni: [],
    analyze: [],
  };

  for (const file of files) {
    const firstSegment = file.relativePath.split("/")[0];
    if (firstSegment in sections && firstSegment !== "root") {
      sections[firstSegment as keyof typeof sections].push(file);
    } else {
      sections.root.push(file);
    }
  }

  return { rootPath: dirPath, files, sections };
}

async function walkDir(basePath: string, currentPath: string, files: FileEntry[]): Promise<void> {
  const entries = await readdir(currentPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(currentPath, entry.name);
    // The ownership marker of our extraction dir is not part of the report.
    if (currentPath === basePath && entry.name === EXTRACT_MARKER_FILE) continue;
    if (entry.isDirectory()) {
      await walkDir(basePath, fullPath, files);
    } else if (entry.isFile()) {
      const fileStat = await stat(fullPath);
      files.push({
        relativePath: relative(basePath, fullPath),
        absolutePath: fullPath,
        size: fileStat.size,
        mtimeMs: fileStat.mtimeMs,
      });
    }
  }
}

const OUT_OF_SPACE_CODES = new Set(["ENOSPC", "EDQUOT"]);

export async function extractArchive(archivePath: string, outputDir: string): Promise<string> {
  // node-tar reports a failed entry write as a warning (non-strict mode); a full disk
  // must fail the extraction instead of leaving truncated files behind.
  let outOfSpace: { code: string; message: string } | null = null;
  await tar.extract({
    file: archivePath,
    cwd: outputDir,
    onwarn: (_code, message, data) => {
      if (!outOfSpace && data?.code && OUT_OF_SPACE_CODES.has(data.code)) outOfSpace = { code: data.code, message };
    },
  });
  if (outOfSpace) {
    const { code, message } = outOfSpace;
    throw Object.assign(new Error(`${message} (while extracting into ${outputDir})`), { code });
  }

  // Older istioctl wraps everything in a `bug-report/` directory; newer
  // releases (1.30+) place the sections at the tar root next to a *file*
  // named `bug-report.log`, so only directory entries may be treated as
  // the archive root.
  const entries = await readdir(outputDir, { withFileTypes: true });
  const bugReportDir = entries.find((e) => e.isDirectory() && e.name.startsWith("bug-report"));
  return bugReportDir ? join(outputDir, bugReportDir.name) : outputDir;
}

/** Section directories of a bug-report tree (istioctl's, and collectors that copy its layout). */
const SECTION_DIRS = new Set(["cluster", "proxies", "istio", "analyze", "cni", "operator"]);

async function sectionDirs(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  return entries.filter((e) => e.isDirectory() && SECTION_DIRS.has(e.name)).map((e) => e.name);
}

/** A directory that holds a report of its own: a cluster/ section, or two other sections. */
export async function isReportTree(dir: string): Promise<boolean> {
  const sections = await sectionDirs(dir);
  return sections.includes("cluster") || sections.length >= 2;
}

/**
 * Report trees below `dir` (not `dir` itself), at most `maxDepth` levels down, sorted by
 * path. Some collectors write one tree per cluster under a common top directory; only one
 * of them is loaded, so the load says which others exist. Section directories are not searched.
 */
export async function findReportTrees(dir: string, maxDepth = 2): Promise<string[]> {
  const found: string[] = [];
  const walk = async (current: string, depth: number) => {
    if (depth > maxDepth) return;
    const entries = await readdir(current, { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      if (!e.isDirectory() || SECTION_DIRS.has(e.name)) continue;
      const path = join(current, e.name);
      if (await isReportTree(path)) found.push(path);
      else await walk(path, depth + 1);
    }
  };
  await walk(dir, 1);
  return found.sort();
}

import { readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import * as tar from "tar";

export interface FileEntry {
  relativePath: string;
  absolutePath: string;
  size: number;
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
    if (entry.isDirectory()) {
      await walkDir(basePath, fullPath, files);
    } else if (entry.isFile()) {
      const fileStat = await stat(fullPath);
      files.push({
        relativePath: relative(basePath, fullPath),
        absolutePath: fullPath,
        size: fileStat.size,
      });
    }
  }
}

export async function extractArchive(archivePath: string, outputDir: string): Promise<string> {
  await tar.extract({
    file: archivePath,
    cwd: outputDir,
  });

  // Older istioctl wraps everything in a `bug-report/` directory; newer
  // releases (1.30+) place the sections at the tar root next to a *file*
  // named `bug-report.log`, so only directory entries may be treated as
  // the archive root.
  const entries = await readdir(outputDir, { withFileTypes: true });
  const bugReportDir = entries.find((e) => e.isDirectory() && e.name.startsWith("bug-report"));
  return bugReportDir ? join(outputDir, bugReportDir.name) : outputDir;
}

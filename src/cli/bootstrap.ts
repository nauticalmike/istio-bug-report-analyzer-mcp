import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { access, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const execFileAsync = promisify(execFile);

export async function findIstioctl(): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("which", ["istioctl"]);
    const path = stdout.trim();
    if (path) {
      await access(path);
      return path;
    }
  } catch {
    // Not found in PATH
  }
  return null;
}

export async function downloadIstioctl(
  version?: string,
  source?: "oss" | "solo",
): Promise<string> {
  // Placeholder — in a full implementation, this would:
  // 1. Detect OS and architecture
  // 2. Download from istio.io (oss) or Solo.io (solo)
  // 3. Extract and make executable
  // 4. Return path to binary
  throw new Error(
    `Automatic istioctl download not yet implemented. ` +
    `Please install istioctl manually or provide a path via istioctl_path. ` +
    `Version: ${version ?? "latest"}, Source: ${source ?? "oss"}`,
  );
}

export async function getClusterIstioVersion(context?: string): Promise<string | null> {
  try {
    const args = ["version", "--short", "--remote"];
    if (context) args.push("--context", context);
    const istioctlPath = await findIstioctl();
    if (!istioctlPath) return null;
    const { stdout } = await execFileAsync(istioctlPath, args, { timeout: 30000 });
    const match = stdout.match(/(\d+\.\d+\.\d+)/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

export async function runBugReport(
  istioctlPath: string,
  options: {
    context?: string;
    namespaces?: string[];
    exclude?: string[];
    outputDir?: string;
  },
): Promise<string> {
  const outputDir = options.outputDir ?? join(tmpdir(), `bug-report-${Date.now()}`);
  await mkdir(outputDir, { recursive: true });

  // istioctl treats --dir as *temporary* artifact storage and removes it when
  // done; the archive itself is written to --output-dir (default: cwd).
  const args = ["bug-report", "--full-secrets", `--output-dir=${outputDir}`];
  if (options.context) args.push("--context", options.context);
  if (options.namespaces?.length) {
    args.push("--include", options.namespaces.join(","));
  }
  if (options.exclude?.length) {
    args.push("--exclude", options.exclude.join(","));
  }

  await execFileAsync(istioctlPath, args, {
    timeout: 300000, // 5 minutes
    maxBuffer: 50 * 1024 * 1024, // 50MB
  });

  // bug-report creates a .tar.gz in the output directory
  const { readdir } = await import("node:fs/promises");
  const files = await readdir(outputDir);
  const archive = files.find((f) => f.endsWith(".tar.gz"));
  if (archive) {
    return join(outputDir, archive);
  }

  // If no tar.gz, maybe it was already extracted
  return outputDir;
}

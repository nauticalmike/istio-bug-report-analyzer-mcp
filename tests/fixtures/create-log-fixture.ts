import { open } from "node:fs/promises";

const WRITE_BUFFER_BYTES = 8 * 1024 * 1024;

/**
 * Writes `block` over and over until the file holds at least `bytes`, then `tail`.
 * Writes go through one reused buffer, so multi-GB synthetic logs take seconds and
 * almost no memory. Returns the file size.
 */
export async function writeRepeatedLog(path: string, bytes: number, block: string, tail = ""): Promise<number> {
  const unit = Buffer.from(block, "utf-8");
  const reps = Math.max(1, Math.floor(WRITE_BUFFER_BYTES / unit.length));
  const buf = Buffer.alloc(unit.length * reps);
  for (let i = 0; i < reps; i++) unit.copy(buf, i * unit.length);

  const handle = await open(path, "w");
  let written = 0;
  try {
    while (written < bytes) {
      const n = Math.min(buf.length, Math.ceil((bytes - written) / unit.length) * unit.length);
      await handle.write(buf, 0, n);
      written += n;
    }
    if (tail) written += (await handle.write(Buffer.from(tail, "utf-8"))).bytesWritten;
  } finally {
    await handle.close();
  }
  return written;
}

// Kubernetes generates pod-name suffixes from this alphabet (no vowels, no 0, 1 or 3).
const K8S_ALPHABET = "bcdfghjklmnpqrstvwxz2456789";

/** A deterministic pod-name suffix of `len` characters with at least one digit, like Kubernetes makes. */
function k8sSuffix(seed: number, len: number): string {
  let s = "";
  for (let k = 0; k < len; k++) s += K8S_ALPHABET[(seed * 7 + k * 13 + seed * k) % K8S_ALPHABET.length];
  return /\d/.test(s) ? s : `${s.slice(0, -1)}7`;
}

/**
 * Proxy-log lines that differ only in tokens the error grouping normalizes
 * (durations, decimals, ports, IPs, UUIDs, pod-hash suffixes, key=value ids),
 * plus probe and scrape noise: five patterns, whatever the line count. Every line is synthetic.
 */
export function noisyProxyLogBlock(lines = 200): string {
  const out: string[] = [];
  for (let i = 0; i < lines; i++) {
    const ip = `10.${i % 250}.${(i * 7) % 250}.${(i * 13) % 250}`;
    const ip6 = `fd00:10:${(i % 0xffff).toString(16)}::${((i * 3) % 0xffff).toString(16)}`;
    const uuid = `${(0x10000000 + i).toString(16)}-1234-4abc-8def-${(0x100000000000 + i * 31).toString(16)}`;
    const pod = `app-${k8sSuffix(i, 10)}-${k8sSuffix(i + 1, 5)}`;
    const ts = `2026-01-01T00:${String(i % 60).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}.${String(i).padStart(6, "0")}Z`;
    switch (i % 5) {
      case 0:
        out.push(`${ts}\twarn\txdsproxy\tupstream ${ip}:${15000 + i} reset after ${i % 9}.${i % 10}s id=${i} pod=${pod}`);
        break;
      case 1:
        out.push(`${ts}\terror\tcache\tsecret fetch for ${uuid} by ${pod} failed after ${(i % 900) + 10}ms on [${ip6}]:${8000 + i}`);
        break;
      case 2:
        out.push(`${ts}\twarn\tapp health check failed: Get "http://${ip}:${8080 + (i % 20)}/healthz" ready=${(i % 7) / 10 + 0.15} took ${i % 5}m${i % 60}s ns=team-${i}`);
        break;
      case 3:
        out.push(`${ts}\twarn\tagent\tRequest to probe app failed: Get "http://${ip}:${9000 + i}/ready": dial tcp ${ip}:${9000 + i}: connect: connection refused`);
        break;
      default:
        out.push(`${ts}\terror\tagent\tfailed scraping application metrics: Get "http://${ip}:${15020 + (i % 3)}/stats/prometheus" src.workload=w-${i} dst.service=s${i}.svc.cluster.local`);
    }
  }
  return out.join("\n") + "\n";
}

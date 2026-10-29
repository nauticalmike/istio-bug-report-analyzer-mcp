#!/usr/bin/env node
// Fails when DIAG-006's upstream support window drifts from istio.io's support table.
// Usage: node scripts/check-istio-support.mjs [--html <saved page>] [--template <yaml>]
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import yaml from "js-yaml";

export const SUPPORTED_RELEASES_URL = "https://istio.io/latest/docs/releases/supported-releases/";
const DEFAULT_TEMPLATE = join(dirname(fileURLToPath(import.meta.url)), "..", "templates", "DIAG-006-unsupported-version.yaml");

const cellText = (html) =>
  html.replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();

const cells = (row, tag) => [...row.matchAll(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "g"))].map((m) => cellText(m[1]));

/** Minors marked "Yes" in the "Currently Supported" column, sorted ascending. */
export function parseSupportedMinors(html) {
  for (const [table] of html.matchAll(/<table[\s\S]*?<\/table>/g)) {
    const rows = [...table.matchAll(/<tr[\s\S]*?<\/tr>/g)].map((m) => m[0]);
    const header = rows.length > 0 ? cells(rows[0], "th") : [];
    const versionCol = header.findIndex((h) => /^version$/i.test(h));
    const supportedCol = header.findIndex((h) => /currently supported/i.test(h));
    if (versionCol < 0 || supportedCol < 0) continue;

    const supported = [];
    for (const row of rows.slice(1)) {
      const data = cells(row, "td");
      const version = data[versionCol] ?? "";
      if (/^\d+\.\d+$/.test(version) && /^yes\b/i.test(data[supportedCol] ?? "")) supported.push(version);
    }
    return sortMinors(supported);
  }
  throw new Error(`Istio support table not found at ${SUPPORTED_RELEASES_URL}; the page layout may have changed.`);
}

/** The upstream `supported` list from the DIAG-006 version_support signal. */
export function readTemplateWindow(templateText) {
  const template = yaml.load(templateText);
  const signal = template?.signals?.find((s) => s?.source?.type === "version_support");
  if (!Array.isArray(signal?.source?.supported)) {
    throw new Error("DIAG-006 has no version_support signal with a supported list.");
  }
  return sortMinors(signal.source.supported.map(String));
}

export function compareWindows(upstream, template) {
  const added = sortMinors(upstream.filter((v) => !template.includes(v)));
  const removed = sortMinors(template.filter((v) => !upstream.includes(v)));
  return { ok: added.length === 0 && removed.length === 0, added, removed };
}

function sortMinors(list) {
  const key = (v) => v.split(".").map(Number);
  return [...new Set(list)].sort((a, b) => {
    const [am, an] = key(a);
    const [bm, bn] = key(b);
    return am - bm || an - bn;
  });
}

async function fetchPage(url, attempts = 3) {
  let lastError;
  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (err) {
      lastError = err;
      if (i < attempts) await new Promise((r) => setTimeout(r, 2_000 * i));
    }
  }
  throw new Error(`Could not fetch ${url}: ${lastError?.message ?? lastError}`);
}

function argValue(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(args) {
  const htmlFile = argValue(args, "--html");
  const templateFile = resolve(argValue(args, "--template") ?? DEFAULT_TEMPLATE);
  const html = htmlFile ? readFileSync(htmlFile, "utf8") : await fetchPage(SUPPORTED_RELEASES_URL);

  const upstream = parseSupportedMinors(html);
  if (upstream.length === 0) throw new Error("istio.io lists no supported minors; refusing to compare.");
  const template = readTemplateWindow(readFileSync(templateFile, "utf8"));
  const result = compareWindows(upstream, template);

  console.log(`istio.io supported minors: ${upstream.join(", ")}`);
  console.log(`DIAG-006 supported list:   ${template.join(", ")}`);
  if (result.ok) {
    console.log("OK: DIAG-006 matches the upstream support window.");
    return 0;
  }
  if (result.added.length) console.log(`Add to DIAG-006: ${result.added.join(", ")}`);
  if (result.removed.length) console.log(`Remove from DIAG-006 (now EOL): ${result.removed.join(", ")}`);
  console.log(`Update "supported" (and the "Last verified" date) in ${templateFile}.`);
  console.log("Also check supportedSolo against https://docs.solo.io/istio/latest/reference/versions/ (n-4).");
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`ERROR: ${err.message}`);
      process.exit(2);
    },
  );
}

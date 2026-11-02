#!/usr/bin/env node
// Fails when DIAG-006's upstream support window or its release / end-of-life dates drift from istio.io's support table.
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

/** Rows of the support table as { header text: cell text }, for minor-version rows only. */
function supportRows(html) {
  for (const [table] of html.matchAll(/<table[\s\S]*?<\/table>/g)) {
    const rows = [...table.matchAll(/<tr[\s\S]*?<\/tr>/g)].map((m) => m[0]);
    const header = rows.length > 0 ? cells(rows[0], "th") : [];
    if (!header.some((h) => /^version$/i.test(h)) || !header.some((h) => /currently supported/i.test(h))) continue;
    const named = (data, re) => data[header.findIndex((h) => re.test(h))] ?? "";
    return rows.slice(1).map((row) => {
      const data = cells(row, "td");
      return {
        version: named(data, /^version$/i),
        supported: named(data, /currently supported/i),
        released: named(data, /^release date$/i),
        endOfLife: named(data, /^end of life$/i),
      };
    }).filter((r) => /^\d+\.\d+$/.test(r.version));
  }
  throw new Error(`Istio support table not found at ${SUPPORTED_RELEASES_URL}; the page layout may have changed.`);
}

/** Minors marked "Yes" in the "Currently Supported" column, sorted ascending. */
export function parseSupportedMinors(html) {
  return sortMinors(supportRows(html).filter((r) => /^yes\b/i.test(r.supported)).map((r) => r.version));
}

const MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/** "Aug 27, 2026", "Sept 30, 2025", "April 7, 2026" -> YYYY-MM-DD; null for "~Feb 2027 (Expected)" and the like. */
function isoDay(text) {
  const m = /^([A-Za-z]+)\.?\s+(\d{1,2}),\s*(\d{4})$/.exec(text.trim());
  const month = m ? MONTHS.indexOf(m[1].slice(0, 3).toLowerCase()) : -1;
  if (month < 0) return null;
  return `${m[3]}-${String(month + 1).padStart(2, "0")}-${m[2].padStart(2, "0")}`;
}

/** Release and end-of-life days per minor from the support table (expected dates are skipped). */
export function parseSupportDates(html) {
  const released = {};
  const endOfLife = {};
  for (const row of supportRows(html)) {
    const r = isoDay(row.released);
    const e = isoDay(row.endOfLife);
    if (r) released[row.version] = r;
    if (e) endOfLife[row.version] = e;
  }
  return { released, endOfLife };
}

/** The `released` and `endOfLife` tables from the DIAG-006 version_support signal. */
export function readTemplateDates(templateText) {
  const template = yaml.load(templateText);
  const source = template?.signals?.find((s) => s?.source?.type === "version_support")?.source ?? {};
  return { released: source.released ?? {}, endOfLife: source.endOfLife ?? {} };
}

/**
 * Every upstream date for a minor at or after the oldest one a template table tracks must
 * be in that table with the same day.
 */
export function compareDates(upstream, template) {
  const problems = [];
  for (const kind of ["released", "endOfLife"]) {
    const tracked = sortMinors(Object.keys(template[kind]));
    if (tracked.length === 0) continue;
    const oldest = tracked[0].split(".").map(Number);
    for (const minor of sortMinors(Object.keys(upstream[kind]))) {
      const [maj, min] = minor.split(".").map(Number);
      if (maj < oldest[0] || (maj === oldest[0] && min < oldest[1])) continue;
      const want = upstream[kind][minor];
      const have = template[kind][minor];
      if (!have) problems.push(`${kind}["${minor}"] is missing (istio.io: ${want})`);
      else if (have !== want) problems.push(`${kind}["${minor}"] is ${have}, istio.io says ${want}`);
    }
  }
  return { ok: problems.length === 0, problems };
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
  const templateText = readFileSync(templateFile, "utf8");
  const template = readTemplateWindow(templateText);
  const result = compareWindows(upstream, template);
  const dates = compareDates(parseSupportDates(html), readTemplateDates(templateText));

  console.log(`istio.io supported minors: ${upstream.join(", ")}`);
  console.log(`DIAG-006 supported list:   ${template.join(", ")}`);
  if (result.ok && dates.ok) {
    console.log("OK: DIAG-006 matches the upstream support window and dates.");
    return 0;
  }
  if (result.added.length) console.log(`Add to DIAG-006: ${result.added.join(", ")}`);
  if (result.removed.length) console.log(`Remove from DIAG-006 (now EOL): ${result.removed.join(", ")}`);
  for (const p of dates.problems) console.log(`DIAG-006 ${p}`);
  console.log(`Update "supported", "released", "endOfLife" (and the "Last verified" date) in ${templateFile}.`);
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

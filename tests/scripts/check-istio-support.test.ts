import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  parseSupportedMinors,
  readTemplateWindow,
  compareWindows,
  parseSupportDates,
  readTemplateDates,
  compareDates,
} from "../../scripts/check-istio-support.mjs";

const root = join(import.meta.dirname, "..", "..");
const snapshot = readFileSync(join(root, "tests", "fixtures", "istio-supported-releases.html"), "utf8");
const template = readFileSync(join(root, "templates", "DIAG-006-unsupported-version.yaml"), "utf8");

describe("parseSupportedMinors", () => {
  it("reads the supported minors from the istio.io support table (2026-10-20 snapshot)", () => {
    expect(parseSupportedMinors(snapshot)).toEqual(["1.30", "1.31"]);
  });

  it("finds the table by header names, not column position", () => {
    const html =
      "<table><thead><tr><th>Currently Supported</th><th>Version</th></tr></thead>" +
      "<tbody><tr><td>Yes</td><td>1.40</td></tr><tr><td>No</td><td>1.39</td></tr>" +
      "<tr><td>No, development only</td><td>master</td></tr></tbody></table>";
    expect(parseSupportedMinors(html)).toEqual(["1.40"]);
  });

  it("throws when the support table is missing, so a page redesign cannot pass silently", () => {
    expect(() => parseSupportedMinors("<html><body>nothing here</body></html>")).toThrow(/support table/);
  });
});

describe("readTemplateWindow", () => {
  it("reads the upstream list from DIAG-006", () => {
    expect(readTemplateWindow(template)).toEqual(["1.30", "1.31"]);
  });
});

describe("compareWindows", () => {
  it("reports no drift when the lists match in any order", () => {
    expect(compareWindows(["1.31", "1.30"], ["1.30", "1.31"])).toEqual({ ok: true, added: [], removed: [] });
  });

  it("reports minors to add and remove", () => {
    expect(compareWindows(["1.31", "1.32"], ["1.30", "1.31"])).toEqual({ ok: false, added: ["1.32"], removed: ["1.30"] });
  });
});

describe("support dates (DIAG-006 judges support as of the capture date)", () => {
  it("reads release and end-of-life days, skipping expected dates", () => {
    const dates = parseSupportDates(snapshot);
    expect(dates.released["1.31"]).toBe("2026-08-27");
    expect(dates.released["1.25"]).toBe("2025-03-03");
    expect(dates.endOfLife["1.29"]).toBe("2026-10-15");
    expect(dates.endOfLife["1.25"]).toBe("2025-09-30");
    expect(dates.endOfLife["1.27"]).toBe("2026-04-07");
    expect(dates.endOfLife["1.31"]).toBeUndefined();
  });

  it("the template's tables match the istio.io snapshot", () => {
    expect(compareDates(parseSupportDates(snapshot), readTemplateDates(template))).toEqual({ ok: true, problems: [] });
  });

  it("reports a missing or different date for minors the template tracks", () => {
    const upstream = { released: { "1.31": "2026-08-27", "1.32": "2026-11-20" }, endOfLife: { "1.28": "2026-07-01", "1.29": "2026-10-15" } };
    const tmpl = { released: { "1.31": "2026-08-27" }, endOfLife: { "1.28": "2026-07-02" } };
    expect(compareDates(upstream, tmpl).problems).toEqual([
      'released["1.32"] is missing (istio.io: 2026-11-20)',
      'endOfLife["1.28"] is 2026-07-02, istio.io says 2026-07-01',
      'endOfLife["1.29"] is missing (istio.io: 2026-10-15)',
    ]);
  });
});

import { describe, it, expect } from "vitest";
import {
  CONTENT_BUDGET_CHARS,
  OUTPUT_BUDGET_CHARS,
  clampLine,
  fitItems,
  fitItemsFromEnd,
  pageFooter,
  pageText,
  renderTextPage,
  toOffset,
} from "../../src/tools/output-budget.js";

describe("output budget", () => {
  it("keeps room for headers and footers inside the response budget", () => {
    expect(CONTENT_BUDGET_CHARS).toBeLessThan(OUTPUT_BUDGET_CHARS);
  });

  it("normalizes offsets", () => {
    expect(toOffset(undefined)).toBe(0);
    expect(toOffset(-5)).toBe(0);
    expect(toOffset(3.7)).toBe(3);
  });

  describe("pageFooter", () => {
    it("is empty when the page is everything", () => {
      expect(pageFooter(0, 10, 10)).toBe("");
      expect(pageFooter(0, 0, 0)).toBe("");
    });

    it("gives a 1-based range and the next offset", () => {
      expect(pageFooter(0, 200, 1500)).toBe("Showing 1-200 of 1500. Pass offset=200 for more.");
      expect(pageFooter(200, 400, 1500, { unit: "bytes", hint: "or filter" })).toBe(
        "Showing bytes 201-400 of 1500. Pass offset=400 for more, or filter.",
      );
    });

    it("has no next offset on the last page", () => {
      expect(pageFooter(1400, 1500, 1500)).toBe("Showing 1401-1500 of 1500.");
    });

    it("says when the budget cut the page", () => {
      expect(pageFooter(0, 3, 10, { budgetHit: true })).toContain("100,000-character output budget");
    });
  });

  describe("fitItems", () => {
    it("stops at the limit", () => {
      expect(fitItems(["a", "b", "c"], { limit: 2 })).toEqual({ taken: ["a", "b"], budgetHit: false });
    });

    it("stops before the budget, counting separators", () => {
      // "aaaa" + "\n" + "bbbb" = 9 chars; a third item would make 14.
      const { taken, budgetHit } = fitItems(["aaaa", "bbbb", "cccc"], { budget: 13 });
      expect(taken).toEqual(["aaaa", "bbbb"]);
      expect(budgetHit).toBe(true);
    });

    it("fits exactly at the budget", () => {
      expect(fitItems(["aaaa", "bbbb"], { budget: 9 })).toEqual({ taken: ["aaaa", "bbbb"], budgetHit: false });
    });

    it("never returns an empty page: an oversized first item is cut", () => {
      const { taken, budgetHit } = fitItems(["x".repeat(5000)], { budget: 1000 });
      expect(taken).toHaveLength(1);
      expect(taken[0].length).toBeLessThanOrEqual(1000);
      expect(taken[0]).toContain("item cut at the output budget: 5,000 chars");
      expect(budgetHit).toBe(true);
    });

    it("takes from the end, keeping order", () => {
      expect(fitItemsFromEnd(["aaaa", "bbbb", "cccc"], { budget: 9 })).toEqual({ taken: ["bbbb", "cccc"], budgetHit: true });
    });
  });

  it("clamps long lines", () => {
    expect(clampLine("short", 10)).toBe("short");
    expect(clampLine("x".repeat(25), 10)).toBe(`${"x".repeat(10)} … [15 more chars]`);
  });

  describe("pageText", () => {
    const text = Array.from({ length: 50 }, (_, i) => `line ${i} ${"y".repeat(i % 7)}`).join("\n");

    it("ends each page on a line boundary and pages cover the text exactly", () => {
      const pages: string[] = [];
      let offset = 0;
      for (let guard = 0; guard < 100; guard++) {
        const p = pageText(text, offset, 64);
        expect(p.page.length).toBeLessThanOrEqual(64);
        if (p.end < p.total) expect(p.page.endsWith("\n")).toBe(true);
        pages.push(p.page);
        if (p.end >= p.total) break;
        expect(p.end).toBeGreaterThan(offset);
        offset = p.end;
      }
      expect(pages.join("")).toBe(text);
    });

    it("cuts mid-line when a single line is longer than the budget", () => {
      const p = pageText("z".repeat(100), 0, 30);
      expect(p).toMatchObject({ start: 0, end: 30, total: 100 });
    });

    it("does not split a surrogate pair when cutting mid-line", () => {
      const p = pageText("ab\u{1F600}cd", 0, 3);
      expect(p.page).toBe("ab");
      expect(pageText("ab\u{1F600}cd", p.end, 3).page).toBe("\u{1F600}c");
    });

    it("renders a footer only when there is more", () => {
      expect(renderTextPage("small", undefined)).toBe("small");
      const out = renderTextPage("a\nb\nc\nd\n", 0, 4);
      expect(out).toBe("a\nb\n\nShowing chars 1-4 of 8. Pass offset=4 for more.");
      expect(renderTextPage("a\nb\n", 99)).toContain("past the end");
    });
  });
});

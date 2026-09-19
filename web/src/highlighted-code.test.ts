import { describe, expect, it } from "vitest";

import {
  MAX_HIGHLIGHT_CHARACTERS,
  MAX_HIGHLIGHT_LINES,
  shouldHighlight,
} from "./highlighted-code";

describe("syntax highlighting bounds", () => {
  it("accepts representative source and rejects oversized input", () => {
    expect(shouldHighlight("fn main() {}\n")).toBe(true);
    expect(shouldHighlight("x".repeat(MAX_HIGHLIGHT_CHARACTERS + 1))).toBe(
      false,
    );
    expect(shouldHighlight("\n".repeat(MAX_HIGHLIGHT_LINES))).toBe(false);
  });
});

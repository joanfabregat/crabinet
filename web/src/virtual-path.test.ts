import { describe, expect, it } from "vitest";

import { isValidPathComponent, isValidVirtualPath } from "./virtual-path";

describe("virtual path grammar", () => {
  it("accepts the root and canonical NFC Unicode components", () => {
    expect(isValidVirtualPath("")).toBe(true);
    expect(isValidVirtualPath("Café/東京 🚀/report.v1.md")).toBe(true);
    expect(isValidPathComponent("100% complete")).toBe(true);
  });

  it.each([
    ".",
    "..",
    "folder/name",
    "folder\\name",
    "control\u0000",
    "control\u001f",
    "control\u007f",
    "control\u0085",
    "literal%2e",
    "literal%AF",
    "trailing.",
    "trailing ",
    "Cafe\u0301",
    "\ud800",
    "\udc00",
  ])("rejects ambiguous component %j", (component) => {
    expect(isValidPathComponent(component)).toBe(false);
  });

  it.each(["/absolute", "one/", "one//two", "one/../two", "one/Cafe\u0301"])(
    "rejects non-canonical path %j",
    (path) => {
      expect(isValidVirtualPath(path)).toBe(false);
    },
  );
});

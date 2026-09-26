import { describe, expect, it } from "vitest";

import { entryIconKind } from "./file-icons";

describe("entryIconKind", () => {
  it("uses a small stable mapping with a generic fallback", () => {
    expect(entryIconKind({ kind: "directory", name: "src.rs" })).toBe("folder");
    expect(entryIconKind({ kind: "directory", name: ".config" })).toBe(
      "hidden-folder",
    );
    expect(entryIconKind({ kind: "file", name: "README.MD" })).toBe("text");
    expect(entryIconKind({ kind: "file", name: "main.RS" })).toBe("code");
    expect(entryIconKind({ kind: "file", name: "data.json" })).toBe("json");
    expect(entryIconKind({ kind: "file", name: "photo.webp" })).toBe("image");
    expect(entryIconKind({ kind: "file", name: ".gitignore" })).toBe("file");
    expect(entryIconKind({ kind: "file", name: "archive.unknown" })).toBe(
      "file",
    );
  });
});

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  applyThemePreference,
  readLegacyThemePreference,
  readThemePreference,
  saveThemePreference,
  subscribeThemePreference,
  themePreferenceKey,
  themeSyncedKey,
} from "./theme";

describe("theme preference", () => {
  it("defaults to the system theme and ignores unknown stored values", () => {
    expect(readThemePreference()).toBe("system");
    window.localStorage.setItem(themePreferenceKey, "sepia");
    expect(readThemePreference()).toBe("system");
  });

  it("pins a theme on the root element and clears it for system", () => {
    saveThemePreference("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(readThemePreference()).toBe("light");

    saveThemePreference("system");
    expect(document.documentElement.dataset.theme).toBeUndefined();
    expect(window.localStorage.getItem(themePreferenceKey)).toBeNull();
  });

  it("still applies the theme when storage is blocked", () => {
    const blocked = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new DOMException("blocked", "SecurityError");
      });
    try {
      saveThemePreference("dark");
      expect(document.documentElement.dataset.theme).toBe("dark");
    } finally {
      blocked.mockRestore();
    }
  });

  it("follows changes made in another tab", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeThemePreference(listener);
    window.localStorage.setItem(themePreferenceKey, "dark");
    window.dispatchEvent(
      new StorageEvent("storage", { key: themePreferenceKey }),
    );
    window.dispatchEvent(new StorageEvent("storage", { key: "unrelated" }));
    unsubscribe();
    window.dispatchEvent(
      new StorageEvent("storage", { key: themePreferenceKey }),
    );
    expect(listener).toHaveBeenCalledTimes(1);
    expect(listener).toHaveBeenCalledWith("dark");
    applyThemePreference("system");
  });

  it("reports only a pinned copy that predates account settings as legacy", () => {
    expect(readLegacyThemePreference()).toBeNull();
    window.localStorage.setItem(themePreferenceKey, "light");
    expect(readLegacyThemePreference()).toBe("light");

    saveThemePreference("dark");
    expect(window.localStorage.getItem(themeSyncedKey)).toBe("1");
    expect(readLegacyThemePreference()).toBeNull();
    applyThemePreference("system");
  });
});

describe("night mode stylesheet", () => {
  // Vitest stubs CSS imports and jsdom gives import.meta.url an http scheme,
  // so read the source relative to web/, where Vitest runs.
  const styles = readFileSync(resolve("src/styles.css"), "utf8");

  function declarations(selector: string): string {
    const start = styles.indexOf(`${selector} {`);
    expect(start).toBeGreaterThanOrEqual(0);
    const body = styles.slice(start, styles.indexOf("}", start));
    return body
      .split("\n")
      .slice(1)
      .map((line) => line.trim())
      .filter(Boolean)
      .join("\n");
  }

  it("keeps the system and pinned dark palettes identical", () => {
    const system = declarations(':root:not([data-theme="light"])');
    const pinned = declarations(':root[data-theme="dark"]');
    expect(system).toContain("--ink:");
    expect(pinned).toBe(system);
    expect(
      declarations(':root:not([data-theme="light"]) .shiki-source span'),
    ).toBe(declarations(':root[data-theme="dark"] .shiki-source span'));
  });

  it("never defines a token in terms of itself", () => {
    const selfReferences = styles
      .split("\n")
      .map((line) => /^\s*(--[a-z-]+):(.*);/.exec(line))
      .filter((match) => match?.[2]?.includes(`var(${match[1]})`))
      .map((match) => match?.[0].trim());
    expect(selfReferences).toEqual([]);
  });

  it("gives every light token a dark value", () => {
    const names = (block: string) =>
      block
        .split("\n")
        .map((line) => /^(--[a-z-]+):/.exec(line)?.[1])
        .filter(Boolean)
        .sort();
    expect(names(declarations(':root[data-theme="dark"]'))).toEqual(
      names(declarations(":root")),
    );
  });
});

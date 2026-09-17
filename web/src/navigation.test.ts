import { describe, expect, it } from "vitest";

import {
  browserNavigation,
  directoryUrl,
  parentPath,
  routeFromUrl,
} from "./navigation";

describe("browser navigation", () => {
  it("round-trips Unicode share IDs and relative paths", () => {
    const href = directoryUrl("équipe/a", "Designs/東京 🚀");
    expect(href).toBe(
      "/browse/%C3%A9quipe%2Fa?path=Designs%2F%E6%9D%B1%E4%BA%AC+%F0%9F%9A%80",
    );
    expect(routeFromUrl(new URL(href, "https://index.test"))).toEqual({
      shareId: "équipe/a",
      path: "Designs/東京 🚀",
    });
  });

  it("falls back safely for unrelated or malformed routes", () => {
    expect(routeFromUrl(new URL("https://index.test/api/v1/session"))).toEqual({
      shareId: null,
      path: "",
    });
    expect(routeFromUrl(new URL("https://index.test/browse/%E0%A4%A"))).toEqual(
      {
        shareId: null,
        path: "",
      },
    );
  });

  it.each([
    ".",
    "..",
    "/absolute",
    "one/",
    "one//two",
    "one\\two",
    "control\u0001",
    "literal%2e",
    "trailing.",
    "trailing ",
    "Cafe\u0301",
  ])("falls back to the share root for ambiguous deep-link path %j", (path) => {
    const url = new URL("https://index.test/browse/docs");
    url.searchParams.set("path", path);
    expect(routeFromUrl(url)).toEqual({ shareId: "docs", path: "" });
    expect(directoryUrl("docs", path)).toBe("/browse/docs");
  });

  it("builds parent paths without escaping the share route", () => {
    expect(parentPath("one/two/three")).toBe("one/two");
    expect(parentPath("one")).toBe("");
    expect(parentPath("")).toBe("");
  });

  it("notifies subscribers when browser history restores a directory", () => {
    const routes: unknown[] = [];
    const unsubscribe = browserNavigation.subscribe((route) =>
      routes.push(route),
    );
    window.history.pushState(null, "", "/browse/docs?path=one%2Ftwo");
    window.dispatchEvent(new PopStateEvent("popstate"));

    expect(routes).toEqual([{ shareId: "docs", path: "one/two" }]);
    unsubscribe();
  });
});

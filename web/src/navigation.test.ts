import { describe, expect, it } from "vitest";

import {
  browserNavigation,
  directoryUrl,
  parentPath,
  previewRouteUrl,
  routeFromUrl,
  trashUrl,
} from "./navigation";

describe("browser navigation", () => {
  it("round-trips a per-share Trash route", () => {
    const href = trashUrl("équipe/a");
    expect(href).toBe("/trash/%C3%A9quipe%2Fa");
    expect(routeFromUrl(new URL(href, "https://crabinet.test"))).toEqual({
      shareId: "équipe/a",
      path: "",
      view: "trash",
    });
  });
  it("round-trips Unicode share IDs and relative paths", () => {
    const href = directoryUrl("équipe/a", "Designs/東京 🚀");
    expect(href).toBe(
      "/browse/%C3%A9quipe%2Fa/Designs/%E6%9D%B1%E4%BA%AC%20%F0%9F%9A%80",
    );
    expect(routeFromUrl(new URL(href, "https://crabinet.test"))).toEqual({
      shareId: "équipe/a",
      path: "Designs/東京 🚀",
    });
  });

  it("falls back safely for unrelated or malformed routes", () => {
    expect(
      routeFromUrl(new URL("https://crabinet.test/api/v1/session")),
    ).toEqual({
      shareId: null,
      path: "",
    });
    expect(
      routeFromUrl(new URL("https://crabinet.test/browse/%E0%A4%A")),
    ).toEqual({
      shareId: null,
      path: "",
    });
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
    const url = new URL("https://crabinet.test/browse/docs");
    url.searchParams.set("path", path);
    expect(routeFromUrl(url)).toEqual({ shareId: "docs", path: "" });
    expect(directoryUrl("docs", path)).toBe("/browse/docs");
  });

  it("rejects path segments that decode to a slash or an ambiguous name", () => {
    for (const href of [
      "/browse/docs/one%2Ftwo",
      "/browse/docs/literal%252e",
      "/browse/docs/trailing%20",
    ]) {
      expect(routeFromUrl(new URL(href, "https://crabinet.test"))).toEqual({
        shareId: "docs",
        path: "",
      });
    }
    expect(
      routeFromUrl(new URL("https://crabinet.test/browse/docs/one/two/")),
    ).toEqual({ shareId: "docs", path: "one/two" });
  });

  it("still reads the former ?path= links and rewrites them in place", () => {
    const legacy = "/browse/docs?path=one%2Ftwo&preview=one%2Ftwo%2Fa.md";
    expect(routeFromUrl(new URL(legacy, "https://crabinet.test"))).toEqual({
      shareId: "docs",
      path: "one/two",
      previewPath: "one/two/a.md",
    });

    window.history.replaceState(null, "", legacy);
    expect(browserNavigation.current()).toEqual({
      shareId: "docs",
      path: "one/two",
      previewPath: "one/two/a.md",
    });
    expect(window.location.pathname + window.location.search).toBe(
      "/browse/docs/one/two?preview=one%2Ftwo%2Fa.md",
    );
  });

  it("builds parent paths without escaping the share route", () => {
    expect(parentPath("one/two/three")).toBe("one/two");
    expect(parentPath("one")).toBe("");
    expect(parentPath("")).toBe("");
  });

  it("round-trips preview deep links without putting file content in history", () => {
    const href = previewRouteUrl("docs", "projects", "projects/README.md");
    expect(href).toBe("/browse/docs/projects?preview=projects%2FREADME.md");
    expect(routeFromUrl(new URL(href, "https://crabinet.test"))).toEqual({
      shareId: "docs",
      path: "projects",
      previewPath: "projects/README.md",
    });
  });

  it("round-trips an explicit full-screen preview without changing the folder", () => {
    const href = previewRouteUrl("docs", "projects", "projects/app.rs", "full");
    expect(href).toBe(
      "/browse/docs/projects?preview=projects%2Fapp.rs&view=full",
    );
    expect(routeFromUrl(new URL(href, "https://crabinet.test"))).toEqual({
      shareId: "docs",
      path: "projects",
      previewPath: "projects/app.rs",
      previewMode: "full",
    });
  });

  it("ignores an ambiguous preview path while keeping the directory route", () => {
    const url = new URL("https://crabinet.test/browse/docs/projects");
    url.searchParams.set("preview", "../secret");
    expect(routeFromUrl(url)).toEqual({ shareId: "docs", path: "projects" });
    expect(previewRouteUrl("docs", "projects", "../secret")).toBe(
      "/browse/docs/projects",
    );
  });

  it("notifies subscribers when browser history restores a directory", () => {
    const routes: unknown[] = [];
    const unsubscribe = browserNavigation.subscribe((route) =>
      routes.push(route),
    );
    window.history.pushState(null, "", "/browse/docs/one/two");
    window.dispatchEvent(new PopStateEvent("popstate"));

    expect(routes).toEqual([{ shareId: "docs", path: "one/two" }]);
    unsubscribe();
  });
});

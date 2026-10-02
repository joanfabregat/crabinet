import { describe, expect, it } from "vitest";

import {
  browserNavigation,
  directoryUrl,
  parentPath,
  previewRouteUrl,
  renderedHtmlViewUrl,
  routeFromUrl,
  trashUrl,
} from "./navigation";

const at = (href: string) =>
  routeFromUrl(new URL(href, "https://crabinet.test"));

describe("browser navigation", () => {
  it("addresses the one Trash without a share", () => {
    expect(trashUrl()).toBe("/trash");
    expect(at("/trash")).toEqual({ shareId: null, path: "", view: "trash" });
    expect(directoryUrl("work", "")).toBe("/work");
  });

  it("still opens Trash from a former per-share Trash link", () => {
    expect(at("/trash/%C3%A9quipe%2Fa")).toEqual({
      shareId: "équipe/a",
      path: "",
      view: "trash",
    });
  });

  it("round-trips Unicode share IDs and relative paths", () => {
    const href = directoryUrl("équipe/a", "Designs/東京 🚀");
    expect(href).toBe(
      "/%C3%A9quipe%2Fa/Designs/%E6%9D%B1%E4%BA%AC%20%F0%9F%9A%80",
    );
    expect(at(href)).toEqual({
      shareId: "équipe/a",
      path: "Designs/東京 🚀",
    });
  });

  it("falls back safely for the root, reserved, and malformed routes", () => {
    for (const href of [
      "/",
      "/api/v1/session",
      "/assets/index.js",
      "/API/v1/session",
      "/src/main.tsx",
      "/@vite/client",
      "/browse",
      "/%E0%A4%A",
      "/browse/%E0%A4%A",
    ]) {
      expect(at(href), href).toEqual({ shareId: null, path: "" });
    }
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
    "Café",
  ])("falls back to the share root for ambiguous deep-link path %j", (path) => {
    const url = new URL("https://crabinet.test/docs");
    url.searchParams.set("path", path);
    expect(routeFromUrl(url)).toEqual({ shareId: "docs", path: "" });
    expect(directoryUrl("docs", path)).toBe("/docs");
  });

  it("rejects path segments that decode to a slash or an ambiguous name", () => {
    for (const href of [
      "/docs/one%2Ftwo",
      "/docs/literal%252e",
      "/docs/trailing%20",
    ]) {
      expect(at(href)).toEqual({ shareId: "docs", path: "" });
    }
    expect(at("/docs/one/two/")).toEqual({ shareId: "docs", path: "one/two" });
  });

  it("builds parent paths without escaping the share route", () => {
    expect(parentPath("one/two/three")).toBe("one/two");
    expect(parentPath("one")).toBe("");
    expect(parentPath("")).toBe("");
  });

  it("addresses a file previewed from its own folder by the file path", () => {
    expect(previewRouteUrl("docs", "projects", "projects/README.md")).toBe(
      "/docs/projects/README.md",
    );
    expect(previewRouteUrl("docs", "", "notes.txt", "full")).toBe(
      "/docs/notes.txt?view=full",
    );
    // Until the app resolves it, the file path reads as a folder path.
    expect(at("/docs/projects/README.md?view=full")).toEqual({
      shareId: "docs",
      path: "projects/README.md",
      previewMode: "full",
    });
  });

  it("addresses the full-window rendered HTML viewer by the file path", () => {
    const href = renderedHtmlViewUrl("my docs", "site/index page.html");
    expect(href).toBe("/my%20docs/site/index%20page.html?view=rendered");
    expect(href).not.toContain("/api/");
    expect(at(href)).toEqual({
      shareId: "my docs",
      path: "site/index page.html",
      view: "rendered",
    });
  });

  it("opens the share instead of a rendered viewer without a valid file", () => {
    expect(renderedHtmlViewUrl("docs", "")).toBe("/docs");
    expect(renderedHtmlViewUrl("docs", "../secret.html")).toBe("/docs");
    expect(at("/docs?view=rendered")).toEqual({ shareId: "docs", path: "" });
    expect(at("/docs/a%2Fb.html?view=rendered")).toEqual({
      shareId: "docs",
      path: "",
    });
  });

  it("keeps ?preview= for a file outside the folder being browsed", () => {
    const href = previewRouteUrl("docs", "projects", "other/app.rs", "full");
    expect(href).toBe("/docs/projects?preview=other%2Fapp.rs&view=full");
    expect(at(href)).toEqual({
      shareId: "docs",
      path: "projects",
      previewPath: "other/app.rs",
      previewMode: "full",
    });
  });

  it("ignores an ambiguous preview path while keeping the directory route", () => {
    const url = new URL("https://crabinet.test/docs/projects");
    url.searchParams.set("preview", "../secret");
    expect(routeFromUrl(url)).toEqual({ shareId: "docs", path: "projects" });
    expect(previewRouteUrl("docs", "projects", "../secret")).toBe(
      "/docs/projects",
    );
  });

  it.each([
    "/browse/docs?path=one%2Ftwo&preview=one%2Ftwo%2Fa.md",
    "/browse/docs/one/two?preview=one%2Ftwo%2Fa.md",
    "/docs/one/two?preview=one%2Ftwo%2Fa.md",
  ])("reads the former link %s and rewrites it in place", (legacy) => {
    const route = {
      shareId: "docs",
      path: "one/two",
      previewPath: "one/two/a.md",
    };
    expect(at(legacy)).toEqual(route);

    window.history.replaceState(null, "", legacy);
    expect(browserNavigation.current()).toEqual(route);
    expect(window.location.pathname + window.location.search).toBe(
      "/docs/one/two/a.md",
    );
  });

  it("keeps a resolved file route across reloads and history traversal", () => {
    const file = { shareId: "docs", path: "one", previewPath: "one/a.md" };
    browserNavigation.go(file, { replace: true });
    expect(window.location.pathname).toBe("/docs/one/a.md");
    expect(browserNavigation.current()).toEqual(file);

    const routes: unknown[] = [];
    const unsubscribe = browserNavigation.subscribe((route) =>
      routes.push(route),
    );
    window.dispatchEvent(new PopStateEvent("popstate"));
    unsubscribe();
    expect(routes).toEqual([file]);
  });

  it("notifies subscribers when browser history restores a directory", () => {
    const routes: unknown[] = [];
    const unsubscribe = browserNavigation.subscribe((route) =>
      routes.push(route),
    );
    window.history.pushState(null, "", "/docs/one/two");
    window.dispatchEvent(new PopStateEvent("popstate"));

    expect(routes).toEqual([{ shareId: "docs", path: "one/two" }]);
    unsubscribe();
  });
});

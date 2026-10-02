import { isValidVirtualPath } from "./virtual-path";

export interface BrowserRoute {
  shareId: string | null;
  path: string;
  /**
   * `rendered` shows the HTML file named by `path` alone, full-window, in the
   * same sandboxed iframe as its preview. The UI never opens the rendered-HTML
   * endpoint as a top-level document, where the page could navigate itself.
   */
  view?: "trash" | "rendered";
  /** A virtual file path selected for preview, or null when browsing only. */
  previewPath?: string | null;
  previewMode?: "side" | "full";
}

export interface BrowserNavigation {
  current(): BrowserRoute;
  go(route: BrowserRoute, options?: { replace?: boolean }): void;
  subscribe(listener: (route: BrowserRoute) => void): () => void;
}

/**
 * A URL ending in a file name reads the same as one ending in a folder
 * name, so each history entry keeps the route the app resolved for it.
 */
function historyRoute(url: URL): BrowserRoute {
  const saved: unknown = (window.history.state as { route?: unknown } | null)
    ?.route;
  if (
    saved &&
    typeof saved === "object" &&
    browserUrl(saved as BrowserRoute) === url.pathname + url.search
  ) {
    return { ...(saved as BrowserRoute) };
  }
  return routeFromUrl(url);
}

export const browserNavigation: BrowserNavigation = {
  current: () => {
    const url = new URL(window.location.href);
    const route = historyRoute(url);
    const canonical = browserUrl(route);
    // Rewrite bookmarks from the former /browse/, /trash/<share>, ?path= and
    // ?preview= forms.
    if (
      route.shareId &&
      canonical !== url.pathname + url.search &&
      (url.pathname.startsWith("/browse/") ||
        url.pathname.startsWith("/trash/") ||
        url.searchParams.has("path") ||
        url.searchParams.has("preview"))
    ) {
      window.history.replaceState({ route }, "", canonical + url.hash);
    }
    return route;
  },
  go: (route, options) => {
    const url = browserUrl(route);
    if (options?.replace) {
      window.history.replaceState({ route }, "", url);
    } else {
      window.history.pushState({ route }, "", url);
    }
    window.dispatchEvent(new PopStateEvent("popstate"));
  },
  subscribe: (listener) => {
    const handlePopState = () =>
      listener(historyRoute(new URL(window.location.href)));
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  },
};

export function routeFromUrl(url: URL): BrowserRoute {
  // One Trash lists every share. A former per-share `/trash/<share>` link
  // still opens it, starting from that share.
  const trashMatch = /^\/trash(?:\/([^/]+))?\/?$/.exec(url.pathname);
  if (trashMatch) {
    try {
      return {
        shareId: trashMatch[1] ? decodeURIComponent(trashMatch[1]) : null,
        path: "",
        view: "trash",
      };
    } catch {
      return { shareId: null, path: "", view: "trash" };
    }
  }
  // `/browse/` is the former prefix; links using it still resolve.
  const match = /^\/(?:browse\/)?([^/]+)(?:\/(.*))?$/.exec(url.pathname);
  if (!match || isReservedShareId(match[1]!)) {
    return { shareId: null, path: "" };
  }

  try {
    const segments = (match[2] ?? "")
      .split("/")
      .filter(Boolean)
      .map(decodeURIComponent);
    // An encoded slash cannot come from a real folder name.
    const path = segments.some((segment) => segment.includes("/"))
      ? ""
      : segments.join("/") || (url.searchParams.get("path") ?? "");
    if (url.searchParams.get("view") === "rendered") {
      const shareId = decodeURIComponent(match[1]!);
      return path && isValidVirtualPath(path)
        ? { shareId, path, view: "rendered" }
        : { shareId, path: "" };
    }
    const previewPath = url.searchParams.get("preview");
    const route: BrowserRoute = {
      shareId: decodeURIComponent(match[1]!),
      path: isValidVirtualPath(path) ? path : "",
    };
    if (previewPath !== null && isValidVirtualPath(previewPath)) {
      route.previewPath = previewPath;
    }
    // Without ?preview= the last segment may still name a file; the app
    // resolves that and keeps the requested full-screen mode.
    if (url.searchParams.get("view") === "full") route.previewMode = "full";
    return route;
  } catch {
    return { shareId: null, path: "" };
  }
}

/**
 * First URL segments that belong to the server or the dev server rather than
 * a share. Keep in sync with `RESERVED_SHARE_IDS` in `src/config.rs`, which
 * refuses to start with a share that uses one.
 */
const reservedShareIds = new Set([
  "api",
  "assets",
  "browse",
  "crabinet.png",
  "favicon.ico",
  "google-g.png",
  "health",
  "index.html",
  "node_modules",
  "src",
  "trash",
]);

function isReservedShareId(segment: string): boolean {
  return reservedShareIds.has(segment.toLowerCase()) || segment.startsWith("@");
}

export function directoryUrl(shareId: string | null, path: string): string {
  return browserUrl({ shareId, path });
}

export function trashUrl(): string {
  return "/trash";
}

/** The full-window sandboxed viewer for one HTML file. */
export function renderedHtmlViewUrl(shareId: string, path: string): string {
  return browserUrl({ shareId, path, view: "rendered" });
}

export function previewRouteUrl(
  shareId: string,
  directoryPath: string,
  previewPath: string,
  previewMode: "side" | "full" = "side",
): string {
  return browserUrl({ shareId, path: directoryPath, previewPath, previewMode });
}

function browserUrl(route: BrowserRoute): string {
  const { shareId } = route;
  if (route.view === "trash") return trashUrl();
  if (!shareId) return "/";
  const query = new URLSearchParams();
  const safePath = isValidVirtualPath(route.path) ? route.path : "";
  if (route.view === "rendered" && safePath) {
    query.set("view", "rendered");
    return `/${encodeURIComponent(shareId)}${pathSuffix(safePath)}?${query.toString()}`;
  }
  const previewPath =
    route.previewPath && isValidVirtualPath(route.previewPath)
      ? route.previewPath
      : null;
  // A file previewed from its own folder is addressed by its own path.
  const inline = previewPath !== null && parentPath(previewPath) === safePath;
  if (previewPath !== null && !inline) query.set("preview", previewPath);
  // Also kept before a file link resolves, so full screen survives it.
  if (route.previewMode === "full") query.set("view", "full");
  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  return `/${encodeURIComponent(shareId)}${pathSuffix(inline ? previewPath : safePath)}${suffix}`;
}

function pathSuffix(path: string): string {
  return path
    .split("/")
    .filter(Boolean)
    .map((segment) => `/${encodeURIComponent(segment)}`)
    .join("");
}

export function parentPath(path: string): string {
  if (!isValidVirtualPath(path)) return "";
  const segments = path.split("/").filter(Boolean);
  return segments.slice(0, -1).join("/");
}

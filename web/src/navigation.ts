import { isValidVirtualPath } from "./virtual-path";

export interface BrowserRoute {
  shareId: string | null;
  path: string;
  /** A virtual file path selected for preview, or null when browsing only. */
  previewPath?: string | null;
  previewMode?: "side" | "full";
}

export interface BrowserNavigation {
  current(): BrowserRoute;
  go(route: BrowserRoute, options?: { replace?: boolean }): void;
  subscribe(listener: (route: BrowserRoute) => void): () => void;
}

export const browserNavigation: BrowserNavigation = {
  current: () => routeFromUrl(new URL(window.location.href)),
  go: (route, options) => {
    const url = browserUrl(route);
    if (options?.replace) {
      window.history.replaceState(null, "", url);
    } else {
      window.history.pushState(null, "", url);
    }
    window.dispatchEvent(new PopStateEvent("popstate"));
  },
  subscribe: (listener) => {
    const handlePopState = () =>
      listener(routeFromUrl(new URL(window.location.href)));
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  },
};

export function routeFromUrl(url: URL): BrowserRoute {
  const match = /^\/browse\/([^/]+)\/?$/.exec(url.pathname);
  if (!match) return { shareId: null, path: "" };

  try {
    const path = url.searchParams.get("path") ?? "";
    const previewPath = url.searchParams.get("preview");
    const route: BrowserRoute = {
      shareId: decodeURIComponent(match[1]!),
      path: isValidVirtualPath(path) ? path : "",
    };
    if (previewPath !== null && isValidVirtualPath(previewPath)) {
      route.previewPath = previewPath;
      if (url.searchParams.get("view") === "full") route.previewMode = "full";
    }
    return route;
  } catch {
    return { shareId: null, path: "" };
  }
}

export function directoryUrl(shareId: string | null, path: string): string {
  return browserUrl({ shareId, path });
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
  if (!shareId) return "/";
  const query = new URLSearchParams();
  const safePath = isValidVirtualPath(route.path) ? route.path : "";
  if (safePath) query.set("path", safePath);
  if (route.previewPath && isValidVirtualPath(route.previewPath)) {
    query.set("preview", route.previewPath);
    if (route.previewMode === "full") query.set("view", "full");
  }
  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  return `/browse/${encodeURIComponent(shareId)}${suffix}`;
}

export function parentPath(path: string): string {
  if (!isValidVirtualPath(path)) return "";
  const segments = path.split("/").filter(Boolean);
  return segments.slice(0, -1).join("/");
}

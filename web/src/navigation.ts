import { isValidVirtualPath } from "./virtual-path";

export interface BrowserRoute {
  shareId: string | null;
  path: string;
}

export interface BrowserNavigation {
  current(): BrowserRoute;
  go(route: BrowserRoute, options?: { replace?: boolean }): void;
  subscribe(listener: (route: BrowserRoute) => void): () => void;
}

export const browserNavigation: BrowserNavigation = {
  current: () => routeFromUrl(new URL(window.location.href)),
  go: (route, options) => {
    const url = directoryUrl(route.shareId, route.path);
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
    return {
      shareId: decodeURIComponent(match[1]!),
      path: isValidVirtualPath(path) ? path : "",
    };
  } catch {
    return { shareId: null, path: "" };
  }
}

export function directoryUrl(shareId: string | null, path: string): string {
  if (!shareId) return "/";
  const query = new URLSearchParams();
  const safePath = isValidVirtualPath(path) ? path : "";
  if (safePath) query.set("path", safePath);
  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  return `/browse/${encodeURIComponent(shareId)}${suffix}`;
}

export function parentPath(path: string): string {
  if (!isValidVirtualPath(path)) return "";
  const segments = path.split("/").filter(Boolean);
  return segments.slice(0, -1).join("/");
}

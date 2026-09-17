import { type JSX } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";

import {
  ApiError,
  createApiClient,
  type ApiClient,
  type DirectoryEntry,
  type DirectoryPage,
  type Session,
  type Share,
} from "./api";
import {
  browserNavigation,
  directoryUrl,
  parentPath,
  type BrowserNavigation,
  type BrowserRoute,
} from "./navigation";

const defaultApi = createApiClient();

type AuthState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "guest"; reason?: "expired" }
  | { status: "authenticated"; session: Session };

export interface AppProps {
  api?: ApiClient;
  navigation?: BrowserNavigation;
}

export function App({
  api = defaultApi,
  navigation = browserNavigation,
}: AppProps) {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const [route, setRoute] = useState<BrowserRoute>(() => navigation.current());
  const [sessionRefreshKey, setSessionRefreshKey] = useState(0);

  useEffect(() => navigation.subscribe(setRoute), [navigation]);

  useEffect(() => {
    const controller = new AbortController();

    api.session(controller.signal).then(
      (session) => setAuth({ status: "authenticated", session }),
      (error: unknown) => {
        if (isAborted(error)) return;
        setAuth(
          isUnauthorized(error) ? { status: "guest" } : { status: "error" },
        );
      },
    );

    return () => controller.abort();
  }, [api, sessionRefreshKey]);

  useEffect(() => {
    if (auth.status !== "authenticated" || auth.session.shares.length === 0)
      return;
    const routeIsAllowed = auth.session.shares.some(
      (share) => share.id === route.shareId,
    );
    if (!routeIsAllowed) {
      navigation.go(
        { shareId: auth.session.shares[0]!.id, path: "" },
        { replace: true },
      );
    }
  }, [auth, navigation, route.shareId]);

  if (auth.status === "loading") return <LoadingScreen />;

  if (auth.status === "error") {
    return (
      <SessionErrorScreen
        onRetry={() => {
          setAuth({ status: "loading" });
          setSessionRefreshKey((value) => value + 1);
        }}
      />
    );
  }

  if (auth.status === "guest") {
    return (
      <LoginScreen
        api={api}
        reason={auth.reason}
        onAuthenticated={(session) =>
          setAuth({ status: "authenticated", session })
        }
      />
    );
  }

  return (
    <AuthenticatedShell
      api={api}
      navigation={navigation}
      route={route}
      session={auth.session}
      onSessionExpired={() => setAuth({ status: "guest", reason: "expired" })}
      onSignedOut={() => setAuth({ status: "guest" })}
    />
  );
}

function AppHeader({ children }: { children?: preact.ComponentChildren }) {
  return (
    <header class="app-header">
      <a class="brand" href="/" aria-label="Index home">
        <span class="brand-mark" aria-hidden="true">
          I
        </span>
        <span>Index</span>
      </a>
      {children}
    </header>
  );
}

function LoadingScreen() {
  return (
    <div class="app-frame">
      <AppHeader />
      <main class="centered-panel" aria-busy="true">
        <p class="status-message" role="status">
          Loading your files…
        </p>
      </main>
    </div>
  );
}

function SessionErrorScreen({ onRetry }: { onRetry: () => void }) {
  return (
    <div class="app-frame">
      <AppHeader />
      <main class="centered-panel">
        <div class="empty-state" role="alert">
          <h1>Index is unavailable</h1>
          <p>Check your connection and try again.</p>
          <Button onClick={onRetry}>Try again</Button>
        </div>
      </main>
    </div>
  );
}

interface LoginScreenProps {
  api: ApiClient;
  reason?: "expired";
  onAuthenticated: (session: Session) => void;
}

function LoginScreen({ api, reason, onAuthenticated }: LoginScreenProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: JSX.TargetedSubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (pending) return;

    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const username = String(form.get("username") ?? "");
    const password = String(form.get("password") ?? "");
    setPending(true);
    setError(undefined);

    try {
      const session = await api.login({ username, password });
      formElement.reset();
      onAuthenticated(session);
    } catch (cause) {
      if (!isAborted(cause)) {
        setError("Sign-in failed. Check your credentials and try again.");
      }
    } finally {
      setPending(false);
    }
  };

  return (
    <div class="app-frame">
      <AppHeader />
      <main class="login-layout">
        <section class="login-card" aria-labelledby="login-title">
          <p class="eyebrow">Private workspace</p>
          <h1 id="login-title">Sign in to Index</h1>
          <p class="muted">
            Browse the folders that have been shared with you.
          </p>
          {reason === "expired" && (
            <Notice tone="warning">
              Your session expired. Sign in again to continue.
            </Notice>
          )}
          {error && <Notice tone="danger">{error}</Notice>}
          <form class="login-form" onSubmit={submit}>
            <label for="username">Username</label>
            <input
              id="username"
              name="username"
              type="text"
              autocomplete="username"
              autocapitalize="none"
              required
              disabled={pending}
            />
            <label for="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              autocomplete="current-password"
              required
              disabled={pending}
            />
            <Button type="submit" busy={pending}>
              {pending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </section>
      </main>
    </div>
  );
}

interface AuthenticatedShellProps {
  api: ApiClient;
  navigation: BrowserNavigation;
  route: BrowserRoute;
  session: Session;
  onSessionExpired: () => void;
  onSignedOut: () => void;
}

function AuthenticatedShell({
  api,
  navigation,
  route,
  session,
  onSessionExpired,
  onSignedOut,
}: AuthenticatedShellProps) {
  const [signingOut, setSigningOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string>();
  const selectedShare = session.shares.find(
    (share) => share.id === route.shareId,
  );

  const logout = async () => {
    setSigningOut(true);
    setLogoutError(undefined);
    try {
      await api.logout(session.csrfToken);
      onSignedOut();
    } catch (error) {
      if (isUnauthorized(error)) {
        onSignedOut();
      } else if (!isAborted(error)) {
        setLogoutError(
          "Could not sign out. Check your connection and try again.",
        );
      }
    } finally {
      setSigningOut(false);
    }
  };

  return (
    <div class="app-frame">
      <AppHeader>
        <div class="account-actions">
          <span class="account-name">{session.user.displayName}</span>
          <Button variant="secondary" busy={signingOut} onClick={logout}>
            {signingOut ? "Signing out…" : "Sign out"}
          </Button>
        </div>
      </AppHeader>
      {logoutError && (
        <div class="global-notice">
          <Notice tone="danger">{logoutError}</Notice>
        </div>
      )}
      <main class="browser-layout">
        <section class="browser-toolbar" aria-label="File browser controls">
          <label for="share-select">Shared folder</label>
          <select
            id="share-select"
            value={selectedShare?.id ?? ""}
            disabled={session.shares.length === 0}
            onChange={(event) =>
              navigation.go({ shareId: event.currentTarget.value, path: "" })
            }
          >
            {session.shares.map((share) => (
              <option key={share.id} value={share.id}>
                {share.name} — {accessLabel(share)}
              </option>
            ))}
          </select>
          {selectedShare && <AccessBadge share={selectedShare} />}
        </section>

        {session.shares.length === 0 ? (
          <EmptyState
            title="No shared folders"
            detail="An administrator has not shared any folders with this account."
          />
        ) : selectedShare ? (
          <DirectoryBrowser
            api={api}
            navigation={navigation}
            route={route}
            share={selectedShare}
            onSessionExpired={onSessionExpired}
          />
        ) : (
          <p role="status">Opening a shared folder…</p>
        )}
      </main>
    </div>
  );
}

interface DirectoryBrowserProps {
  api: ApiClient;
  navigation: BrowserNavigation;
  route: BrowserRoute;
  share: Share;
  onSessionExpired: () => void;
}

function DirectoryBrowser({
  api,
  navigation,
  route,
  share,
  onSessionExpired,
}: DirectoryBrowserProps) {
  const [page, setPage] = useState<DirectoryPage>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<ApiError>();
  const [refreshKey, setRefreshKey] = useState(0);
  const loadMoreController = useRef<AbortController>();
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    loadMoreController.current?.abort();
    setLoading(true);
    setPage(undefined);
    setError(undefined);

    api.directory(share.id, route.path, undefined, controller.signal).then(
      (result) => {
        setPage(result);
        setLoading(false);
        requestAnimationFrame(() => headingRef.current?.focus());
      },
      (cause: unknown) => {
        if (isAborted(cause)) return;
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
        setError(asApiError(cause));
        setLoading(false);
      },
    );

    return () => {
      controller.abort();
      loadMoreController.current?.abort();
    };
  }, [api, onSessionExpired, refreshKey, route.path, share.id]);

  const loadMore = async () => {
    if (!page?.nextCursor || loadingMore) return;
    const controller = new AbortController();
    loadMoreController.current = controller;
    setLoadingMore(true);
    setError(undefined);
    try {
      const next = await api.directory(
        share.id,
        route.path,
        page.nextCursor,
        controller.signal,
      );
      setPage((current) =>
        current
          ? {
              ...next,
              entries: mergeEntries(current.entries, next.entries),
            }
          : next,
      );
    } catch (cause) {
      if (isUnauthorized(cause)) {
        onSessionExpired();
      } else if (!isAborted(cause)) {
        setError(asApiError(cause));
      }
    } finally {
      setLoadingMore(false);
    }
  };

  const crumbs = breadcrumbItems(route.path);

  return (
    <section class="directory-panel" aria-labelledby="directory-title">
      <nav class="breadcrumbs" aria-label="Breadcrumb">
        <ol>
          <li>
            <a
              href={directoryUrl(share.id, "")}
              aria-current={route.path === "" ? "page" : undefined}
              onClick={(event) => {
                event.preventDefault();
                navigation.go({ shareId: share.id, path: "" });
              }}
            >
              {share.name}
            </a>
          </li>
          {crumbs.map((crumb, index) => (
            <li key={crumb.path}>
              <span aria-hidden="true">/</span>
              <a
                href={directoryUrl(share.id, crumb.path)}
                aria-current={index === crumbs.length - 1 ? "page" : undefined}
                onClick={(event) => {
                  event.preventDefault();
                  navigation.go({ shareId: share.id, path: crumb.path });
                }}
              >
                {crumb.name}
              </a>
            </li>
          ))}
        </ol>
      </nav>

      <div class="directory-heading">
        <div>
          <p class="eyebrow">Current folder</p>
          <h1 id="directory-title" ref={headingRef} tabIndex={-1}>
            {crumbs.at(-1)?.name ?? share.name}
          </h1>
        </div>
        <Button
          variant="secondary"
          onClick={() => setRefreshKey((value) => value + 1)}
        >
          Refresh
        </Button>
      </div>

      <div class="sr-only" role="status" aria-live="polite">
        {loading
          ? "Loading folder"
          : page
            ? `${page.entries.length} items loaded`
            : "Folder unavailable"}
      </div>

      {loading ? (
        <DirectorySkeleton />
      ) : error && !page ? (
        <DirectoryError
          error={error}
          shareId={share.id}
          path={route.path}
          navigation={navigation}
          retry={() => setRefreshKey((value) => value + 1)}
        />
      ) : page && page.entries.length === 0 ? (
        <EmptyState
          title="This folder is empty"
          detail="There are no files or folders here."
        />
      ) : page ? (
        <>
          <EntryList
            entries={page.entries}
            shareId={share.id}
            path={route.path}
            navigation={navigation}
          />
          {error && (
            <Notice tone="danger">
              More items could not be loaded. The folder may have changed;
              refresh and try again.
            </Notice>
          )}
          {page.nextCursor && (
            <div class="load-more">
              <Button variant="secondary" busy={loadingMore} onClick={loadMore}>
                {loadingMore ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      ) : null}
    </section>
  );
}

function EntryList({
  entries,
  shareId,
  path,
  navigation,
}: {
  entries: DirectoryEntry[];
  shareId: string;
  path: string;
  navigation: BrowserNavigation;
}) {
  return (
    <div class="entry-list" role="list" aria-label="Folder contents">
      {entries.map((entry) => {
        const key = `${entry.kind}:${entry.name}`;
        return (
          <div class="entry-row" role="listitem" key={key}>
            <span
              class={`entry-icon entry-icon-${entry.kind}`}
              aria-hidden="true"
            >
              {entry.kind === "directory" ? "▰" : "▪"}
            </span>
            <div class="entry-primary">
              {entry.kind === "directory" ? (
                <a
                  class="entry-name"
                  href={directoryUrl(shareId, joinPath(path, entry.name))}
                  onClick={(event) => {
                    event.preventDefault();
                    navigation.go({
                      shareId,
                      path: joinPath(path, entry.name),
                    });
                  }}
                >
                  {entry.name}
                </a>
              ) : (
                <span class="entry-name">{entry.name}</span>
              )}
              <span class="entry-kind">
                {entry.kind === "directory" ? "Folder" : "File"}
              </span>
            </div>
            <span class="entry-meta">{formatSize(entry.size)}</span>
          </div>
        );
      })}
    </div>
  );
}

function DirectoryError({
  error,
  shareId,
  path,
  navigation,
  retry,
}: {
  error: ApiError;
  shareId: string;
  path: string;
  navigation: BrowserNavigation;
  retry: () => void;
}) {
  const missing = error.kind === "not-found";
  return (
    <div class="empty-state" role="alert">
      <h2>
        {missing
          ? "This folder is no longer available"
          : "We could not load this folder"}
      </h2>
      <p>
        {missing
          ? "It may have been moved or deleted."
          : "Check your connection and try again. If the problem continues, contact an administrator."}
      </p>
      <div class="button-row">
        {path !== "" && (
          <Button
            variant="secondary"
            onClick={() => navigation.go({ shareId, path: parentPath(path) })}
          >
            Go to parent folder
          </Button>
        )}
        <Button onClick={retry}>Try again</Button>
      </div>
    </div>
  );
}

function DirectorySkeleton() {
  return (
    <div class="directory-skeleton" aria-hidden="true">
      <span />
      <span />
      <span />
    </div>
  );
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div class="empty-state">
      <span class="empty-icon" aria-hidden="true">
        ◇
      </span>
      <h2>{title}</h2>
      <p>{detail}</p>
    </div>
  );
}

function AccessBadge({ share }: { share: Share }) {
  return (
    <span class={`access-badge access-${share.access}`}>
      {share.access === "read-write" ? "Read & write" : "Read only"}
    </span>
  );
}

function Notice({
  children,
  tone,
}: {
  children: preact.ComponentChildren;
  tone: "danger" | "warning";
}) {
  return (
    <div
      class={`notice notice-${tone}`}
      role={tone === "danger" ? "alert" : "status"}
    >
      {children}
    </div>
  );
}

function Button({
  busy = false,
  variant = "primary",
  children,
  ...props
}: JSX.ButtonHTMLAttributes<HTMLButtonElement> & {
  busy?: boolean;
  variant?: "primary" | "secondary";
}) {
  return (
    <button
      {...props}
      class={`button button-${variant}`}
      disabled={busy || Boolean(props.disabled)}
      aria-busy={busy || undefined}
    >
      {children}
    </button>
  );
}

function accessLabel(share: Share): string {
  return share.access === "read-write" ? "Read & write" : "Read only";
}

function joinPath(path: string, name: string): string {
  return path ? `${path}/${name}` : name;
}

function breadcrumbItems(path: string): Array<{ name: string; path: string }> {
  const segments = path.split("/").filter(Boolean);
  return segments.map((name, index) => ({
    name,
    path: segments.slice(0, index + 1).join("/"),
  }));
}

function formatSize(size: number | undefined): string {
  if (size === undefined) return "—";
  if (size < 1_000) return `${size} B`;
  if (size < 1_000_000) return `${(size / 1_000).toFixed(1)} kB`;
  if (size < 1_000_000_000) return `${(size / 1_000_000).toFixed(1)} MB`;
  return `${(size / 1_000_000_000).toFixed(1)} GB`;
}

function mergeEntries(
  current: DirectoryEntry[],
  next: DirectoryEntry[],
): DirectoryEntry[] {
  const seen = new Set(
    current.map((entry) => `${entry.kind}\u0000${entry.name}`),
  );
  return current.concat(
    next.filter((entry) => {
      const key = `${entry.kind}\u0000${entry.name}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  );
}

function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.kind === "unauthorized";
}

function isAborted(error: unknown): boolean {
  return (
    (error instanceof ApiError && error.kind === "aborted") ||
    (error instanceof DOMException && error.name === "AbortError")
  );
}

function asApiError(error: unknown): ApiError {
  return error instanceof ApiError
    ? error
    : new ApiError("network", "The request could not be completed", {
        retryable: true,
      });
}

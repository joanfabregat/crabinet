import { type JSX } from "preact";
import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import {
  Code2,
  Download,
  ExternalLink,
  FilePenLine,
  FolderInput,
  LogOut,
  Maximize2,
  Minimize2,
  Pencil,
  Settings2,
  Trash2,
  Upload,
  X,
} from "lucide-preact";

import {
  ApiError,
  createApiClient,
  directoryEventsUrl,
  downloadUrl,
  htmlPreviewUrl,
  imagePreviewUrl,
  renderedHtmlPreviewUrl,
  type ApiClient,
  type AuthMethods,
  type DirectoryEntry,
  type DirectoryPage,
  type DefaultFolder,
  type EntryMetadata,
  type PreviewDocument,
  type Session,
  type Share,
} from "./api";
import {
  EntryActionButtons,
  Modal,
  OperationDialog,
  UploadQueue,
  WriteToolbar,
  type EntryOperation,
  type UploadSelection,
} from "./operations";
import { EntryIcon } from "./file-icons";
import { HighlightedCode } from "./highlighted-code";
import { CopyPathButton } from "./copy-path-button";
import {
  browserNavigation,
  directoryUrl,
  parentPath,
  previewRouteUrl,
  type BrowserNavigation,
  type BrowserRoute,
} from "./navigation";
import { SafeMarkdown } from "./safe-markdown";
import { TooltipLayer } from "./tooltip-layer";
import { beginEntryDrag, ShareTree } from "./tree";

const defaultApi = createApiClient();
const defaultOidcRedirect = (url: string) => window.location.assign(url);
declare const __CRABINET_DEV_REVISION__: string | null;

function hiddenFilesPreferenceKey(userId: string): string {
  return `crabinet.showHiddenFiles.${userId}`;
}

function readShowHiddenFiles(userId: string): boolean {
  try {
    return (
      window.localStorage.getItem(hiddenFilesPreferenceKey(userId)) !== "false"
    );
  } catch {
    return true;
  }
}

type AuthState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "guest"; reason?: "expired" | "signed_out" }
  | { status: "authenticated"; session: Session };

export interface AppProps {
  api?: ApiClient;
  navigation?: BrowserNavigation;
  onOidcRedirect?: (url: string) => void;
}

export function App({
  api = defaultApi,
  navigation = browserNavigation,
  onOidcRedirect = defaultOidcRedirect,
}: AppProps) {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const [route, setRoute] = useState<BrowserRoute>(() => navigation.current());
  const [sessionRefreshKey, setSessionRefreshKey] = useState(0);
  const handleSessionExpired = useCallback(
    () => setAuth({ status: "guest", reason: "expired" }),
    [],
  );
  const handleSignedOut = useCallback(
    () => setAuth({ status: "guest", reason: "signed_out" }),
    [],
  );

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
      const startFolder =
        route.shareId === null ? auth.session.defaultFolder : null;
      navigation.go(
        startFolder ?? { shareId: auth.session.shares[0]!.id, path: "" },
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
        onOidcRedirect={onOidcRedirect}
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
      onSessionExpired={handleSessionExpired}
      onSignedOut={handleSignedOut}
      onDefaultFolderChanged={(folder) =>
        setAuth((current) =>
          current.status === "authenticated"
            ? {
                ...current,
                session: { ...current.session, defaultFolder: folder },
              }
            : current,
        )
      }
      onSessionRefreshed={(session) =>
        setAuth((current) =>
          current.status === "authenticated" &&
          current.session.user.id === session.user.id
            ? { status: "authenticated", session }
            : current,
        )
      }
    />
  );
}

function AppHeader({ children }: { children?: preact.ComponentChildren }) {
  return (
    <header class="app-header">
      <a class="brand" href="/" aria-label="Crabinet home">
        <img class="brand-mark" src="/crabinet.png" alt="" />
        <span>Crabinet</span>
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
          <h1>Crabinet is unavailable</h1>
          <p>Check your connection and try again.</p>
          <Button onClick={onRetry}>Try again</Button>
        </div>
      </main>
    </div>
  );
}

interface LoginScreenProps {
  api: ApiClient;
  onOidcRedirect: (url: string) => void;
  reason?: "expired" | "signed_out";
  onAuthenticated: (session: Session) => void;
}

function LoginScreen({
  api,
  onOidcRedirect,
  reason,
  onAuthenticated,
}: LoginScreenProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  const [methods, setMethods] = useState<AuthMethods>();
  const [methodsError, setMethodsError] = useState(false);
  const oidcError = new URLSearchParams(window.location.search).get(
    "oidc_error",
  );

  useEffect(() => {
    const controller = new AbortController();
    api.authMethods(controller.signal).then(
      (available) => {
        setMethods(available);
        if (
          available.oidcEnabled &&
          !available.passwordEnabled &&
          !oidcError &&
          reason !== "signed_out"
        ) {
          onOidcRedirect("/api/v1/auth/oidc/start");
        }
      },
      () => setMethodsError(true),
    );
    return () => controller.abort();
  }, [api, onOidcRedirect, oidcError, reason]);

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
          <h1 id="login-title">Sign in to Crabinet</h1>
          <p class="muted">
            Browse the folders that have been shared with you.
          </p>
          {reason === "expired" && (
            <Notice tone="warning">
              Your session expired. Sign in again to continue.
            </Notice>
          )}
          {reason === "signed_out" && (
            <Notice tone="warning">You have signed out of Crabinet.</Notice>
          )}
          {error && <Notice tone="danger">{error}</Notice>}
          {oidcError === "unrecognized" && (
            <Notice tone="danger">
              This identity is not authorized for Crabinet. Contact an
              administrator if you need access.
            </Notice>
          )}
          {oidcError === "provider_logout_unavailable" && (
            <Notice tone="warning">
              Crabinet ended this sign-in attempt, but the identity provider
              does not offer sign-out here. Sign out at the provider before
              trying another account.
            </Notice>
          )}
          {oidcError === "unrecognized" && (
            <a href="/api/v1/auth/oidc/disconnect">Disconnect</a>
          )}
          {methodsError && (
            <Notice tone="danger">
              Sign-in options could not be loaded. Refresh to try again.
            </Notice>
          )}
          {methods?.oidcEnabled &&
            (methods.passwordEnabled ||
              oidcError ||
              reason === "signed_out") && (
              <a class="google-signin" href="/api/v1/auth/oidc/start">
                <img src="/google-g.png" width="20" height="20" alt="" />
                <span>Sign in with Google</span>
              </a>
            )}
          {methods?.oidcEnabled && methods.passwordEnabled && (
            <p class="login-divider">or sign in with a password</p>
          )}
          {methods?.passwordEnabled && (
            <form class="login-form" onSubmit={submit}>
              <label for="username">Email or username</label>
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
          )}
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
  onDefaultFolderChanged: (folder: DefaultFolder | null) => void;
  onSessionRefreshed: (session: Session) => void;
}

function AuthenticatedShell({
  api,
  navigation,
  route,
  session,
  onSessionExpired,
  onSignedOut,
  onDefaultFolderChanged,
  onSessionRefreshed,
}: AuthenticatedShellProps) {
  const [signingOut, setSigningOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string>();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [savingPreferences, setSavingPreferences] = useState(false);
  const [preferencesError, setPreferencesError] = useState<string>();
  const [showHiddenFiles, setShowHiddenFiles] = useState(() =>
    readShowHiddenFiles(session.user.id),
  );
  const selectedShare = session.shares.find(
    (share) => share.id === route.shareId,
  );
  const defaultFolder = session.defaultFolder ?? null;
  const defaultShare = session.shares.find(
    (share) => share.id === defaultFolder?.shareId,
  );
  const startFolderValue = defaultFolder
    ? defaultFolder.path
      ? "/"
      : defaultFolder.shareId
    : "";

  useEffect(() => {
    const key = hiddenFilesPreferenceKey(session.user.id);
    setShowHiddenFiles(readShowHiddenFiles(session.user.id));
    const syncPreference = (event: StorageEvent) => {
      if (event.key === key || event.key === null) {
        setShowHiddenFiles(readShowHiddenFiles(session.user.id));
      }
    };
    window.addEventListener("storage", syncPreference);
    return () => window.removeEventListener("storage", syncPreference);
  }, [session.user.id]);

  const updateShowHiddenFiles = (value: boolean) => {
    setShowHiddenFiles(value);
    try {
      window.localStorage.setItem(
        hiddenFilesPreferenceKey(session.user.id),
        String(value),
      );
    } catch {
      // The display preference still works for this tab if storage is blocked.
    }
  };

  const saveDefaultFolder = async (folder: DefaultFolder | null) => {
    setSavingPreferences(true);
    setPreferencesError(undefined);
    try {
      const saved = await api.updateDefaultFolder(folder, session.csrfToken);
      onDefaultFolderChanged(saved);
    } catch (error) {
      if (isUnauthorized(error)) {
        onSessionExpired();
      } else {
        setPreferencesError("Could not save your start folder. Try again.");
      }
    } finally {
      setSavingPreferences(false);
    }
  };

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
          <Button
            variant="secondary"
            type="button"
            aria-haspopup="dialog"
            onClick={() => setSettingsOpen(true)}
          >
            <Settings2 size={17} aria-hidden="true" />
            Settings
          </Button>
          <Button variant="secondary" busy={signingOut} onClick={logout}>
            <LogOut size={17} aria-hidden="true" />
            {signingOut ? "Signing out…" : "Sign out"}
          </Button>
        </div>
      </AppHeader>
      {settingsOpen && (
        <Modal
          title="Settings"
          onClose={() => setSettingsOpen(false)}
          busy={savingPreferences}
        >
          <div class="settings-content">
            <label for="start-folder">Start folder</label>
            <select
              id="start-folder"
              value={startFolderValue}
              disabled={savingPreferences}
              onChange={(event) => {
                const shareId = event.currentTarget.value;
                if (shareId === "/") return;
                void saveDefaultFolder(shareId ? { shareId, path: "" } : null);
              }}
            >
              <option value="">First shared folder</option>
              {defaultFolder?.path && defaultShare && (
                <option value="/" disabled>
                  Current: {defaultShare.name} / {defaultFolder.path}
                </option>
              )}
              {session.shares.map((share) => (
                <option key={share.id} value={share.id}>
                  {share.name}
                </option>
              ))}
            </select>
            <p class="muted">
              This choice follows your account across devices.
            </p>
            <label class="hidden-files-toggle">
              <input
                type="checkbox"
                checked={showHiddenFiles}
                onChange={(event) =>
                  updateShowHiddenFiles(event.currentTarget.checked)
                }
              />
              Show hidden files
            </label>
            <p class="muted">Saved in this browser for your account.</p>
            {preferencesError && (
              <Notice tone="danger">{preferencesError}</Notice>
            )}
          </div>
        </Modal>
      )}
      {import.meta.env.DEV && (
        <div class="development-banner" role="status">
          Development preview · revision{" "}
          {__CRABINET_DEV_REVISION__ ?? "working tree"} · live HMR
        </div>
      )}
      {logoutError && (
        <div class="global-notice">
          <Notice tone="danger">{logoutError}</Notice>
        </div>
      )}
      <main class="browser-layout">
        {session.shares.length === 0 ? (
          <EmptyState
            title="No shared folders"
            detail="An administrator has not shared any folders with this account."
          />
        ) : selectedShare ? (
          <DirectoryBrowser
            api={api}
            csrfToken={session.csrfToken}
            navigation={navigation}
            route={route}
            share={selectedShare}
            shares={session.shares}
            userId={session.user.id}
            showHiddenFiles={showHiddenFiles}
            onSessionExpired={onSessionExpired}
            onSessionRefreshed={onSessionRefreshed}
          />
        ) : (
          <p role="status">Opening a shared folder…</p>
        )}
      </main>
      <TooltipLayer />
    </div>
  );
}

interface DirectoryBrowserProps {
  api: ApiClient;
  csrfToken: string;
  navigation: BrowserNavigation;
  route: BrowserRoute;
  share: Share;
  shares: Share[];
  userId: string;
  showHiddenFiles: boolean;
  onSessionExpired: () => void;
  onSessionRefreshed: (session: Session) => void;
}

function DirectoryBrowser({
  api,
  csrfToken,
  navigation,
  route,
  share,
  shares,
  userId,
  showHiddenFiles,
  onSessionExpired,
  onSessionRefreshed,
}: DirectoryBrowserProps) {
  const [page, setPage] = useState<DirectoryPage>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<ApiError>();
  const [refreshKey, setRefreshKey] = useState(0);
  const [operation, setOperation] = useState<EntryOperation>();
  const [uploadSelection, setUploadSelection] = useState<UploadSelection>();
  const [fileDragActive, setFileDragActive] = useState(false);
  const loadMoreController = useRef<AbortController>();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const previewTriggerRef = useRef<HTMLAnchorElement>();
  const operationLocation = useRef(`${share.id}\u0000${route.path}`);
  const focusedLocation = useRef<string>();
  const activePreview = useRef(route.previewPath);
  activePreview.current = route.previewPath;
  const writable = share.access === "read-write";
  const visibleEntries =
    page?.entries.filter(
      (entry) => showHiddenFiles || !entry.name.startsWith("."),
    ) ?? [];

  useEffect(() => {
    // A history/share change invalidates every relative operation target.
    // Unmounting an upload queue also aborts its active transports.
    const nextLocation = `${share.id}\u0000${route.path}`;
    if (operationLocation.current !== nextLocation) {
      operationLocation.current = nextLocation;
      setOperation(undefined);
      setUploadSelection(undefined);
    }
  }, [route.path, share.id]);

  useEffect(() => {
    let internalDrag = false;
    const resetFileDrag = () => {
      setFileDragActive(false);
    };
    const hasFiles = (transfer: DataTransfer | null) =>
      Array.from(transfer?.types ?? []).some(
        (type) => type === "Files" || type === "application/x-moz-file",
      ) ||
      Array.from(transfer?.items ?? []).some((item) => item.kind === "file") ||
      (transfer?.files.length ?? 0) > 0;
    const dragStart = () => {
      internalDrag = true;
      resetFileDrag();
    };
    const dragEnter = (event: DragEvent) => {
      if (internalDrag) {
        if (hasFiles(event.dataTransfer)) {
          event.preventDefault();
          event.stopPropagation();
          if (event.dataTransfer) event.dataTransfer.dropEffect = "none";
        }
        return;
      }
      if (!hasFiles(event.dataTransfer)) return;
      event.preventDefault();
      event.stopPropagation();
      if (event.dataTransfer) {
        event.dataTransfer.dropEffect = writable ? "copy" : "none";
      }
      setFileDragActive(true);
    };
    const dragOver = (event: DragEvent) => {
      if (internalDrag) {
        if (hasFiles(event.dataTransfer)) {
          event.preventDefault();
          event.stopPropagation();
          if (event.dataTransfer) event.dataTransfer.dropEffect = "none";
        }
        return;
      }
      if (!hasFiles(event.dataTransfer)) return;
      event.preventDefault();
      event.stopPropagation();
      if (event.dataTransfer) {
        event.dataTransfer.dropEffect = writable ? "copy" : "none";
      }
      setFileDragActive(true);
    };
    const dragLeave = (event: DragEvent) => {
      const leftViewport =
        event.clientX <= 0 ||
        event.clientY <= 0 ||
        event.clientX >= window.innerWidth ||
        event.clientY >= window.innerHeight;
      if (event.relatedTarget === null && leftViewport) resetFileDrag();
    };
    const drop = (event: DragEvent) => {
      if (internalDrag) {
        if (hasFiles(event.dataTransfer)) {
          event.preventDefault();
          event.stopPropagation();
        }
        internalDrag = false;
        resetFileDrag();
        return;
      }
      if (!hasFiles(event.dataTransfer)) return;
      event.preventDefault();
      event.stopPropagation();
      const files = Array.from(event.dataTransfer?.files ?? []);
      resetFileDrag();
      if (writable && files.length > 0) {
        setUploadSelection({ id: crypto.randomUUID(), files });
      }
    };

    const dragEnd = () => {
      internalDrag = false;
      resetFileDrag();
    };
    window.addEventListener("dragstart", dragStart, true);
    window.addEventListener("dragenter", dragEnter, true);
    window.addEventListener("dragover", dragOver, true);
    window.addEventListener("dragleave", dragLeave, true);
    window.addEventListener("drop", drop, true);
    window.addEventListener("dragend", dragEnd, true);
    window.addEventListener("blur", dragEnd);
    return () => {
      window.removeEventListener("dragstart", dragStart, true);
      window.removeEventListener("dragenter", dragEnter, true);
      window.removeEventListener("dragover", dragOver, true);
      window.removeEventListener("dragleave", dragLeave, true);
      window.removeEventListener("drop", drop, true);
      window.removeEventListener("dragend", dragEnd, true);
      window.removeEventListener("blur", dragEnd);
      resetFileDrag();
    };
  }, [route.path, share.id, writable]);

  useEffect(() => {
    const controller = new AbortController();
    const location = `${share.id}\u0000${route.path}`;
    const shouldFocusHeading = focusedLocation.current !== location;
    focusedLocation.current = location;
    loadMoreController.current?.abort();
    setLoading(true);
    setPage(undefined);
    setError(undefined);

    api
      .directory(
        share.id,
        route.path,
        undefined,
        controller.signal,
        showHiddenFiles,
      )
      .then(
        (result) => {
          if (controller.signal.aborted) return;
          setPage(result);
          setLoading(false);
          if (shouldFocusHeading) {
            requestAnimationFrame(() => headingRef.current?.focus());
          }
        },
        (cause: unknown) => {
          if (controller.signal.aborted) return;
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
  }, [
    api,
    onSessionExpired,
    refreshKey,
    route.path,
    share.id,
    showHiddenFiles,
  ]);

  useEffect(() => {
    if (typeof EventSource === "undefined") return;
    const events = new EventSource(directoryEventsUrl(share.id, route.path));
    let debounce: number | undefined;
    let fallback: number | undefined;
    let fallbackDelay = 5_000;
    const invalidate = () => {
      window.clearTimeout(debounce);
      debounce = window.setTimeout(
        () => setRefreshKey((value) => value + 1),
        150,
      );
    };
    const clearFallback = () => window.clearTimeout(fallback);
    const scheduleFallback = () => {
      clearFallback();
      if (document.visibilityState !== "visible") return;
      fallback = window.setTimeout(() => {
        invalidate();
        fallbackDelay = Math.min(fallbackDelay * 2, 60_000);
        scheduleFallback();
      }, fallbackDelay);
    };
    const visibilityChanged = () => {
      if (document.visibilityState === "visible" && events.readyState !== 1) {
        scheduleFallback();
      } else if (document.visibilityState !== "visible") {
        clearFallback();
      }
    };
    events.onopen = () => {
      fallbackDelay = 5_000;
      clearFallback();
    };
    events.onerror = scheduleFallback;
    events.addEventListener("invalidate", invalidate);
    events.addEventListener("resync", invalidate);
    document.addEventListener("visibilitychange", visibilityChanged);
    return () => {
      window.clearTimeout(debounce);
      clearFallback();
      document.removeEventListener("visibilitychange", visibilityChanged);
      events.close();
    };
  }, [route.path, share.id]);

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
        showHiddenFiles,
      );
      if (controller.signal.aborted) return;
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

  const openPreview = (path: string, trigger: HTMLAnchorElement) => {
    previewTriggerRef.current = trigger;
    navigation.go({ shareId: share.id, path: route.path, previewPath: path });
  };

  const closePreview = () => {
    navigation.go({ shareId: share.id, path: route.path });
    requestAnimationFrame(() => previewTriggerRef.current?.focus());
  };

  const changed = (
    completedOperation: EntryOperation,
    destinationPath?: string,
  ) => {
    setOperation(undefined);
    if (
      completedOperation.kind === "delete" &&
      activePreview.current === completedOperation.path
    ) {
      navigation.go({ shareId: share.id, path: route.path }, { replace: true });
      requestAnimationFrame(() => headingRef.current?.focus());
    } else if (
      (completedOperation.kind === "rename" ||
        completedOperation.kind === "move") &&
      destinationPath &&
      activePreview.current === completedOperation.path
    ) {
      navigation.go(
        {
          shareId: share.id,
          path: route.path,
          previewPath: destinationPath,
          ...(route.previewMode ? { previewMode: route.previewMode } : {}),
        },
        { replace: true },
      );
    }
    setRefreshKey((value) => value + 1);
  };

  const operateOnPreview = (kind: "edit" | "rename" | "move" | "delete") => {
    const previewPath = route.previewPath;
    if (!previewPath) return;
    const name = previewPath.split("/").at(-1) ?? previewPath;
    const listedEntry = page?.entries.find(
      (entry) => joinPath(route.path, entry.name) === previewPath,
    );
    setOperation({
      kind,
      entry: listedEntry ?? { name, kind: "file" },
      path: previewPath,
    });
  };

  return (
    <div
      class={`browser-workspace${route.previewPath ? " has-preview" : ""}${route.previewMode === "full" ? " preview-full" : ""}`}
    >
      <ShareTree
        api={api}
        shares={shares}
        revision={refreshKey}
        showHidden={showHiddenFiles}
        activeShareId={share.id}
        activePath={route.path}
        navigation={navigation}
        onMove={(entry, path, destinationDirectory) =>
          setOperation({ kind: "move", entry, path, destinationDirectory })
        }
        onSessionExpired={onSessionExpired}
      />
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
                  aria-current={
                    index === crumbs.length - 1 ? "page" : undefined
                  }
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
          <div class="directory-heading-actions">
            {writable && (
              <WriteToolbar
                onCreateFile={() => setOperation({ kind: "create-file" })}
                onCreateFolder={() => setOperation({ kind: "create-folder" })}
                onUpload={(files) =>
                  setUploadSelection({ id: crypto.randomUUID(), files })
                }
              />
            )}
            <CopyPathButton
              value={`${share.id}${route.path ? `/${route.path}` : ""}`}
              label={`Copy full path for ${crumbs.at(-1)?.name ?? share.name}`}
            />
          </div>
        </div>

        <div class="sr-only" role="status" aria-live="polite">
          {loading
            ? "Loading folder"
            : page
              ? `${visibleEntries.length} items loaded`
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
        ) : page && visibleEntries.length === 0 ? (
          <EmptyState
            title={
              showHiddenFiles
                ? "This folder is empty"
                : "No visible files or folders"
            }
            detail={
              showHiddenFiles
                ? "There are no files or folders here."
                : "Turn on Show hidden files in Settings to include dotfiles and dotfolders."
            }
          />
        ) : page ? (
          <>
            <EntryList
              entries={visibleEntries}
              shareId={share.id}
              path={route.path}
              navigation={navigation}
              onOpenPreview={openPreview}
              writable={writable}
              onOperation={setOperation}
            />
            {error && (
              <Notice tone="danger">
                More items could not be loaded. The folder may have changed; use
                Load more to try again.
              </Notice>
            )}
            {page.nextCursor && (
              <div class="load-more">
                <Button
                  variant="secondary"
                  busy={loadingMore}
                  onClick={loadMore}
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </Button>
              </div>
            )}
          </>
        ) : null}
      </section>
      {route.previewPath && (
        <PreviewPanel
          key={`${share.id}:${route.previewPath}`}
          api={api}
          path={route.previewPath}
          shareId={share.id}
          revision={refreshKey}
          writable={writable}
          fullScreen={route.previewMode === "full"}
          onOperation={operateOnPreview}
          onClose={closePreview}
          onToggleFullScreen={() =>
            navigation.go({
              shareId: share.id,
              path: route.path,
              previewPath: route.previewPath,
              previewMode: route.previewMode === "full" ? "side" : "full",
            })
          }
          onSessionExpired={onSessionExpired}
        />
      )}
      {operation && (
        <OperationDialog
          api={api}
          csrfToken={csrfToken}
          operation={operation}
          directory={route.path}
          shareId={share.id}
          onClose={() => setOperation(undefined)}
          onChanged={changed}
          onSessionExpired={onSessionExpired}
          onSessionRefreshed={onSessionRefreshed}
          userId={userId}
        />
      )}
      {uploadSelection && (
        <UploadQueue
          key={uploadSelection.id}
          api={api}
          csrfToken={csrfToken}
          directory={route.path}
          files={uploadSelection.files}
          shareId={share.id}
          onClose={() => setUploadSelection(undefined)}
          onChanged={() => setRefreshKey((value) => value + 1)}
          onSessionExpired={onSessionExpired}
        />
      )}
      {fileDragActive && (
        <div
          class="upload-drop-overlay"
          data-testid="upload-drop-overlay"
          role="status"
          aria-live="polite"
        >
          <div class="upload-drop-overlay-content">
            <Upload size={42} strokeWidth={1.8} aria-hidden="true" />
            {writable ? (
              <>
                <strong>Drop files to upload</strong>
                <span>
                  Upload to {share.name}
                  {route.path ? ` / ${route.path}` : ""}
                </span>
              </>
            ) : (
              <>
                <strong>Upload unavailable</strong>
                <span>{share.name} is read only</span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function EntryList({
  entries,
  shareId,
  path,
  navigation,
  onOpenPreview,
  writable,
  onOperation,
}: {
  entries: DirectoryEntry[];
  shareId: string;
  path: string;
  navigation: BrowserNavigation;
  onOpenPreview: (path: string, trigger: HTMLAnchorElement) => void;
  writable: boolean;
  onOperation: (operation: EntryOperation) => void;
}) {
  return (
    <div class="entry-list" role="list" aria-label="Folder contents">
      {entries.map((entry) => {
        const key = `${entry.kind}:${entry.name}`;
        return (
          <div
            class="entry-row"
            role="listitem"
            key={key}
            draggable={writable}
            onDragStart={(event) =>
              beginEntryDrag(event, shareId, joinPath(path, entry.name), entry)
            }
          >
            <span
              class={`entry-icon entry-icon-${entry.kind}`}
              aria-hidden="true"
            >
              <EntryIcon entry={entry} size={22} strokeWidth={1.8} />
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
                <a
                  class="entry-name"
                  href={previewRouteUrl(
                    shareId,
                    path,
                    joinPath(path, entry.name),
                  )}
                  onClick={(event) => {
                    event.preventDefault();
                    onOpenPreview(
                      joinPath(path, entry.name),
                      event.currentTarget,
                    );
                  }}
                >
                  {entry.name}
                </a>
              )}
              <span class="entry-kind">
                {entry.kind === "directory" ? "Folder" : "File"}
              </span>
            </div>
            <span class="entry-meta">{formatSize(entry.size)}</span>
            <EntryActionButtons
              entry={entry}
              path={joinPath(path, entry.name)}
              copyPath={`${shareId}/${joinPath(path, entry.name)}`}
              writable={writable}
              onOperation={onOperation}
            />
          </div>
        );
      })}
    </div>
  );
}

interface PreviewPanelProps {
  api: ApiClient;
  path: string;
  shareId: string;
  revision: number;
  writable: boolean;
  fullScreen: boolean;
  onOperation: (kind: "edit" | "rename" | "move" | "delete") => void;
  onClose: () => void;
  onToggleFullScreen: () => void;
  onSessionExpired: () => void;
}

type PreviewState =
  | { status: "loading" }
  | { status: "ready"; document: PreviewDocument }
  | { status: "error"; error: ApiError };

type PreviewMetadataState =
  | { status: "loading" }
  | { status: "ready"; metadata: EntryMetadata }
  | { status: "unavailable" };

function PreviewPanel({
  api,
  path,
  shareId,
  revision,
  writable,
  fullScreen,
  onOperation,
  onClose,
  onToggleFullScreen,
  onSessionExpired,
}: PreviewPanelProps) {
  const [state, setState] = useState<PreviewState>({ status: "loading" });
  const [metadataState, setMetadataState] = useState<PreviewMetadataState>({
    status: "loading",
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const panelRef = useRef<HTMLElement>(null);
  const filename = path.split("/").at(-1) ?? path;

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    setMetadataState({ status: "loading" });
    const load = async () => {
      try {
        const document = await api.preview(shareId, path, controller.signal);
        if (!controller.signal.aborted) setState({ status: "ready", document });
      } catch (cause) {
        if (controller.signal.aborted || isAborted(cause)) return;
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
        setState({ status: "error", error: asApiError(cause) });
      }
      if (controller.signal.aborted) return;
      try {
        const metadata = await api.metadata(shareId, path, controller.signal);
        if (!controller.signal.aborted) {
          setMetadataState({ status: "ready", metadata });
        }
      } catch (cause) {
        if (controller.signal.aborted || isAborted(cause)) return;
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
        setMetadataState({ status: "unavailable" });
      }
    };
    void load();
    return () => controller.abort();
  }, [api, onSessionExpired, path, refreshKey, revision, shareId]);

  useEffect(() => {
    const timer = window.setTimeout(() => titleRef.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [path]);

  useEffect(() => {
    if (!fullScreen) return;
    document.documentElement.classList.add("preview-fullscreen-open");
    return () =>
      document.documentElement.classList.remove("preview-fullscreen-open");
  }, [fullScreen]);

  useEffect(() => {
    if (!fullScreen) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    const focusTimer = window.setTimeout(() => titleRef.current?.focus(), 0);
    const handleModalKeys = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onToggleFullScreen();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          "button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), [href]",
        ),
      );
      if (focusable.length === 0) return;
      const first = focusable[0]!;
      const last = focusable.at(-1)!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleModalKeys);
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener("keydown", handleModalKeys);
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [fullScreen, onToggleFullScreen]);

  const metadata =
    metadataState.status === "ready" ? metadataState.metadata : undefined;
  const previewDocument = state.status === "ready" ? state.document : undefined;
  const assetRevision = `${revision}-${refreshKey}`;

  return (
    <>
      {fullScreen && (
        <div
          class="preview-modal-backdrop"
          aria-hidden="true"
          onClick={onToggleFullScreen}
        />
      )}
      <aside
        ref={panelRef}
        class={`preview-panel${fullScreen ? " is-fullscreen" : ""}`}
        aria-labelledby="preview-title"
        role={fullScreen ? "dialog" : undefined}
        aria-modal={fullScreen ? "true" : undefined}
      >
        <header class="preview-header">
          <div class="preview-heading">
            <p class="eyebrow">
              {fullScreen ? "Expanded preview" : "File preview"}
            </p>
            <h2 id="preview-title" ref={titleRef} tabIndex={-1}>
              {filename}
            </h2>
            <p class="preview-path" title={path}>
              {path}
            </p>
          </div>
          <div class="preview-window-actions">
            <TooltipButton
              className="preview-fullscreen-button tooltip-below"
              onClick={onToggleFullScreen}
              label={fullScreen ? "Restore side preview" : "Expand preview"}
            >
              {fullScreen ? (
                <Minimize2 size={18} aria-hidden="true" />
              ) : (
                <Maximize2 size={18} aria-hidden="true" />
              )}
            </TooltipButton>
            <TooltipButton
              className="tooltip-below"
              onClick={onClose}
              label={`Close preview of ${filename}`}
            >
              <X size={20} aria-hidden="true" />
            </TooltipButton>
          </div>
        </header>

        <div class="preview-actions" role="group" aria-label="File actions">
          <CopyPathButton
            value={`${shareId}/${path}`}
            label={`Copy full path for ${filename}`}
            className="icon-button"
          />
          {writable && (
            <TooltipButton
              onClick={() => onOperation("edit")}
              label={`Edit ${filename}`}
            >
              <FilePenLine size={19} aria-hidden="true" />
            </TooltipButton>
          )}
          {writable && (
            <>
              <TooltipButton
                onClick={() => onOperation("rename")}
                label={`Rename ${filename}`}
              >
                <Pencil size={19} aria-hidden="true" />
              </TooltipButton>
              <TooltipButton
                onClick={() => onOperation("move")}
                label={`Move ${filename}`}
              >
                <FolderInput size={19} aria-hidden="true" />
              </TooltipButton>
              <TooltipButton
                className="icon-button-danger"
                onClick={() => onOperation("delete")}
                label={`Delete ${filename}`}
              >
                <Trash2 size={19} aria-hidden="true" />
              </TooltipButton>
            </>
          )}
          <TooltipLink
            href={downloadUrl(shareId, path)}
            label={`Download ${filename}`}
          >
            <Download size={19} aria-hidden="true" />
          </TooltipLink>
          {state.status === "ready" &&
            state.document.kind === "html_source" && (
              <>
                <TooltipLink
                  href={renderedHtmlPreviewUrl(shareId, path)}
                  target="_blank"
                  rel="noopener noreferrer"
                  label="Open rendered HTML in new tab"
                >
                  <ExternalLink size={19} aria-hidden="true" />
                </TooltipLink>
                <TooltipLink
                  href={htmlPreviewUrl(shareId, path)}
                  target="_blank"
                  rel="noopener noreferrer"
                  label="Open HTML source in new tab"
                >
                  <Code2 size={19} aria-hidden="true" />
                </TooltipLink>
              </>
            )}
        </div>

        <dl class="preview-metadata" aria-label="File details">
          <div>
            <dt>Size</dt>
            <dd>{formatSize(metadata?.size ?? previewDocument?.size)}</dd>
          </div>
          <div>
            <dt>Type</dt>
            <dd>{previewTypeLabel(previewDocument, filename)}</dd>
          </div>
          <div>
            <dt>Last opened</dt>
            <dd>
              {metadataState.status === "loading"
                ? "Loading…"
                : formatTimestamp(metadata?.accessedAtMs)}
            </dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd>
              {metadataState.status === "loading"
                ? "Loading…"
                : formatTimestamp(metadata?.createdAtMs)}
            </dd>
          </div>
        </dl>

        <div class="preview-body">
          {state.status === "loading" ? (
            <p class="status-message" role="status" aria-live="polite">
              Loading preview…
            </p>
          ) : state.status === "error" ? (
            <PreviewErrorState
              error={state.error}
              retry={() => setRefreshKey((value) => value + 1)}
            />
          ) : (
            <PreviewContent
              document={state.document}
              htmlSourceUrl={`${htmlPreviewUrl(shareId, path)}&v=${assetRevision}`}
              htmlRenderedUrl={`${renderedHtmlPreviewUrl(shareId, path)}&v=${assetRevision}`}
              imageUrl={`${imagePreviewUrl(shareId, path)}&v=${assetRevision}`}
              filename={filename}
            />
          )}
        </div>
      </aside>
    </>
  );
}

function PreviewContent({
  document,
  htmlSourceUrl,
  htmlRenderedUrl,
  imageUrl,
  filename,
}: {
  document: PreviewDocument;
  htmlSourceUrl: string;
  htmlRenderedUrl: string;
  imageUrl: string;
  filename: string;
}) {
  if (document.kind === "html_source") {
    return (
      <HtmlPreview
        filename={filename}
        renderedUrl={htmlRenderedUrl}
        sourceUrl={htmlSourceUrl}
      />
    );
  }

  if (document.kind === "image") {
    return (
      <figure class="image-preview">
        <a
          href={imageUrl}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={`Open ${filename} in a new tab`}
          draggable={false}
        >
          <img
            src={imageUrl}
            alt={`Preview of ${filename}`}
            draggable={false}
          />
        </a>
        <figcaption>
          {document.mimeType}
          {document.width && document.height
            ? ` · ${document.width} × ${document.height}`
            : ""}
          {` · ${formatSize(document.size)}`}
        </figcaption>
      </figure>
    );
  }

  if (document.kind === "markdown_source") {
    return <MarkdownPreview document={document} />;
  }

  return <SourcePreview document={document} />;
}

function HtmlPreview({
  filename,
  renderedUrl,
  sourceUrl,
}: {
  filename: string;
  renderedUrl: string;
  sourceUrl: string;
}) {
  const [mode, setMode] = useState<"rendered" | "source">("rendered");
  const renderedTab = useRef<HTMLButtonElement>(null);
  const sourceTab = useRef<HTMLButtonElement>(null);
  const chooseMode = (next: "rendered" | "source") => {
    setMode(next);
    requestAnimationFrame(() =>
      (next === "rendered" ? renderedTab : sourceTab).current?.focus(),
    );
  };
  const handleKeys = (event: JSX.TargetedKeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowLeft" || event.key === "Home") {
      event.preventDefault();
      chooseMode("rendered");
    } else if (event.key === "ArrowRight" || event.key === "End") {
      event.preventDefault();
      chooseMode("source");
    }
  };

  return (
    <div class="html-preview">
      <p class="preview-security-note">
        Rendered HTML runs in an isolated sandbox. Scripts, forms, navigation,
        storage, popups, and network requests are disabled.
      </p>
      <div class="preview-tabs" role="tablist" aria-label="HTML view">
        <button
          ref={renderedTab}
          type="button"
          role="tab"
          aria-selected={mode === "rendered"}
          tabIndex={mode === "rendered" ? 0 : -1}
          onClick={() => chooseMode("rendered")}
          onKeyDown={handleKeys}
        >
          Rendered
        </button>
        <button
          ref={sourceTab}
          type="button"
          role="tab"
          aria-selected={mode === "source"}
          tabIndex={mode === "source" ? 0 : -1}
          onClick={() => chooseMode("source")}
          onKeyDown={handleKeys}
        >
          Source
        </button>
      </div>
      <iframe
        class="html-source-frame"
        src={mode === "rendered" ? renderedUrl : sourceUrl}
        sandbox=""
        referrerPolicy="no-referrer"
        title={`${mode === "rendered" ? "Sandboxed HTML preview" : "Inert HTML source"} for ${filename}`}
      />
    </div>
  );
}

function SourcePreview({ document }: { document: PreviewDocument }) {
  const [wrap, setWrap] = useState(true);
  return (
    <div class="source-preview">
      <div class="preview-options">
        <span class="file-type-label">
          {document.language ? `${document.language} source` : "Plain text"}
        </span>
        <Button
          variant="secondary"
          aria-pressed={wrap}
          onClick={() => setWrap((value) => !value)}
        >
          {wrap ? "Disable line wrapping" : "Enable line wrapping"}
        </Button>
      </div>
      {document.truncated && (
        <Notice tone="warning">
          This preview is truncated. Download the file to see all content.
        </Notice>
      )}
      {document.source === "" ? (
        <p class="preview-empty">This file is empty.</p>
      ) : document.kind === "code" && document.language ? (
        <HighlightedCode
          source={document.source}
          language={document.language}
          wrap={wrap}
        />
      ) : (
        <pre
          class={`source-code${wrap ? " source-code-wrap" : ""}`}
          tabIndex={0}
          aria-label="File source"
        >
          <code>{document.source}</code>
        </pre>
      )}
      <p class="preview-size">{formatSize(document.size)}</p>
    </div>
  );
}

function MarkdownPreview({ document }: { document: PreviewDocument }) {
  const [mode, setMode] = useState<"readable" | "source">("readable");
  const readableTab = useRef<HTMLButtonElement>(null);
  const sourceTab = useRef<HTMLButtonElement>(null);

  const chooseMode = (next: "readable" | "source") => {
    setMode(next);
    requestAnimationFrame(() =>
      (next === "readable" ? readableTab : sourceTab).current?.focus(),
    );
  };

  const handleKeys = (event: JSX.TargetedKeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowLeft" || event.key === "Home") {
      event.preventDefault();
      chooseMode("readable");
    } else if (event.key === "ArrowRight" || event.key === "End") {
      event.preventDefault();
      chooseMode("source");
    }
  };

  return (
    <div class="markdown-preview">
      <p class="preview-security-note">
        Raw HTML, links, images, and embeds are displayed as text and are never
        activated.
      </p>
      <div class="preview-tabs" role="tablist" aria-label="Markdown view">
        <button
          ref={readableTab}
          type="button"
          role="tab"
          id="markdown-readable-tab"
          aria-controls="markdown-readable-panel"
          aria-selected={mode === "readable"}
          tabIndex={mode === "readable" ? 0 : -1}
          onClick={() => chooseMode("readable")}
          onKeyDown={handleKeys}
        >
          Readable
        </button>
        <button
          ref={sourceTab}
          type="button"
          role="tab"
          id="markdown-source-tab"
          aria-controls="markdown-source-panel"
          aria-selected={mode === "source"}
          tabIndex={mode === "source" ? 0 : -1}
          onClick={() => chooseMode("source")}
          onKeyDown={handleKeys}
        >
          Source
        </button>
      </div>
      {mode === "readable" ? (
        <div
          id="markdown-readable-panel"
          role="tabpanel"
          aria-labelledby="markdown-readable-tab"
          tabIndex={0}
        >
          {document.source === "" ? (
            <p class="preview-empty">This file is empty.</p>
          ) : (
            <SafeMarkdown source={document.source} />
          )}
        </div>
      ) : (
        <div
          id="markdown-source-panel"
          role="tabpanel"
          aria-labelledby="markdown-source-tab"
          tabIndex={0}
        >
          <pre
            class="source-code source-code-wrap"
            aria-label="Markdown source"
          >
            <code>{document.source}</code>
          </pre>
        </div>
      )}
      {document.truncated && (
        <Notice tone="warning">
          This preview is truncated. Download the file to see all content.
        </Notice>
      )}
    </div>
  );
}

function PreviewErrorState({
  error,
  retry,
}: {
  error: ApiError;
  retry: () => void;
}) {
  const detail = previewErrorDetail(error);
  return (
    <div class="preview-error" role="alert">
      <h3>{detail.title}</h3>
      <p>{detail.message}</p>
      {detail.retry && <Button onClick={retry}>Try preview again</Button>}
    </div>
  );
}

function previewErrorDetail(error: ApiError): {
  title: string;
  message: string;
  retry: boolean;
} {
  if (error.kind === "not-found") {
    return {
      title: "Preview no longer available",
      message: "The file may have been deleted, moved, or changed.",
      retry: true,
    };
  }
  if (error.code === "preview_too_large" || error.status === 413) {
    return {
      title: "File is too large to preview",
      message: "Download the file to view it with a local application.",
      retry: false,
    };
  }
  if (error.code === "binary_file") {
    return {
      title: "Binary preview is not supported",
      message: "Download the file to open it safely.",
      retry: false,
    };
  }
  if (error.code === "invalid_utf8") {
    return {
      title: "Text encoding is not supported",
      message: "This preview supports valid UTF-8 text only.",
      retry: false,
    };
  }
  if (error.code === "unsupported_entry") {
    return {
      title: "This item cannot be previewed",
      message: "Only regular text files can be previewed.",
      retry: false,
    };
  }
  if (error.kind === "invalid-response") {
    return {
      title: "Preview response was invalid",
      message:
        "The file was not displayed because the server response was unsafe.",
      retry: true,
    };
  }
  return {
    title: "We could not load this preview",
    message: "The file may have changed. Check your connection and try again.",
    retry: true,
  };
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

function TooltipButton({
  label,
  className,
  children,
  ...props
}: Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> & {
  label: string;
  className?: string;
}) {
  return (
    <button
      {...props}
      class={`icon-button tooltip-action${className ? ` ${className}` : ""}`}
      type={props.type ?? "button"}
      aria-label={label}
      data-tooltip={label}
    >
      {children}
    </button>
  );
}

function TooltipLink({
  label,
  className,
  children,
  ...props
}: Omit<JSX.AnchorHTMLAttributes<HTMLAnchorElement>, "aria-label"> & {
  label: string;
  className?: string;
}) {
  return (
    <a
      {...props}
      class={`icon-button tooltip-action${className ? ` ${className}` : ""}`}
      aria-label={label}
      data-tooltip={label}
    >
      {children}
    </a>
  );
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

function previewTypeLabel(
  document: PreviewDocument | undefined,
  filename: string,
): string {
  if (document?.kind === "image") return document.mimeType ?? "Image";
  if (document?.kind === "markdown_source") return "Markdown";
  if (document?.kind === "html_source") return "HTML";
  if (document?.kind === "code") {
    const language = document.language;
    if (!language) return "Code";
    const displayNames: Record<string, string> = {
      css: "CSS",
      html: "HTML",
      javascript: "JavaScript",
      json: "JSON",
      jsx: "JSX",
      markdown: "Markdown",
      shellscript: "Shell",
      sql: "SQL",
      tsx: "TSX",
      typescript: "TypeScript",
      yaml: "YAML",
    };
    return `${displayNames[language] ?? capitalize(language)} code`;
  }
  if (document?.kind === "text") return "Plain text";

  const extension = filename.match(/\.([^.]+)$/)?.[1];
  return extension ? `${extension.toUpperCase()} file` : "File";
}

function capitalize(value: string): string {
  return value.length === 0 ? value : value[0]!.toUpperCase() + value.slice(1);
}

function formatTimestamp(milliseconds: number | undefined): string {
  if (milliseconds === undefined) return "Unavailable";
  const date = new Date(milliseconds);
  if (Number.isNaN(date.valueOf())) return "Unavailable";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
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

import { type JSX } from "preact";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "preact/hooks";
import {
  browserSupportsWebAuthn,
  startAuthentication,
} from "@simplewebauthn/browser";
import {
  ArrowLeft,
  ChevronDown,
  Download,
  ExternalLink,
  EyeOff,
  FilePenLine,
  FolderDown,
  FolderInput,
  FolderOpen,
  FolderTree,
  Info,
  KeyRound,
  LogOut,
  Maximize2,
  Minimize2,
  Pencil,
  Settings2,
  SunMoon,
  Trash2,
  Upload,
  X,
} from "lucide-preact";

import {
  accountChangedCode,
  ApiError,
  archiveUrl,
  createApiClient,
  withCsrfRetry,
  directoryEventsUrl,
  downloadUrl,
  htmlPreviewUrl,
  imagePreviewUrl,
  isStreamedPreviewKind,
  openUrl,
  renderedHtmlPreviewUrl,
  thumbnailStatus,
  thumbnailUrl,
  type ApiClient,
  type AuthMethods,
  type DirectoryEntry,
  type DirectoryPage,
  type DefaultFolder,
  type EntryMetadata,
  type PreviewDocument,
  type Session,
  type Share,
  type UserPreferences,
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
import { PdfFirstPage } from "./pdf-preview";
import { CopyPathButton } from "./copy-path-button";
import {
  browserNavigation,
  directoryUrl,
  parentPath,
  previewRouteUrl,
  renderedHtmlViewUrl,
  type BrowserNavigation,
  type BrowserRoute,
} from "./navigation";
import { SafeMarkdown } from "./safe-markdown";
import { TooltipLayer } from "./tooltip-layer";
import { beginEntryDrag, ShareTree } from "./tree";
import { ToastProvider, useToast } from "./toast";
import {
  bulkTrashMessage,
  isModifiedClick,
  moveEntriesToTrash,
  SelectionBar,
  useArchiveDownload,
  useEntrySelection,
  type TrashedEntry,
} from "./selection";
import { TrashView } from "./trash";
import { isWebAuthnCancellation, PasskeySettings } from "./passkey-settings";
import {
  applyThemePreference,
  readLegacyThemePreference,
  saveThemePreference,
  subscribeThemePreference,
  type ThemePreference,
} from "./theme";

const defaultApi = createApiClient();
declare const __CRABINET_DEV_REVISION__: string | null;

// Before settings followed the account, this per-browser key held the
// hidden-files choice. It is read once to carry the choice over, then removed.
function legacyHiddenFilesKey(userId: string): string {
  return `crabinet.showHiddenFiles.${userId}`;
}

function readLegacyHiddenFiles(userId: string): string | null {
  try {
    return window.localStorage.getItem(legacyHiddenFilesKey(userId));
  } catch {
    return null;
  }
}

function removeLegacyHiddenFiles(userId: string): void {
  try {
    window.localStorage.removeItem(legacyHiddenFilesKey(userId));
  } catch {
    // Nothing to clean up when storage is blocked.
  }
}

/** The saved values of the settings named in `update`. */
function pickPreferences(
  preferences: UserPreferences,
  update: Partial<UserPreferences>,
): Partial<UserPreferences> {
  const picked: Partial<UserPreferences> = {};
  if (update.showHiddenFiles !== undefined) {
    picked.showHiddenFiles = preferences.showHiddenFiles;
  }
  if (update.theme !== undefined) picked.theme = preferences.theme;
  return picked;
}

type AuthState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "guest"; reason?: "expired" | "signed_out" }
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
  const handleSessionExpired = useCallback(
    () => setAuth({ status: "guest", reason: "expired" }),
    [],
  );
  const handleSignedOut = useCallback(
    () => setAuth({ status: "guest", reason: "signed_out" }),
    [],
  );
  const handlePreferencesChanged = useCallback(
    (update: Partial<UserPreferences>) =>
      setAuth((current) =>
        current.status === "authenticated"
          ? {
              ...current,
              session: {
                ...current.session,
                preferences: { ...current.session.preferences, ...update },
              },
            }
          : current,
      ),
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
    // Trash spans every share, so it needs no share of its own.
    if (route.view === "trash") return;
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
  }, [auth, navigation, route.shareId, route.view]);

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
    <ToastProvider>
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
        onPreferencesChanged={handlePreferencesChanged}
        onSessionRefreshed={(session) =>
          setAuth((current) =>
            current.status === "authenticated" &&
            current.session.user.id === session.user.id
              ? { status: "authenticated", session }
              : current,
          )
        }
      />
    </ToastProvider>
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
  reason?: "expired" | "signed_out";
  onAuthenticated: (session: Session) => void;
}

function LoginScreen({ api, reason, onAuthenticated }: LoginScreenProps) {
  const [pending, setPending] = useState(false);
  const [passkeyPending, setPasskeyPending] = useState(false);
  const [error, setError] = useState<string>();
  const [methods, setMethods] = useState<AuthMethods>();
  const [methodsError, setMethodsError] = useState(false);
  const oidcError = new URLSearchParams(window.location.search).get(
    "oidc_error",
  );

  useEffect(() => {
    const controller = new AbortController();
    api
      .authMethods(controller.signal)
      .then(setMethods, () => setMethodsError(true));
    return () => controller.abort();
  }, [api]);

  const signInWithPasskey = async () => {
    if (passkeyPending) return;
    setPasskeyPending(true);
    setError(undefined);
    try {
      const challenge = await api.startPasskeyLogin();
      const credential = await startAuthentication({
        optionsJSON: challenge.options.publicKey,
      });
      onAuthenticated(
        await api.finishPasskeyLogin(challenge.flowId, credential),
      );
    } catch (cause) {
      if (!isAborted(cause) && !isWebAuthnCancellation(cause)) {
        setError("Passkey sign-in failed. Check your account and try again.");
      }
    } finally {
      setPasskeyPending(false);
    }
  };

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
            <a
              class="button button-secondary"
              href="/api/v1/auth/oidc/disconnect"
            >
              Disconnect
            </a>
          )}
          {methodsError && (
            <Notice tone="danger">
              Sign-in options could not be loaded. Refresh to try again.
            </Notice>
          )}
          {methods?.oidcEnabled && (
            <a class="google-signin" href="/api/v1/auth/oidc/start">
              <img src="/google-g.png" width="20" height="20" alt="" />
              <span>Sign in with Google</span>
            </a>
          )}
          {methods?.oidcEnabled && methods.passkeyEnabled && (
            <p class="login-divider">or sign in with a passkey</p>
          )}
          {methods?.passkeyEnabled && (
            <div class="login-form">
              <Button
                type="button"
                onClick={() => void signInWithPasskey()}
                busy={passkeyPending}
                disabled={!browserSupportsWebAuthn()}
              >
                {passkeyPending ? "Signing in…" : "Sign in with a passkey"}
              </Button>
              {!browserSupportsWebAuthn() && (
                <p class="muted">This browser does not support passkeys.</p>
              )}
            </div>
          )}
          {methods?.passwordEnabled && methods.passkeyEnabled && (
            <p class="login-divider">or sign in with a password</p>
          )}
          {methods?.passwordEnabled &&
            methods.oidcEnabled &&
            !methods.passkeyEnabled && (
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
  /** Merges display settings into the session without saving them. */
  onPreferencesChanged: (update: Partial<UserPreferences>) => void;
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
  onPreferencesChanged,
  onSessionRefreshed,
}: AuthenticatedShellProps) {
  const [signingOut, setSigningOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string>();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [savingPreferences, setSavingPreferences] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeysVisible, setPasskeysVisible] = useState(false);
  const showToast = useToast();
  const [preferencesError, setPreferencesError] = useState<string>();
  const { showHiddenFiles, theme: themePreference } = session.preferences;
  const legacyCheckedUser = useRef<string>();
  const carryingTheme = useRef<ThemePreference>();
  // Trash opened from a link has no share; the folder tree then starts from
  // the first one.
  const selectedShare =
    session.shares.find((share) => share.id === route.shareId) ??
    (route.view === "trash" ? session.shares[0] : undefined);
  const defaultFolder = session.defaultFolder ?? null;
  const defaultShare = session.shares.find(
    (share) => share.id === defaultFolder?.shareId,
  );
  // A saved folder whose share is no longer listed, or a nested folder, has
  // no selectable option; show it as a disabled "Current" entry instead of
  // letting the select fall back to a misleading "First shared folder".
  const showCurrentStartFolder = Boolean(
    defaultFolder && (defaultFolder.path || !defaultShare),
  );
  const startFolderValue = defaultFolder
    ? showCurrentStartFolder
      ? "/"
      : defaultFolder.shareId
    : "";

  /**
   * Applies `update` at once and saves it to the account. A failed save of a
   * Settings change is reverted and reported; a failed carry-over of an
   * earlier browser-only choice (`carryOver`) stays applied and is retried on
   * the next visit.
   */
  const savePreferences = async (
    update: Partial<UserPreferences>,
    { carryOver = false } = {},
  ): Promise<boolean> => {
    const previous = pickPreferences(session.preferences, update);
    onPreferencesChanged(update);
    if (!carryOver) setPreferencesError(undefined);
    try {
      const saved = await withCsrfRetry(
        api,
        session.csrfToken,
        session.user.id,
        onSessionRefreshed,
        (token) => api.updatePreferences(update, token),
      );
      // Only the fields sent here: another change may still be in flight.
      onPreferencesChanged(pickPreferences(saved, update));
      if (!carryOver) {
        showToast(
          update.theme !== undefined
            ? "Appearance saved."
            : update.showHiddenFiles
              ? "Hidden files are now shown."
              : "Hidden files are now hidden.",
        );
      }
      return true;
    } catch (error) {
      if (carryOver) return false;
      onPreferencesChanged(previous);
      if (isUnauthorized(error)) {
        onSessionExpired();
      } else if (
        error instanceof ApiError &&
        error.code === accountChangedCode
      ) {
        setPreferencesError(
          "A different account is now signed in. Reload the page to continue.",
        );
      } else {
        setPreferencesError(
          update.theme !== undefined
            ? "Could not save your appearance choice. Try again."
            : "Could not save your hidden files choice. Try again.",
        );
      }
      return false;
    }
  };

  useEffect(() => {
    let carryOver: Partial<UserPreferences> | undefined;
    if (legacyCheckedUser.current !== session.user.id) {
      legacyCheckedUser.current = session.user.id;
      carryOver = {};
      const legacyHidden = readLegacyHiddenFiles(session.user.id);
      if (legacyHidden === "true" && !session.preferences.showHiddenFiles) {
        carryOver.showHiddenFiles = true;
      } else if (legacyHidden !== null) {
        removeLegacyHiddenFiles(session.user.id);
      }
      const legacyTheme = readLegacyThemePreference();
      if (legacyTheme && session.preferences.theme === "system") {
        carryOver.theme = legacyTheme;
        carryingTheme.current = legacyTheme;
      }
    }
    // Until the account has an earlier browser-only theme, leave that copy
    // unmarked so a failed carry-over is retried on the next visit.
    if (carryingTheme.current === undefined) {
      saveThemePreference(themePreference);
    } else {
      applyThemePreference(themePreference);
    }
    if (carryOver && Object.keys(carryOver).length > 0) {
      const update = carryOver;
      void savePreferences(update, { carryOver: true }).then((saved) => {
        if (!saved) return;
        if (update.showHiddenFiles !== undefined) {
          removeLegacyHiddenFiles(session.user.id);
        }
        if (update.theme !== undefined && carryingTheme.current) {
          carryingTheme.current = undefined;
          saveThemePreference(update.theme);
        }
      });
    }
    // savePreferences reads the current session; rerunning on its identity
    // would repeat the carry-over check on every render.
  }, [session.user.id, themePreference]);

  // Another tab saved a new theme and updated the shared copy.
  useEffect(
    () => subscribeThemePreference((theme) => onPreferencesChanged({ theme })),
    [onPreferencesChanged],
  );

  const updateThemePreference = (value: ThemePreference) => {
    // A choice made here replaces any earlier browser-only theme.
    carryingTheme.current = undefined;
    void savePreferences({ theme: value });
  };

  const updateShowHiddenFiles = (value: boolean) => {
    void savePreferences({ showHiddenFiles: value });
  };

  const saveDefaultFolder = async (folder: DefaultFolder | null) => {
    setSavingPreferences(true);
    setPreferencesError(undefined);
    try {
      const saved = await withCsrfRetry(
        api,
        session.csrfToken,
        session.user.id,
        onSessionRefreshed,
        (token) => api.updateDefaultFolder(folder, token),
      );
      onDefaultFolderChanged(saved);
      showToast("Start folder saved.");
    } catch (error) {
      if (isUnauthorized(error)) {
        onSessionExpired();
      } else if (
        error instanceof ApiError &&
        error.code === accountChangedCode
      ) {
        setPreferencesError(
          "A different account is now signed in. Reload the page to continue.",
        );
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

  if (route.view === "rendered" && selectedShare) {
    return (
      <RenderedHtmlView
        key={`${selectedShare.id}:${route.path}`}
        api={api}
        navigation={navigation}
        shareId={selectedShare.id}
        path={route.path}
        onSessionExpired={onSessionExpired}
      />
    );
  }

  return (
    <div class="app-frame app-shell">
      {import.meta.env.DEV && (
        <div class="development-banner" role="status">
          Development preview · revision{" "}
          {__CRABINET_DEV_REVISION__ ?? "working tree"} · live HMR
        </div>
      )}
      <AppHeader>
        <div class="account-actions">
          <span class="account-name">{session.user.displayName}</span>
          {session.user.pictureUrl && (
            <img
              class="account-avatar"
              src={session.user.pictureUrl}
              alt={`Profile image for ${session.user.displayName}`}
              referrerPolicy="no-referrer"
              width="32"
              height="32"
            />
          )}
          <TooltipButton
            label="Settings"
            aria-haspopup="dialog"
            onClick={() => setSettingsOpen(true)}
          >
            <Settings2 size={19} aria-hidden="true" />
          </TooltipButton>
          <TooltipButton
            label={signingOut ? "Signing out…" : "Sign out"}
            disabled={signingOut}
            aria-busy={signingOut || undefined}
            onClick={logout}
          >
            <LogOut size={19} aria-hidden="true" />
          </TooltipButton>
        </div>
      </AppHeader>
      {settingsOpen && (
        <Modal
          title="Settings"
          onClose={() => setSettingsOpen(false)}
          busy={savingPreferences || passkeyBusy}
          className="settings-dialog"
        >
          <SettingsLayout
            sections={[
              { id: "start-folder", label: "Start folder", icon: FolderOpen },
              { id: "files", label: "Files", icon: EyeOff },
              { id: "appearance", label: "Appearance", icon: SunMoon },
              ...(passkeysVisible
                ? [{ id: "passkeys", label: "Passkeys", icon: KeyRound }]
                : []),
            ]}
          >
            {(section) => (
              <>
                {preferencesError && (
                  <Notice tone="danger">{preferencesError}</Notice>
                )}
                <div
                  class="settings-content"
                  hidden={section !== "start-folder"}
                >
                  <h3>Start folder</h3>
                  <label for="start-folder">Folder to open after sign-in</label>
                  <div class="select-field">
                    <select
                      id="start-folder"
                      value={startFolderValue}
                      disabled={savingPreferences}
                      onChange={(event) => {
                        const shareId = event.currentTarget.value;
                        if (shareId === "/") return;
                        void saveDefaultFolder(
                          shareId ? { shareId, path: "" } : null,
                        );
                      }}
                    >
                      <option value="">First shared folder</option>
                      {showCurrentStartFolder && (
                        <option value="/" disabled>
                          {defaultShare
                            ? `Current: ${defaultShare.name} / ${defaultFolder?.path}`
                            : "Current: a folder you can no longer access"}
                        </option>
                      )}
                      {session.shares.map((share) => (
                        <option key={share.id} value={share.id}>
                          {share.name}
                        </option>
                      ))}
                    </select>
                    <ChevronDown size={18} aria-hidden="true" />
                  </div>
                  <p class="muted">
                    This choice follows your account across devices.
                  </p>
                </div>
                <div class="settings-content" hidden={section !== "files"}>
                  <h3>Files</h3>
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
                  <p class="muted">
                    This setting follows your account across devices.
                  </p>
                </div>
                <div class="settings-content" hidden={section !== "appearance"}>
                  <h3>Appearance</h3>
                  <label for="theme-preference">Theme</label>
                  <div class="select-field">
                    <select
                      id="theme-preference"
                      value={themePreference}
                      onChange={(event) =>
                        updateThemePreference(
                          event.currentTarget.value as ThemePreference,
                        )
                      }
                    >
                      <option value="system">Match system</option>
                      <option value="light">Light</option>
                      <option value="dark">Dark</option>
                    </select>
                    <ChevronDown size={18} aria-hidden="true" />
                  </div>
                  <p class="muted">
                    This setting follows your account across devices.
                  </p>
                </div>
                {/* Stays mounted, so it can report whether passkeys are on. */}
                <div class="settings-content" hidden={section !== "passkeys"}>
                  <PasskeySettings
                    api={api}
                    csrfToken={session.csrfToken}
                    userId={session.user.id}
                    onSessionExpired={onSessionExpired}
                    onSessionRefreshed={onSessionRefreshed}
                    onBusyChange={setPasskeyBusy}
                    onVisibleChange={setPasskeysVisible}
                  />
                </div>
              </>
            )}
          </SettingsLayout>
        </Modal>
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
        <TooltipLayer />
      </main>
      {session.version && (
        <footer class="app-footer">Crabinet {session.version}</footer>
      )}
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
  const [previewOperationError, setPreviewOperationError] = useState<string>();
  const [deleteError, setDeleteError] = useState<string>();
  const [pendingDelete, setPendingDelete] = useState<{
    entry: DirectoryEntry;
    path: string;
  }>();
  const [deletingPath, setDeletingPath] = useState<string>();
  const showToast = useToast();
  // On narrow screens the tree lives in a drawer opened from "Folders".
  const [treeOpen, setTreeOpen] = useState(false);
  const treeToggleRef = useRef<HTMLButtonElement>(null);
  const treeDrawerRef = useRef<HTMLDivElement>(null);
  const loadMoreController = useRef<AbortController>();
  const previewOperationController = useRef<AbortController>();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const previewTriggerRef = useRef<HTMLAnchorElement>();
  const operationLocation = useRef(`${share.id}\u0000${route.path}`);
  const focusedLocation = useRef<string>();
  const shownListing = useRef<string>();
  const activePreview = useRef(route.previewPath);
  activePreview.current = route.previewPath;
  const writable = share.access === "read-write";
  const visibleEntries =
    page?.entries.filter(
      (entry) =>
        entry.name !== ".crabinet" &&
        (showHiddenFiles || !entry.name.startsWith(".")),
    ) ?? [];

  const selectionLocation = `${share.id}\u0000${route.path}\u0000${showHiddenFiles}`;
  const {
    selection,
    toggle: toggleSelected,
    toggleAll: toggleAllSelected,
    deselect,
    clear: clearSelection,
  } = useEntrySelection(
    visibleEntries.map((entry) => entry.name),
    selectionLocation,
  );
  const selectedEntries = visibleEntries.filter((entry) =>
    selection.names.has(entry.name),
  );
  const selecting = selectedEntries.length > 0;
  // The preview's opening, closing, and full-screen mode change the heading's
  // width, so they re-measure at once instead of waiting for the observer.
  const [headingRowRef, headingActionsCompact] = useCompactHeadingActions(
    `${writable}\0${share.id}\0${route.path}\0${route.previewPath ?? ""}\0${route.previewMode ?? ""}`,
  );
  const archive = useArchiveDownload(api, share.id, onSessionExpired);
  const [pendingBulkDelete, setPendingBulkDelete] =
    useState<Array<{ entry: DirectoryEntry; path: string }>>();
  const [bulkProgress, setBulkProgress] = useState<number>();

  /** Moves one entry to Trash if it is still of the listed kind. */
  const trashOne = async (entry: DirectoryEntry, path: string) => {
    const metadata = await api.metadata(share.id, path);
    if (metadata.kind !== entry.kind)
      throw new ApiError("conflict", "The item changed");
    const result = await withCsrfRetry(
      api,
      csrfToken,
      userId,
      onSessionRefreshed,
      (token) => api.deleteEntry(share.id, path, metadata.etag, token),
    );
    return result.trashId;
  };

  const deleteSelection = async (
    items: Array<{ entry: DirectoryEntry; path: string }>,
  ) => {
    if (bulkProgress !== undefined || !writable) return;
    const shareId = share.id;
    setBulkProgress(0);
    const outcome = await moveEntriesToTrash(items, trashOne, setBulkProgress);
    setBulkProgress(undefined);
    setPendingBulkDelete(undefined);
    deselect(outcome.moved.map((moved) => moved.entry.name));
    if (outcome.sessionExpired) onSessionExpired();
    if (outcome.moved.length > 0 || outcome.failed.length > 0) {
      showToast(bulkTrashMessage(outcome, items.length), {
        tone:
          outcome.failed.length === 0
            ? "success"
            : outcome.moved.length === 0
              ? "error"
              : "warning",
        ...(outcome.moved.length > 0
          ? {
              action: {
                label: "Undo",
                onClick: () => void undoBulkDelete(shareId, outcome.moved),
              },
            }
          : {}),
      });
    }
    if (outcome.moved.some((moved) => moved.path === activePreview.current)) {
      navigation.go({ shareId, path: route.path }, { replace: true });
    }
    setRefreshKey((value) => value + 1);
  };

  const undoBulkDelete = async (shareId: string, moved: TrashedEntry[]) => {
    let restored = 0;
    for (const item of moved) {
      try {
        await withCsrfRetry(
          api,
          csrfToken,
          userId,
          onSessionRefreshed,
          (token) => api.restoreTrash(shareId, item.id, undefined, token),
        );
        restored += 1;
      } catch (cause) {
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
      }
    }
    const items = (count: number) =>
      `${count} ${count === 1 ? "item" : "items"}`;
    if (restored === moved.length) showToast(`Restored ${items(restored)}.`);
    else
      showToast(
        `Restored ${restored} of ${items(moved.length)}. Open Trash to restore the rest.`,
        { tone: "warning" },
      );
    setRefreshKey((value) => value + 1);
  };

  const deleteToTrash = async (entry: DirectoryEntry, path: string) => {
    if (deletingPath || !writable) return;
    setDeletingPath(path);
    setDeleteError(undefined);
    try {
      const trashId = await trashOne(entry, path);
      setPendingDelete(undefined);
      const deleted = { shareId: share.id, id: trashId, entry, path };
      showToast(`Moved ${entry.name} to Trash.`, {
        action: { label: "Undo", onClick: () => void undoDelete(deleted) },
      });
      changed({ kind: "delete", entry, path });
    } catch (cause) {
      setPendingDelete(undefined);
      if (isUnauthorized(cause)) onSessionExpired();
      else
        setDeleteError(
          cause instanceof ApiError && cause.kind === "conflict"
            ? "This item changed. Reload the folder and try again."
            : "Could not move this item to Trash. Try again.",
        );
    } finally {
      setDeletingPath(undefined);
    }
  };

  const undoDelete = async (deleted: {
    shareId: string;
    id: string;
    entry: DirectoryEntry;
    path: string;
  }) => {
    try {
      await withCsrfRetry(api, csrfToken, userId, onSessionRefreshed, (token) =>
        api.restoreTrash(deleted.shareId, deleted.id, undefined, token),
      );
      // Undoing the restore moves it back without asking again: the
      // person already confirmed this deletion once.
      showToast(`Restored ${deleted.entry.name}.`, {
        action: {
          label: "Undo",
          onClick: () => void deleteToTrash(deleted.entry, deleted.path),
        },
      });
      setRefreshKey((value) => value + 1);
    } catch (cause) {
      if (isUnauthorized(cause)) onSessionExpired();
      else
        showToast("Could not undo. Open Trash to restore the item.", {
          tone: "error",
        });
    }
  };

  useEffect(() => {
    setTreeOpen(false);
  }, [route.path, route.previewPath, route.view, share.id]);

  useEffect(() => {
    if (!treeOpen) return;
    const drawer = treeDrawerRef.current;
    (
      drawer?.querySelector<HTMLElement>('[aria-current="page"]') ??
      drawer?.querySelector<HTMLElement>("a[href], button:not(:disabled)")
    )?.focus();
  }, [treeOpen]);

  useEffect(() => {
    // A history/share change invalidates every relative operation target.
    // Unmounting an upload queue also aborts its active transports.
    const nextLocation = `${share.id}\u0000${route.path}`;
    if (operationLocation.current !== nextLocation) {
      operationLocation.current = nextLocation;
      setOperation(undefined);
      setPendingDelete(undefined);
      setPendingBulkDelete(undefined);
      setUploadSelection(undefined);
    }
  }, [route.path, share.id]);

  useEffect(() => {
    setPreviewOperationError(undefined);
    return () => previewOperationController.current?.abort();
  }, [route.path, route.previewPath, share.id]);

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
    if (route.view === "trash") return;
    const controller = new AbortController();
    const location = `${share.id}\u0000${route.path}`;
    const shouldFocusHeading = focusedLocation.current !== location;
    focusedLocation.current = location;
    loadMoreController.current?.abort();
    // A change event reloads the listing already on screen. Keep it until the
    // new one arrives, so the rows are replaced in place instead of flashing
    // through the loading skeleton.
    const listing = `${location}\u0000${showHiddenFiles}`;
    if (shownListing.current !== listing) {
      shownListing.current = listing;
      setLoading(true);
      setPage(undefined);
    }
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
          setPage(undefined);
          const error = asApiError(cause);
          // A link may end in a file name: open its folder and preview it.
          if (error.kind === "not-found" && route.path && !route.previewPath) {
            void api.metadata(share.id, route.path, controller.signal).then(
              (entry) => {
                if (controller.signal.aborted) return;
                if (entry?.kind !== "file") {
                  setError(error);
                  setLoading(false);
                  return;
                }
                navigation.go(
                  {
                    shareId: share.id,
                    path: parentPath(route.path),
                    previewPath: route.path,
                    ...(route.previewMode === "full"
                      ? { previewMode: "full" as const }
                      : {}),
                  },
                  { replace: true },
                );
              },
              () => {
                if (controller.signal.aborted) return;
                setError(error);
                setLoading(false);
              },
            );
            return;
          }
          setError(error);
          setLoading(false);
        },
      );

    return () => {
      controller.abort();
      loadMoreController.current?.abort();
    };
  }, [
    api,
    navigation,
    onSessionExpired,
    refreshKey,
    route.path,
    route.view,
    share.id,
    showHiddenFiles,
  ]);

  useEffect(() => {
    if (route.view === "trash") return;
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
  }, [route.path, route.view, share.id]);

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
    if (completedOperation.kind === "move" && destinationPath !== undefined) {
      const folder = parentPath(destinationPath);
      showToast(
        `Moved ${completedOperation.entry.name} to ${folder ? folder.split("/").at(-1) : share.name}.`,
      );
    } else if (completedOperation.kind === "rename" && destinationPath) {
      showToast(
        `Renamed ${completedOperation.entry.name} to ${destinationPath.split("/").at(-1)}.`,
      );
    }
    if (completedOperation.kind === "create-file" && destinationPath) {
      showToast(`Created ${destinationPath.split("/").at(-1)}.`);
      navigation.go({
        shareId: share.id,
        path: route.path,
        previewPath: destinationPath,
      });
    } else if (
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
    previewOperationController.current?.abort();
    setPreviewOperationError(undefined);
    const listedEntry = page?.entries.find(
      (entry) => joinPath(route.path, entry.name) === previewPath,
    );
    if (listedEntry) {
      if (kind === "edit" && listedEntry.kind !== "file") return;
      if (kind === "delete") {
        setPendingDelete({ entry: listedEntry, path: previewPath });
        return;
      }
      setOperation({ kind, entry: listedEntry, path: previewPath });
      return;
    }
    // A deep-linked preview may name any path, including a folder. Never
    // guess its kind: the confirmation style depends on it.
    const controller = new AbortController();
    previewOperationController.current = controller;
    const location = operationLocation.current;
    api.metadata(share.id, previewPath, controller.signal).then(
      (metadata) => {
        if (
          controller.signal.aborted ||
          activePreview.current !== previewPath ||
          operationLocation.current !== location
        )
          return;
        if (kind === "edit" && metadata.kind !== "file") {
          setPreviewOperationError("Only files can be edited.");
          return;
        }
        if (kind === "delete") {
          setPendingDelete({
            entry: { name: metadata.name, kind: metadata.kind },
            path: previewPath,
          });
          return;
        }
        setOperation({
          kind,
          entry: { name: metadata.name, kind: metadata.kind },
          path: previewPath,
        });
      },
      (cause: unknown) => {
        if (controller.signal.aborted || isAborted(cause)) return;
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
        setPreviewOperationError(
          "This item could not be checked. Reload the folder and try again.",
        );
      },
    );
  };

  const chooseOperation = (operation: EntryOperation) => {
    if (operation.kind === "delete")
      setPendingDelete({ entry: operation.entry, path: operation.path });
    else setOperation(operation);
  };

  return (
    <div
      class={`browser-workspace${route.previewPath ? " has-preview" : ""}${route.previewPath && route.previewMode === "full" ? " preview-full" : ""}`}
    >
      <button
        ref={treeToggleRef}
        type="button"
        class="button button-secondary tree-drawer-toggle"
        aria-expanded={treeOpen}
        aria-controls="tree-drawer"
        onClick={() => setTreeOpen((open) => !open)}
      >
        <FolderTree size={18} aria-hidden="true" />
        Folders
      </button>
      {treeOpen && (
        <div
          class="tree-drawer-backdrop"
          aria-hidden="true"
          onClick={() => setTreeOpen(false)}
        />
      )}
      <div
        ref={treeDrawerRef}
        id="tree-drawer"
        class={`tree-drawer${treeOpen ? " is-open" : ""}`}
        onKeyDown={(event) => {
          if (event.key !== "Escape" || !treeOpen) return;
          event.stopPropagation();
          setTreeOpen(false);
          treeToggleRef.current?.focus();
        }}
      >
        <ShareTree
          api={api}
          shares={shares}
          revision={refreshKey}
          showHidden={showHiddenFiles}
          activeShareId={share.id}
          activePath={route.path}
          activeView={route.view === "trash" ? "trash" : undefined}
          navigation={navigation}
          onMove={(entry, path, destinationDirectory) =>
            setOperation({ kind: "move", entry, path, destinationDirectory })
          }
          onSessionExpired={onSessionExpired}
        />
      </div>
      {route.view === "trash" ? (
        <TrashView
          api={api}
          shares={shares}
          csrfToken={csrfToken}
          userId={userId}
          onSessionExpired={onSessionExpired}
          onSessionRefreshed={onSessionRefreshed}
          onChanged={() => setRefreshKey((value) => value + 1)}
        />
      ) : (
        <div class="directory-column">
          {pendingDelete && (
            <Modal
              title={`Move ${pendingDelete.entry.name} to Trash?`}
              busy={Boolean(deletingPath)}
              onClose={() => setPendingDelete(undefined)}
            >
              <p>
                {pendingDelete.entry.kind === "directory"
                  ? `${pendingDelete.entry.name} and everything in it will move to Trash.`
                  : `${pendingDelete.entry.name} will move to Trash.`}{" "}
                You can restore it from Trash until it expires.
              </p>
              <div class="dialog-actions">
                <button
                  type="button"
                  class="button button-secondary"
                  disabled={Boolean(deletingPath)}
                  onClick={() => setPendingDelete(undefined)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  class="button button-danger"
                  disabled={Boolean(deletingPath)}
                  onClick={() =>
                    void deleteToTrash(pendingDelete.entry, pendingDelete.path)
                  }
                >
                  {deletingPath ? "Moving…" : "Move to Trash"}
                </button>
              </div>
            </Modal>
          )}
          {pendingBulkDelete && (
            <Modal
              title={`Move ${itemCount(pendingBulkDelete.length)} to Trash?`}
              busy={bulkProgress !== undefined}
              onClose={() => setPendingBulkDelete(undefined)}
            >
              <p>
                The selected items, including everything in selected folders,
                will move to Trash. You can restore them from Trash until they
                expire.
              </p>
              <div class="dialog-actions">
                <button
                  type="button"
                  class="button button-secondary"
                  disabled={bulkProgress !== undefined}
                  onClick={() => setPendingBulkDelete(undefined)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  class="button button-danger"
                  disabled={bulkProgress !== undefined}
                  onClick={() => void deleteSelection(pendingBulkDelete)}
                >
                  {bulkProgress !== undefined
                    ? `Moving… ${bulkProgress} of ${pendingBulkDelete.length}`
                    : "Move to Trash"}
                </button>
              </div>
            </Modal>
          )}
          <section
            class="directory-panel"
            aria-labelledby="directory-title"
            onKeyDown={(event) => {
              if (
                event.key !== "Escape" ||
                event.defaultPrevented ||
                !selecting
              )
                return;
              event.preventDefault();
              clearSelection();
            }}
          >
            {deleteError && <Notice tone="danger">{deleteError}</Notice>}
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

            <div class="directory-heading" ref={headingRowRef}>
              <div>
                <h1 id="directory-title" ref={headingRef} tabIndex={-1}>
                  {crumbs.at(-1)?.name ?? share.name}
                </h1>
              </div>
              <div
                class={`directory-heading-actions${headingActionsCompact ? " is-compact" : ""}`}
              >
                {writable && (
                  <WriteToolbar
                    onCreateFile={() => setOperation({ kind: "create-file" })}
                    onCreateFolder={() =>
                      setOperation({ kind: "create-folder" })
                    }
                    onUpload={(files) =>
                      setUploadSelection({ id: crypto.randomUUID(), files })
                    }
                  />
                )}
                <ArchiveDownloadLink
                  shareId={share.id}
                  path={route.path}
                  name={crumbs.at(-1)?.name ?? share.name}
                  checking={archive.checking}
                  onDownload={() =>
                    void archive.download(
                      route.path,
                      crumbs.at(-1)?.name ?? share.name,
                    )
                  }
                />
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
                {selecting && (
                  <SelectionBar
                    count={selectedEntries.length}
                    total={visibleEntries.length}
                    writable={writable}
                    busy={archive.checking || bulkProgress !== undefined}
                    onToggleAll={toggleAllSelected}
                    onDownload={() =>
                      void archive.download(
                        selectedEntries.map((entry) =>
                          joinPath(route.path, entry.name),
                        ),
                        selectedEntries.length === 1
                          ? selectedEntries[0]!.name
                          : undefined,
                      )
                    }
                    onDelete={() =>
                      setPendingBulkDelete(
                        selectedEntries.map((entry) => ({
                          entry,
                          path: joinPath(route.path, entry.name),
                        })),
                      )
                    }
                    onClear={() => {
                      clearSelection();
                      headingRef.current?.focus();
                    }}
                  />
                )}
                <EntryList
                  entries={visibleEntries}
                  shareId={share.id}
                  path={route.path}
                  selectedPath={route.previewPath ?? undefined}
                  navigation={navigation}
                  onOpenPreview={openPreview}
                  writable={writable}
                  onOperation={chooseOperation}
                  checked={selection.names}
                  onToggleChecked={toggleSelected}
                  onDownloadArchive={(path, name) =>
                    void archive.download(path, name)
                  }
                />
                {error && (
                  <Notice tone="danger">
                    More items could not be loaded. The folder may have changed;
                    use Load more to try again.
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
        </div>
      )}
      {route.view !== "trash" && route.previewPath && (
        <PreviewPanel
          key={`${share.id}:${route.previewPath}`}
          api={api}
          path={route.previewPath}
          shareId={share.id}
          revision={refreshKey}
          writable={writable}
          fullScreen={route.previewMode === "full"}
          onOperation={operateOnPreview}
          operationError={previewOperationError}
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
      {route.view !== "trash" && operation && (
        <OperationDialog
          api={api}
          csrfToken={csrfToken}
          operation={operation}
          directory={route.path}
          shareId={share.id}
          shareName={share.name}
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
  selectedPath,
  navigation,
  onOpenPreview,
  writable,
  onOperation,
  checked,
  onToggleChecked,
  onDownloadArchive,
}: {
  entries: DirectoryEntry[];
  shareId: string;
  path: string;
  selectedPath?: string;
  navigation: BrowserNavigation;
  onOpenPreview: (path: string, trigger: HTMLAnchorElement) => void;
  writable: boolean;
  onOperation: (operation: EntryOperation) => void;
  /** Names of the entries ticked for bulk actions. */
  checked: ReadonlySet<string>;
  /** `range` extends from the last toggled row, as on Shift-click. */
  onToggleChecked: (name: string, range: boolean) => void;
  onDownloadArchive: (path: string, name: string) => void;
}) {
  return (
    <div
      class={`entry-list${checked.size > 0 ? " has-checked" : ""}`}
      role="list"
      aria-label="Folder contents"
    >
      {entries.map((entry) => {
        const key = `${entry.kind}:${entry.name}`;
        const entryPath = joinPath(path, entry.name);
        const selected = entry.kind === "file" && selectedPath === entryPath;
        const isChecked = checked.has(entry.name);
        return (
          <div
            class={`entry-row${selected ? " is-selected" : ""}${isChecked ? " is-checked" : ""}`}
            role="listitem"
            key={key}
            draggable={writable}
            onDragStart={(event) =>
              beginEntryDrag(event, shareId, entryPath, entry)
            }
          >
            {/* The icon doubles as the row's checkbox: hovering or focusing
                the row, or selecting anything, shows the checkbox in its
                place, and a tap on it toggles the row (see styles.css). */}
            <label
              class="entry-select"
              onMouseDown={(event) => {
                // Shift-click would otherwise also select the rows' text.
                if (event.shiftKey) event.preventDefault();
              }}
            >
              <span
                class={`entry-icon entry-icon-${entry.kind}`}
                aria-hidden="true"
              >
                <EntryIcon entry={entry} size={22} strokeWidth={1.8} />
              </span>
              <input
                class="selection-checkbox entry-checkbox"
                type="checkbox"
                aria-label={`Select ${entry.name}`}
                checked={isChecked}
                onClick={(event) => {
                  event.stopPropagation();
                  onToggleChecked(entry.name, event.shiftKey);
                }}
              />
            </label>
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
                  aria-current={selected ? "location" : undefined}
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
                {entry.modifiedAtMs !== undefined ? (
                  <>
                    <span class="sr-only">
                      {entry.kind === "directory" ? "Folder" : "File"},
                      modified{" "}
                    </span>
                    <time dateTime={isoTimestamp(entry.modifiedAtMs)}>
                      {formatTimestamp(entry.modifiedAtMs)}
                    </time>
                  </>
                ) : entry.kind === "directory" ? (
                  "Folder"
                ) : (
                  "File"
                )}
              </span>
            </div>
            <span class="entry-meta">
              {entry.kind === "file" ? formatSize(entry.size) : ""}
            </span>
            <EntryActionButtons
              entry={entry}
              path={entryPath}
              copyPath={`${shareId}/${entryPath}`}
              download={
                entry.kind === "directory"
                  ? {
                      href: archiveUrl(shareId, entryPath),
                      onArchive: () => onDownloadArchive(entryPath, entry.name),
                    }
                  : { href: downloadUrl(shareId, entryPath) }
              }
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
  operationError?: string;
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
  operationError,
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
  const shownPath = useRef<string>();

  useEffect(() => {
    const controller = new AbortController();
    // A change event reloads the file already on screen; keep it until the
    // new content arrives instead of flashing through the loading state.
    const shown = `${shareId}\u0000${path}`;
    if (shownPath.current !== shown) {
      shownPath.current = shown;
      setState({ status: "loading" });
      setMetadataState({ status: "loading" });
    }
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
  // The editor accepts the same UTF-8 text, within the same size limit, that
  // the preview does. Binary, oversized, and unreadable files fail to preview,
  // and images, PDFs, audio, and video preview without being text, so none of
  // them offer Edit.
  const editable =
    previewDocument !== undefined &&
    !isStreamedPreviewKind(previewDocument.kind) &&
    !previewDocument.truncated;
  // Only files the server classified as openable get the inline new-tab
  // action; everything else keeps Download alone.
  const openable = previewDocument?.openable === true;
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
            {parentPath(path) && (
              <p class="preview-path" title={path}>
                in {parentPath(path)}
              </p>
            )}
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
          {writable && editable && (
            <button
              type="button"
              class="button button-primary preview-edit-button"
              aria-label={`Edit ${filename}`}
              onClick={() => onOperation("edit")}
            >
              <FilePenLine size={18} aria-hidden="true" />
              Edit
            </button>
          )}
          <CopyPathButton
            value={`${shareId}/${path}`}
            label={`Copy full path for ${filename}`}
            className="icon-button"
          />
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
          {openable && (
            <TooltipLink
              href={openUrl(shareId, path)}
              target="_blank"
              rel="noopener noreferrer"
              label={`Open ${filename} in a new tab`}
            >
              <ExternalLink size={19} aria-hidden="true" />
            </TooltipLink>
          )}
          <TooltipLink
            href={downloadUrl(shareId, path)}
            label={`Download ${filename}`}
          >
            <Download size={19} aria-hidden="true" />
          </TooltipLink>
        </div>
        {operationError && <Notice tone="danger">{operationError}</Notice>}

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
            <dt>Modified</dt>
            <dd>
              {metadataState.status === "loading"
                ? "Loading…"
                : formatTimestamp(metadata?.modifiedAtMs)}
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
              htmlRenderedViewUrl={renderedHtmlViewUrl(shareId, path)}
              imageUrl={`${imagePreviewUrl(shareId, path)}&v=${assetRevision}`}
              thumbnailUrl={`${thumbnailUrl(shareId, path, 1600)}&v=${assetRevision}`}
              inlineUrl={`${openUrl(shareId, path)}&v=${assetRevision}`}
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
  htmlRenderedViewUrl,
  imageUrl,
  thumbnailUrl,
  inlineUrl,
  filename,
}: {
  document: PreviewDocument;
  htmlSourceUrl: string;
  htmlRenderedUrl: string;
  htmlRenderedViewUrl: string;
  imageUrl: string;
  /** The 1600-pixel server thumbnail, for images and RAW files. */
  thumbnailUrl: string;
  /** The inline route, for media elements and the PDF first-page preview. */
  inlineUrl: string;
  filename: string;
}) {
  if (document.kind === "html_source") {
    return (
      <HtmlPreview
        filename={filename}
        source={document.source}
        renderedUrl={htmlRenderedUrl}
        renderedViewUrl={htmlRenderedViewUrl}
        sourceUrl={htmlSourceUrl}
      />
    );
  }

  if (document.kind === "image" || document.kind === "raw") {
    return (
      <ImagePreview
        key={`${thumbnailUrl}\u0000${imageUrl}`}
        document={document}
        filename={filename}
        originalUrl={document.kind === "image" ? imageUrl : undefined}
        thumbnailUrl={document.thumbnailable ? thumbnailUrl : undefined}
      />
    );
  }

  if (document.kind === "pdf") {
    return <PdfFirstPage url={inlineUrl} filename={filename} />;
  }

  if (document.kind === "audio") {
    return (
      <figure class="media-preview">
        <audio
          src={inlineUrl}
          controls
          preload="metadata"
          aria-label={`Audio preview of ${filename}`}
        />
        <figcaption>{document.mimeType}</figcaption>
      </figure>
    );
  }

  if (document.kind === "video") {
    return (
      <figure class="media-preview">
        <video
          src={inlineUrl}
          controls
          preload="metadata"
          playsInline
          aria-label={`Video preview of ${filename}`}
        />
        <figcaption>{document.mimeType}</figcaption>
      </figure>
    );
  }

  if (document.kind === "markdown_source") {
    return <MarkdownPreview document={document} filename={filename} />;
  }

  return <SourcePreview document={document} />;
}

type ImagePreviewState =
  | { mode: "thumbnail"; attempt: number; checked: boolean }
  | { mode: "checking"; attempt: number; checked: boolean }
  | { mode: "original" }
  | { mode: "busy"; attempt: number }
  | { mode: "failed"; reason: "too-large" | "unsupported" | "other" };

/**
 * Shows the server thumbnail, which keeps large photos out of the browser,
 * and falls back to the original for formats the browser decodes itself. An
 * `<img>` cannot see why it failed, so a failed thumbnail is requested once
 * more to read the status: `429` offers a retry, anything else falls back to
 * the original image or, for RAW files, explains why nothing can be shown.
 */
function ImagePreview({
  document,
  filename,
  originalUrl,
  thumbnailUrl,
}: {
  document: PreviewDocument;
  filename: string;
  /** The browser-decodable original, absent for RAW files. */
  originalUrl?: string;
  thumbnailUrl?: string;
}) {
  const [state, setState] = useState<ImagePreviewState>(() =>
    thumbnailUrl
      ? { mode: "thumbnail", attempt: 0, checked: false }
      : originalUrl
        ? { mode: "original" }
        : { mode: "failed", reason: "unsupported" },
  );

  const fallBack = (reason: "too-large" | "unsupported" | "other") =>
    setState(originalUrl ? { mode: "original" } : { mode: "failed", reason });

  useEffect(() => {
    if (state.mode !== "checking" || !thumbnailUrl) return;
    const controller = new AbortController();
    const { attempt, checked } = state;
    thumbnailStatus(thumbnailUrl, controller.signal).then(
      () => {
        if (controller.signal.aborted) return;
        // The thumbnail now succeeds, for example once a busy server has
        // capacity again: load it once more, but never loop.
        if (checked) fallBack("other");
        else
          setState({ mode: "thumbnail", attempt: attempt + 1, checked: true });
      },
      (cause: unknown) => {
        if (controller.signal.aborted || isAborted(cause)) return;
        const status = cause instanceof ApiError ? cause.status : undefined;
        if (status === 429) setState({ mode: "busy", attempt });
        else if (status === 413) fallBack("too-large");
        else if (status === 415) fallBack("unsupported");
        else fallBack("other");
      },
    );
    return () => controller.abort();
    // fallBack reads only props that also key this component.
  }, [state, thumbnailUrl]);

  const isRaw = document.kind === "raw";
  const caption = isRaw
    ? "RAW image"
    : `${document.mimeType ?? "Image"}${
        document.width && document.height
          ? ` · ${document.width} × ${document.height}`
          : ""
      }`;

  if (state.mode === "busy") {
    return (
      <div class="preview-error" role="alert">
        <h3>Preview is busy</h3>
        <p>The server is making other previews right now.</p>
        <Button
          onClick={() =>
            setState({
              mode: "thumbnail",
              attempt: state.attempt + 1,
              checked: false,
            })
          }
        >
          Try preview again
        </Button>
      </div>
    );
  }

  if (state.mode === "failed") {
    const subject = isRaw ? "this RAW file" : "this image";
    const message =
      state.reason === "too-large"
        ? `The preview of ${subject} is too large to show.`
        : state.reason === "unsupported"
          ? isRaw
            ? "This RAW file has no embedded preview that Crabinet can show."
            : "This image format cannot be previewed."
          : `The preview of ${subject} could not be shown.`;
    return (
      <div class="preview-error" role="alert">
        <h3>No preview available</h3>
        <p>{message} Download the file to view it.</p>
      </div>
    );
  }

  if (state.mode === "checking") {
    return (
      <p class="status-message" role="status" aria-live="polite">
        Loading preview…
      </p>
    );
  }

  // The toolbar's Open in new tab action covers images, so the image itself
  // is not a second link.
  const source =
    state.mode === "thumbnail" && thumbnailUrl
      ? state.attempt === 0
        ? thumbnailUrl
        : `${thumbnailUrl}-${state.attempt}`
      : originalUrl;
  return (
    <figure class="image-preview">
      <img
        src={source}
        alt={`Preview of ${filename}`}
        draggable={false}
        onError={() => {
          if (state.mode === "thumbnail") {
            setState({
              mode: "checking",
              attempt: state.attempt,
              checked: state.checked,
            });
          } else {
            setState({ mode: "failed", reason: "other" });
          }
        }}
      />
      <figcaption>{caption}</figcaption>
    </figure>
  );
}

function HtmlPreview({
  filename,
  source,
  renderedUrl,
  renderedViewUrl,
  sourceUrl,
}: {
  filename: string;
  source: string;
  renderedUrl: string;
  /** Crabinet's full-window viewer, never the rendered endpoint itself. */
  renderedViewUrl: string;
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
      <div class="preview-tabs-row">
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
        {/* A top-level document can navigate itself even under a CSP
            sandbox, so rendered HTML opens in Crabinet's own viewer, inside
            the same empty-sandbox iframe. The file toolbar's Open in new tab
            action opens the inert plain-text source. */}
        <TooltipLink
          href={renderedViewUrl}
          target="_blank"
          rel="noopener noreferrer"
          label="Open rendered HTML in new tab"
        >
          <ExternalLink size={18} aria-hidden="true" />
        </TooltipLink>
        <SecurityNote>
          Rendered HTML runs in an isolated sandbox. Scripts, forms, navigation,
          storage, popups, and network requests are disabled.
        </SecurityNote>
        <CopySourceButton source={source} filename={filename} />
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

type RenderedHtmlViewState =
  | { status: "loading" }
  | { status: "ready" }
  | { status: "not-html" }
  | { status: "error"; error: ApiError };

/**
 * The new-tab view of rendered HTML: the file alone, full-window, inside the
 * same empty-sandbox iframe as its preview. Loading the rendered endpoint as
 * the tab's own document instead would let the page send the tab elsewhere
 * with a link or a meta refresh, which a CSP sandbox does not prevent.
 */
function RenderedHtmlView({
  api,
  navigation,
  shareId,
  path,
  onSessionExpired,
}: {
  api: ApiClient;
  navigation: BrowserNavigation;
  shareId: string;
  path: string;
  onSessionExpired: () => void;
}) {
  const [state, setState] = useState<RenderedHtmlViewState>({
    status: "loading",
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const filename = path.split("/").at(-1) ?? path;
  const folder = parentPath(path);

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    // Checks the file is HTML, and the session still valid, before framing
    // the rendered endpoint.
    api.preview(shareId, path, controller.signal).then(
      (document) => {
        if (controller.signal.aborted) return;
        setState(
          document.kind === "html_source"
            ? { status: "ready" }
            : { status: "not-html" },
        );
      },
      (cause: unknown) => {
        if (controller.signal.aborted || isAborted(cause)) return;
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
        setState({ status: "error", error: asApiError(cause) });
      },
    );
    return () => controller.abort();
  }, [api, onSessionExpired, path, refreshKey, shareId]);

  useEffect(() => {
    const timer = window.setTimeout(() => titleRef.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [path]);

  return (
    <div class="rendered-view">
      <header class="rendered-view-header">
        <a
          class="button button-secondary rendered-view-back"
          href={previewRouteUrl(shareId, folder, path)}
          onClick={(event) => {
            event.preventDefault();
            navigation.go({ shareId, path: folder, previewPath: path });
          }}
        >
          <ArrowLeft size={18} aria-hidden="true" />
          Back to folder
        </a>
        <div class="rendered-view-heading">
          <p class="eyebrow">Rendered HTML</p>
          <h1 ref={titleRef} tabIndex={-1}>
            {filename}
          </h1>
          {folder && (
            <p class="preview-path" title={path}>
              in {folder}
            </p>
          )}
        </div>
        <SecurityNote>
          Rendered HTML runs in an isolated sandbox. Scripts, forms, navigation,
          storage, popups, and network requests are disabled.
        </SecurityNote>
      </header>
      <main class="rendered-view-body">
        {state.status === "loading" ? (
          <p class="status-message" role="status" aria-live="polite">
            Loading preview…
          </p>
        ) : state.status === "error" ? (
          <PreviewErrorState
            error={state.error}
            retry={() => setRefreshKey((value) => value + 1)}
          />
        ) : state.status === "not-html" ? (
          <div class="preview-error" role="alert">
            <h2>This file is not HTML</h2>
            <p>Only HTML files open in this view.</p>
          </div>
        ) : (
          <iframe
            class="rendered-view-frame"
            src={renderedHtmlPreviewUrl(shareId, path)}
            sandbox=""
            referrerPolicy="no-referrer"
            title={`Sandboxed HTML preview for ${filename}`}
          />
        )}
      </main>
      <TooltipLayer />
    </div>
  );
}

function SourcePreview({ document }: { document: PreviewDocument }) {
  const [wrap, setWrap] = useState(true);
  return (
    <div class="source-preview">
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
      {document.source !== "" && (
        <label class="preview-options">
          <input
            type="checkbox"
            checked={wrap}
            onChange={(event) => setWrap(event.currentTarget.checked)}
          />
          Wrap lines
        </label>
      )}
    </div>
  );
}

function MarkdownPreview({
  document,
  filename,
}: {
  document: PreviewDocument;
  filename: string;
}) {
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
      <div class="preview-tabs-row">
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
        <SecurityNote>
          Scripts, styles, forms, images, and embeds are never loaded. Only web
          and email links open, in a new tab.
        </SecurityNote>
        <CopySourceButton source={document.source} filename={filename} />
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

/** How a preview stays inert, behind an info button instead of a banner. */
function SecurityNote({ children }: { children: string }) {
  return (
    <TooltipButton className="security-note-button" label={children}>
      <Info size={18} aria-hidden="true" />
    </TooltipButton>
  );
}

function CopySourceButton({
  source,
  filename,
}: {
  source: string;
  filename: string;
}) {
  return (
    <CopyPathButton
      value={source}
      label="Copy source"
      className="icon-button preview-tab-action"
      size={18}
      copiedMessage={`Copied the source of ${filename}.`}
      fallbackTitle="Copy source"
      fallbackLabel="Select and copy the source"
    />
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
        <FolderOpen size={28} strokeWidth={1.8} />
      </span>
      <h2>{title}</h2>
      <p>{detail}</p>
    </div>
  );
}

/**
 * Whether a heading's actions should drop their labels. The heading wraps its
 * actions under the title only as a last resort: labelled buttons beside the
 * title, then icon-only buttons beside it, then under it, labelled again if
 * they fit the full width. It is measured rather than guessed from a
 * breakpoint, so each step happens exactly when the previous one no longer
 * fits. `contentKey` re-measures when the title or buttons change without a
 * resize.
 */
function useCompactHeadingActions(contentKey: unknown) {
  const [heading, setHeading] = useState<HTMLElement | null>(null);
  const [compact, setCompact] = useState(false);

  useLayoutEffect(() => {
    if (!heading || typeof ResizeObserver === "undefined") return;
    const title = heading.firstElementChild as HTMLElement | null;
    const actions = heading.querySelector<HTMLElement>(
      ".directory-heading-actions",
    );
    if (!title || !actions) return;
    const measure = () => {
      // Measure both sizes, then restore the class before the browser
      // paints, so nothing flickers.
      const wasCompact = actions.classList.contains("is-compact");
      actions.classList.remove("is-compact");
      const full = actions.scrollWidth;
      actions.classList.add("is-compact");
      const iconsOnly = actions.scrollWidth;
      if (!wasCompact) actions.classList.remove("is-compact");

      const style = getComputedStyle(heading);
      const available =
        heading.clientWidth -
        parseFloat(style.paddingLeft) -
        parseFloat(style.paddingRight);
      const beside =
        title.getBoundingClientRect().width + parseFloat(style.columnGap);
      const fullFitsBeside = beside + full <= available;
      const iconsFitBeside = beside + iconsOnly <= available;
      setCompact(!fullFitsBeside && (iconsFitBeside || full > available));
    };
    measure();
    // The title and buttons also change size without the heading doing so,
    // for example when the web font replaces the fallback.
    const observer = new ResizeObserver(measure);
    observer.observe(heading);
    observer.observe(title);
    observer.observe(actions);
    let active = true;
    void document.fonts?.ready.then(() => {
      if (active) measure();
    });
    return () => {
      active = false;
      observer.disconnect();
    };
  }, [heading, contentKey]);

  return [setHeading, compact] as const;
}

interface SettingsSection {
  id: string;
  label: string;
  icon: typeof Info;
}

/**
 * Settings categories listed in a column of vertical tabs, beside the chosen
 * category's settings. Every panel stays mounted and only the chosen one is
 * shown, so a section can load or report its state while hidden.
 */
function SettingsLayout({
  sections,
  children,
}: {
  sections: SettingsSection[];
  children: (section: string) => preact.ComponentChildren;
}) {
  const [chosen, setChosen] = useState(sections[0]!.id);
  const tabs = useRef<Record<string, HTMLButtonElement | null>>({});
  // A section can disappear, such as Passkeys when the server turns it off.
  const active = sections.some((section) => section.id === chosen)
    ? chosen
    : sections[0]!.id;

  const choose = (id: string) => {
    setChosen(id);
    tabs.current[id]?.focus();
  };

  const handleKeys = (event: JSX.TargetedKeyboardEvent<HTMLButtonElement>) => {
    const index = sections.findIndex((section) => section.id === active);
    const next =
      event.key === "ArrowDown" || event.key === "ArrowRight"
        ? sections[(index + 1) % sections.length]
        : event.key === "ArrowUp" || event.key === "ArrowLeft"
          ? sections[(index - 1 + sections.length) % sections.length]
          : event.key === "Home"
            ? sections[0]
            : event.key === "End"
              ? sections.at(-1)
              : undefined;
    if (!next) return;
    event.preventDefault();
    choose(next.id);
  };

  return (
    <div class="settings-layout">
      <div
        class="settings-nav"
        role="tablist"
        aria-label="Settings categories"
        aria-orientation="vertical"
      >
        {sections.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            ref={(element) => {
              tabs.current[id] = element;
            }}
            type="button"
            role="tab"
            id={`settings-tab-${id}`}
            aria-controls="settings-panel"
            aria-selected={active === id}
            tabIndex={active === id ? 0 : -1}
            onClick={() => choose(id)}
            onKeyDown={handleKeys}
          >
            <Icon size={18} aria-hidden="true" />
            {label}
          </button>
        ))}
      </div>
      <div
        class="settings-panel"
        id="settings-panel"
        role="tabpanel"
        aria-labelledby={`settings-tab-${active}`}
      >
        {children(active)}
      </div>
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

/**
 * Downloads a folder as a ZIP. The server walks the whole folder before it
 * answers, so the link first asks it to start the archive (`onDownload`,
 * see `useArchiveDownload`) and shows a refusal (too large, too deep, busy)
 * here instead of navigating to it.
 */
function ArchiveDownloadLink({
  shareId,
  path,
  name,
  checking,
  onDownload,
}: {
  shareId: string;
  path: string;
  name: string;
  checking: boolean;
  onDownload: () => void;
}) {
  return (
    <TooltipLink
      href={archiveUrl(shareId, path)}
      label={`Download ${name} as ZIP`}
      aria-busy={checking || undefined}
      onClick={(event) => {
        // Modified clicks keep the browser's own link behavior.
        if (isModifiedClick(event)) return;
        event.preventDefault();
        if (!checking) onDownload();
      }}
    >
      <FolderDown size={19} aria-hidden="true" />
    </TooltipLink>
  );
}

function itemCount(count: number): string {
  return `${count} ${count === 1 ? "item" : "items"}`;
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
  if (document?.kind === "pdf") return "PDF";
  if (document?.kind === "raw") return "RAW image";
  if (document?.kind === "audio") return document.mimeType ?? "Audio";
  if (document?.kind === "video") return document.mimeType ?? "Video";
  if (document?.kind === "markdown_source") return "Markdown";
  if (document?.kind === "html_source") return "HTML";
  if (document?.kind === "code") {
    const language = document.language;
    if (!language) return "Code";
    const displayNames: Record<string, string> = {
      c: "C",
      cpp: "C++",
      css: "CSS",
      html: "HTML",
      javascript: "JavaScript",
      json: "JSON",
      jsx: "JSX",
      markdown: "Markdown",
      php: "PHP",
      shell: "Shell script",
      shellscript: "Shell script",
      sql: "SQL",
      toml: "TOML",
      tsx: "TSX",
      typescript: "TypeScript",
      xml: "XML",
      yaml: "YAML",
    };
    return displayNames[language] ?? capitalize(language);
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

/** A machine-readable date for `<time>`, or nothing when out of range. */
function isoTimestamp(milliseconds: number): string | undefined {
  const date = new Date(milliseconds);
  return Number.isNaN(date.valueOf()) ? undefined : date.toISOString();
}

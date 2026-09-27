import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  type ApiClient,
  type DirectoryPage,
  type Session,
} from "./api";
import { App } from "./app";
import type { BrowserNavigation, BrowserRoute } from "./navigation";

const session: Session = {
  user: { id: "u-1", username: "joan", displayName: "Joan" },
  shares: [
    { id: "read-only", name: "Reference", access: "read" },
    { id: "work", name: "Working files", access: "read-write" },
  ],
  csrfToken: "csrf-in-memory",
};

const emptyPage: DirectoryPage = {
  shareId: "read-only",
  path: "",
  entries: [],
};

class MemoryNavigation implements BrowserNavigation {
  private route: BrowserRoute;
  private readonly listeners = new Set<(route: BrowserRoute) => void>();
  readonly visits: Array<{ route: BrowserRoute; replace: boolean }> = [];

  constructor(route: BrowserRoute = { shareId: "read-only", path: "" }) {
    this.route = route;
  }

  current() {
    return this.route;
  }

  go(route: BrowserRoute, options?: { replace?: boolean }) {
    this.route = route;
    this.visits.push({ route, replace: options?.replace ?? false });
    this.listeners.forEach((listener) => listener(route));
  }

  subscribe(listener: (route: BrowserRoute) => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  restore(route: BrowserRoute) {
    this.route = route;
    this.listeners.forEach((listener) => listener(route));
  }
}

function dispatchDrag(
  type: "dragstart" | "dragenter" | "dragover" | "dragleave" | "drop",
  dataTransfer: { types: string[]; files: File[] },
  target: Document | Element = document,
) {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", { value: dataTransfer });
  fireEvent(target, event);
}

function fakeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    session: overrides.session ?? vi.fn(async () => session),
    authMethods:
      overrides.authMethods ??
      vi.fn(async () => ({ passwordEnabled: true, oidcEnabled: false })),
    login: overrides.login ?? vi.fn(async () => session),
    logout: overrides.logout ?? vi.fn(async () => undefined),
    passkeys: overrides.passkeys ?? vi.fn(async () => []),
    startPasskeyRegistration: overrides.startPasskeyRegistration ?? vi.fn(),
    finishPasskeyRegistration: overrides.finishPasskeyRegistration ?? vi.fn(),
    startPasskeyLogin: overrides.startPasskeyLogin ?? vi.fn(),
    finishPasskeyLogin: overrides.finishPasskeyLogin ?? vi.fn(),
    renamePasskey: overrides.renamePasskey ?? vi.fn(),
    removePasskey: overrides.removePasskey ?? vi.fn(),
    updateDefaultFolder:
      overrides.updateDefaultFolder ?? vi.fn(async (folder) => folder),
    directory: overrides.directory ?? vi.fn(async () => emptyPage),
    preview:
      overrides.preview ??
      vi.fn(async () => ({
        kind: "text" as const,
        source: "",
        size: 0,
        truncated: false,
      })),
    metadata:
      overrides.metadata ??
      vi.fn(async (shareId, path) => ({
        shareId,
        path,
        name: path.split("/").at(-1) ?? path,
        kind: "file" as const,
        size: 0,
        etag: 'W/"test"',
      })),
    text:
      overrides.text ??
      vi.fn(async (shareId, path) => ({
        shareId,
        path,
        text: "",
        size: 0,
        mimeType: "text/plain",
        etag: '"content"',
      })),
    createDirectory:
      overrides.createDirectory ??
      vi.fn(async (shareId, path) => ({
        shareId,
        path,
        outcome: "success" as const,
      })),
    createFile:
      overrides.createFile ??
      vi.fn(async (shareId, path) => ({
        shareId,
        path,
        outcome: "success" as const,
      })),
    saveText:
      overrides.saveText ??
      vi.fn(async (shareId, path) => ({
        shareId,
        path,
        outcome: "success" as const,
      })),
    moveEntry:
      overrides.moveEntry ??
      vi.fn(async (shareId, _source, destination) => ({
        shareId,
        path: destination,
        outcome: "success" as const,
      })),
    deleteEntry:
      overrides.deleteEntry ??
      vi.fn(async (shareId, path) => ({
        shareId,
        path,
        outcome: "success" as const,
      })),
    uploadFile:
      overrides.uploadFile ??
      vi.fn(async (shareId, directory, file) => ({
        shareId,
        outcomes: [
          {
            path: directory ? `${directory}/${file.name}` : file.name,
            outcome: "created" as const,
          },
        ],
      })),
  };
}

describe("authentication", () => {
  it("shows a login page in OIDC-only mode and keeps password sign-in in mixed mode", async () => {
    const sessionRequest = vi
      .fn()
      .mockRejectedValue(new ApiError("unauthorized", "anonymous"));
    const oidcOnly = fakeApi({
      session: sessionRequest,
      authMethods: vi.fn(async () => ({
        passwordEnabled: false,
        oidcEnabled: true,
      })),
    });
    const first = render(
      <App api={oidcOnly} navigation={new MemoryNavigation()} />,
    );
    expect(
      await screen.findByRole("link", { name: "Sign in with Google" }),
    ).toHaveAttribute("href", "/api/v1/auth/oidc/start");
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    first.unmount();

    const mixed = fakeApi({
      session: sessionRequest,
      authMethods: vi.fn(async () => ({
        passwordEnabled: true,
        oidcEnabled: true,
      })),
    });
    render(<App api={mixed} navigation={new MemoryNavigation()} />);
    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
    const googleLink = screen.getByRole("link", {
      name: "Sign in with Google",
    });
    expect(googleLink).toHaveAttribute("href", "/api/v1/auth/oidc/start");
    expect(googleLink.querySelector("img")).toHaveAttribute(
      "src",
      "/google-g.png",
    );
  });

  it("offers passkey sign-in alongside Google when password sign-in is disabled", async () => {
    const api = fakeApi({
      session: vi
        .fn()
        .mockRejectedValue(new ApiError("unauthorized", "anonymous")),
      authMethods: vi.fn(async () => ({
        passwordEnabled: false,
        oidcEnabled: true,
        passkeyEnabled: true,
      })),
    });
    render(<App api={api} navigation={new MemoryNavigation()} />);
    expect(
      await screen.findByRole("link", { name: "Sign in with Google" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign in with a passkey" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Use an older passkey with an account name"),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
  });

  it("keeps the unrecognized identity page visible with a Disconnect link", async () => {
    window.history.replaceState(null, "", "/?oidc_error=unrecognized");
    try {
      const api = fakeApi({
        session: vi
          .fn()
          .mockRejectedValue(new ApiError("unauthorized", "anonymous")),
        authMethods: vi.fn(async () => ({
          passwordEnabled: false,
          oidcEnabled: true,
        })),
      });
      render(<App api={api} navigation={new MemoryNavigation()} />);
      expect(
        await screen.findByText(/identity is not authorized/),
      ).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Disconnect" })).toHaveAttribute(
        "href",
        "/api/v1/auth/oidc/disconnect",
      );
    } finally {
      window.history.replaceState(null, "", "/");
    }
  });

  it("shows a loading state and then an accessible login form for an anonymous session", async () => {
    let rejectSession: ((error: ApiError) => void) | undefined;
    const api = fakeApi({
      session: vi.fn(
        () =>
          new Promise<Session>((_resolve, reject) => {
            rejectSession = reject;
          }),
      ),
    });

    render(<App api={api} navigation={new MemoryNavigation()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading your files");

    rejectSession!(new ApiError("unauthorized", "anonymous", { status: 401 }));
    expect(
      await screen.findByRole("heading", { name: "Sign in to Crabinet" }),
    ).toBeInTheDocument();
    expect(await screen.findByLabelText("Email or username")).toHaveAttribute(
      "autocomplete",
      "username",
    );
    expect(await screen.findByLabelText("Password")).toHaveAttribute(
      "autocomplete",
      "current-password",
    );
  });

  it("submits credentials without storage and keeps authentication errors generic", async () => {
    const login = vi.fn<ApiClient["login"]>().mockRejectedValue(
      new ApiError("unauthorized", "user joan does not exist", {
        status: 401,
      }),
    );
    const api = fakeApi({
      session: vi
        .fn()
        .mockRejectedValue(new ApiError("unauthorized", "anonymous")),
      login,
    });
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");

    render(<App api={api} navigation={new MemoryNavigation()} />);
    await screen.findByRole("heading", { name: "Sign in to Crabinet" });
    await screen.findByLabelText("Password");
    fireEvent.input(screen.getByLabelText("Email or username"), {
      target: { value: "joan" },
    });
    fireEvent.input(screen.getByLabelText("Password"), {
      target: { value: "correct horse" },
    });
    fireEvent.submit(
      screen.getByRole("button", { name: "Sign in" }).closest("form")!,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Sign-in failed. Check your credentials and try again.",
    );
    expect(screen.queryByText(/does not exist/i)).not.toBeInTheDocument();
    expect(login).toHaveBeenCalledWith({
      username: "joan",
      password: "correct horse",
    });
    expect(storageSpy).not.toHaveBeenCalled();
    storageSpy.mockRestore();
  });

  it("logs in, bootstraps shares, and logs out with the in-memory CSRF value", async () => {
    const logout = vi.fn<ApiClient["logout"]>().mockResolvedValue(undefined);
    const api = fakeApi({
      session: vi
        .fn()
        .mockRejectedValue(new ApiError("unauthorized", "anonymous")),
      login: vi.fn().mockResolvedValue(session),
      logout,
    });

    render(<App api={api} navigation={new MemoryNavigation()} />);
    await screen.findByRole("heading", { name: "Sign in to Crabinet" });
    await screen.findByLabelText("Password");
    fireEvent.input(screen.getByLabelText("Email or username"), {
      target: { value: "joan" },
    });
    fireEvent.input(screen.getByLabelText("Password"), {
      target: { value: "secret" },
    });
    fireEvent.submit(
      screen.getByRole("button", { name: "Sign in" }).closest("form")!,
    );

    expect(await screen.findByLabelText("Read only")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByRole("heading", { name: "Sign in to Crabinet" });
    expect(logout).toHaveBeenCalledWith("csrf-in-memory");
  });

  it("returns to login with an expiry message after an authenticated 401", async () => {
    const api = fakeApi({
      directory: vi
        .fn()
        .mockRejectedValue(
          new ApiError("unauthorized", "session expired", { status: 401 }),
        ),
    });

    render(<App api={api} navigation={new MemoryNavigation()} />);

    expect(
      await screen.findByText(
        "Your session expired. Sign in again to continue.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Sign in to Crabinet" }),
    ).toBeInTheDocument();
  });

  it("shows a recoverable connection error instead of a misleading login form", async () => {
    const sessionRequest = vi
      .fn<ApiClient["session"]>()
      .mockRejectedValueOnce(
        new ApiError("network", "internal connection detail"),
      )
      .mockResolvedValueOnce(session);

    render(
      <App
        api={fakeApi({ session: sessionRequest })}
        navigation={new MemoryNavigation()}
      />,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Crabinet is unavailable",
    );
    expect(
      screen.queryByText(/internal connection detail/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Sign in to Crabinet" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByLabelText("Read only")).toBeVisible();
  });
});

describe("directory browser", () => {
  it("opens the saved start folder only when entering through the app home", async () => {
    const account = {
      ...session,
      defaultFolder: { shareId: "work", path: "projects" },
    };
    const api = fakeApi({ session: vi.fn(async () => account) });
    const home = new MemoryNavigation({ shareId: null, path: "" });
    const first = render(<App api={api} navigation={home} />);

    await waitFor(() =>
      expect(home.visits).toEqual([
        {
          route: { shareId: "work", path: "projects" },
          replace: true,
        },
      ]),
    );
    first.unmount();

    const direct = new MemoryNavigation({ shareId: "read-only", path: "" });
    render(<App api={api} navigation={direct} />);
    await screen.findByRole("heading", { name: "Reference", level: 1 });
    expect(direct.visits).toEqual([]);
  });

  it("selects a shared-folder root as the account start folder from Settings", async () => {
    const updateDefaultFolder = vi.fn<ApiClient["updateDefaultFolder"]>(
      async (folder) => folder,
    );
    const navigation = new MemoryNavigation({
      shareId: "work",
      path: "projects",
    });
    render(
      <App api={fakeApi({ updateDefaultFolder })} navigation={navigation} />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    const dialog = screen.getByRole("dialog", { name: "Settings" });
    const select = within(dialog).getByRole("combobox", {
      name: "Start folder",
    });
    expect(select).toHaveValue("");
    expect(within(dialog).getAllByRole("option")).toHaveLength(3);
    fireEvent.change(select, { target: { value: "work" } });
    await waitFor(() =>
      expect(updateDefaultFolder).toHaveBeenCalledWith(
        { shareId: "work", path: "" },
        "csrf-in-memory",
      ),
    );
    await waitFor(() => expect(select).toHaveValue("work"));
    fireEvent.change(select, { target: { value: "" } });
    await waitFor(() =>
      expect(updateDefaultFolder).toHaveBeenCalledWith(null, "csrf-in-memory"),
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Close Settings" }),
    );
    expect(
      screen.queryByRole("dialog", { name: "Settings" }),
    ).not.toBeInTheDocument();
  });

  it("shows an existing nested start folder without offering nested choices", async () => {
    const api = fakeApi({
      session: vi.fn(async () => ({
        ...session,
        defaultFolder: { shareId: "work", path: "projects" },
      })),
    });
    render(<App api={api} navigation={new MemoryNavigation()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    const select = within(
      screen.getByRole("dialog", { name: "Settings" }),
    ).getByRole("combobox", { name: "Start folder" });
    expect(select).toHaveValue("/");
    expect(
      within(select).getByRole("option", {
        name: "Current: Working files / projects",
      }),
    ).toBeDisabled();
  });

  it("places a per-user hidden-file toggle in Settings and persists it", async () => {
    const entries = [
      { name: ".private", kind: "directory" as const },
      { name: "public", kind: "directory" as const },
      { name: ".secret.txt", kind: "file" as const },
      { name: "notes.txt", kind: "file" as const },
    ];
    const directory = vi.fn<ApiClient["directory"]>(
      async (shareId, path, _cursor, _signal, showHidden = true) => ({
        shareId,
        path,
        entries:
          path === ""
            ? entries.filter(
                (entry) => showHidden || !entry.name.startsWith("."),
              )
            : [],
      }),
    );
    const api = fakeApi({ directory });
    const navigation = new MemoryNavigation();
    const first = render(<App api={api} navigation={navigation} />);

    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    const dialog = screen.getByRole("dialog", { name: "Settings" });
    const toggle = within(dialog).getByRole("checkbox", {
      name: "Show hidden files",
    });
    expect(toggle).toBeChecked();
    expect(
      await screen.findByRole("link", { name: ".secret.txt" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Expand Reference" }));
    expect(
      await within(
        screen.getByRole("complementary", { name: "Shared folders" }),
      ).findByRole("link", { name: ".private" }),
    ).toBeVisible();

    fireEvent.click(toggle);
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: ".secret.txt" })).toBeNull(),
    );
    expect(screen.queryByRole("link", { name: ".private" })).toBeNull();
    expect(directory).toHaveBeenCalledWith(
      "read-only",
      "",
      undefined,
      expect.any(AbortSignal),
      false,
    );
    expect(window.localStorage.getItem("crabinet.showHiddenFiles.u-1")).toBe(
      "false",
    );

    first.unmount();
    render(<App api={api} navigation={new MemoryNavigation()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    expect(
      within(screen.getByRole("dialog", { name: "Settings" })).getByRole(
        "checkbox",
        { name: "Show hidden files" },
      ),
    ).not.toBeChecked();
    await screen.findByRole("link", { name: "notes.txt" });
    expect(screen.queryByRole("link", { name: ".secret.txt" })).toBeNull();
  });

  it("places create and upload actions beside Copy path outside the sidebar", async () => {
    const navigation = new MemoryNavigation({ shareId: "work", path: "" });
    render(<App api={fakeApi()} navigation={navigation} />);

    const upload = await screen.findByRole("button", {
      name: "Upload files",
    });
    const actions = upload.closest(".directory-heading-actions");
    expect(
      within(actions as HTMLElement).getByRole("button", { name: "New file" }),
    ).toBeVisible();
    expect(
      within(actions as HTMLElement).getByRole("button", {
        name: "New folder",
      }),
    ).toBeVisible();
    expect(
      within(actions as HTMLElement).getByRole("button", {
        name: "Copy full path for Working files",
      }),
    ).toBeVisible();
    for (const label of ["New file", "New folder", "Upload files"]) {
      const button = within(actions as HTMLElement).getByRole("button", {
        name: label,
      });
      expect(button).toHaveTextContent("");
      expect(button).toHaveAttribute("data-tooltip", label);
    }
    const sidebar = screen.getByRole("complementary", {
      name: "Shared folders",
    });
    expect(
      within(sidebar).queryByRole("button", { name: "New file" }),
    ).toBeNull();
    expect(
      within(sidebar).queryByRole("button", { name: "New folder" }),
    ).toBeNull();
    expect(document.querySelector(".directory-toolbar")).toBeNull();
    expect(
      screen.queryByRole("checkbox", { name: "Show hidden files" }),
    ).toBeNull();
    for (const label of ["Settings", "Sign out"]) {
      const button = screen.getByRole("button", { name: label });
      expect(button.querySelector("svg")).not.toBeNull();
      expect(button).toHaveTextContent("");
      expect(button).toHaveAttribute("data-tooltip", label);
    }
    expect(document.querySelector(".app-frame")?.firstElementChild).toHaveClass(
      "development-banner",
    );
  });

  it("shows the profile picture supplied by the session", async () => {
    const withPicture: Session = {
      ...session,
      user: {
        ...session.user,
        pictureUrl: "https://lh3.googleusercontent.com/a/test-avatar",
      },
    };
    const first = render(
      <App
        api={fakeApi({ session: vi.fn(async () => withPicture) })}
        navigation={new MemoryNavigation()}
      />,
    );
    const picture = await screen.findByRole("img", {
      name: "Profile image for Joan",
    });
    expect(picture).toHaveAttribute("src", withPicture.user.pictureUrl);
    expect(picture).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(picture.previousElementSibling).toHaveClass("account-name");

    first.unmount();
    render(<App api={fakeApi()} navigation={new MemoryNavigation()} />);
    await screen.findByRole("button", { name: "Settings" });
    expect(screen.queryByRole("img", { name: /Profile image/ })).toBeNull();
  });

  it("opens sidebar folders and explains when there are no subfolders", async () => {
    const directory = vi.fn<ApiClient["directory"]>(async (shareId, path) => ({
      shareId,
      path,
      entries:
        path === ""
          ? [
              { name: "Photos", kind: "directory" },
              { name: ".cache", kind: "directory" },
            ]
          : [{ name: "portrait.jpg", kind: "file" }],
    }));
    const navigation = new MemoryNavigation();
    render(<App api={fakeApi({ directory })} navigation={navigation} />);

    const sidebar = within(
      await screen.findByRole("complementary", { name: "Shared folders" }),
    );
    fireEvent.click(sidebar.getByRole("link", { name: "Reference" }));
    const photos = await sidebar.findByRole("link", { name: "Photos" });
    const icon = photos.querySelector("svg");
    expect(icon).not.toBeNull();
    fireEvent.click(icon!);

    const hiddenFolder = sidebar.getByRole("link", { name: ".cache" });
    expect(hiddenFolder.querySelector(".lucide-folder-dot")).not.toBeNull();

    expect(navigation.visits.at(-1)?.route).toEqual({
      shareId: "read-only",
      path: "Photos",
    });
    expect(photos).toHaveAttribute("aria-current", "page");
    expect(await sidebar.findByText("No subfolders")).toBeVisible();
    expect(directory).toHaveBeenCalledWith(
      "read-only",
      "Photos",
      undefined,
      expect.any(AbortSignal),
      true,
    );
  });

  it("uses labelled landmarks and keyboard-native controls", async () => {
    render(<App api={fakeApi()} navigation={new MemoryNavigation()} />);

    await screen.findByRole("heading", { name: "This folder is empty" });
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Breadcrumb" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("complementary", { name: "Shared folders" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Shared folder")).not.toBeInTheDocument();
    for (const button of screen.getAllByRole("button")) {
      expect(button).toHaveAccessibleName();
    }
    expect(
      document.querySelector('[tabindex]:not([tabindex="-1"])'),
    ).toBeNull();
  });

  it("shows effective grants and renders Unicode and markup-like names only as text", async () => {
    const directory = vi.fn<ApiClient["directory"]>().mockResolvedValue({
      shareId: "read-only",
      path: "",
      entries: [
        { name: "Grüße 東京 🚀", kind: "directory" },
        { name: "<img src=x onerror=alert(1)>.txt", kind: "file", size: 2048 },
      ],
    });
    const navigation = new MemoryNavigation();

    render(<App api={fakeApi({ directory })} navigation={navigation} />);

    expect(
      await screen.findByRole("link", { name: "Grüße 東京 🚀" }),
    ).toBeVisible();
    expect(screen.getByText("<img src=x onerror=alert(1)>.txt")).toBeVisible();
    expect(document.querySelector("main img")).toBeNull();
    expect(screen.getByLabelText("Read only")).toHaveTextContent("R");
    expect(screen.getByLabelText("Read and write")).toHaveTextContent("RW");

    fireEvent.click(screen.getByRole("link", { name: "Grüße 東京 🚀" }));
    expect(navigation.visits.at(-1)?.route).toEqual({
      shareId: "read-only",
      path: "Grüße 東京 🚀",
    });

    fireEvent.click(
      within(
        screen.getByRole("complementary", { name: "Shared folders" }),
      ).getByRole("link", { name: "Working files" }),
    );
    expect(navigation.visits.at(-1)?.route).toEqual({
      shareId: "work",
      path: "",
    });
  });

  it("preserves deterministic page order and de-duplicates entries across cursors", async () => {
    const directory = vi
      .fn<ApiClient["directory"]>()
      .mockResolvedValueOnce({
        shareId: "read-only",
        path: "",
        entries: [
          { name: "alpha", kind: "directory" },
          { name: "beta.txt", kind: "file" },
        ],
        nextCursor: "page-2",
      })
      .mockResolvedValueOnce({
        shareId: "read-only",
        path: "",
        entries: [
          { name: "beta.txt", kind: "file" },
          { name: "gamma.txt", kind: "file" },
        ],
      });

    render(
      <App api={fakeApi({ directory })} navigation={new MemoryNavigation()} />,
    );
    await screen.findByText("alpha");
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("gamma.txt");

    const rows = within(
      screen.getByRole("list", { name: "Folder contents" }),
    ).getAllByRole("listitem");
    expect(
      rows.map((row) => row.querySelector(".entry-name")?.textContent),
    ).toEqual(["alpha", "beta.txt", "gamma.txt"]);
    expect(directory).toHaveBeenLastCalledWith(
      "read-only",
      "",
      "page-2",
      expect.any(AbortSignal),
      true,
    );
  });

  it("supports direct navigation, breadcrumbs, and restored history", async () => {
    const navigation = new MemoryNavigation({
      shareId: "work",
      path: "projects/Crabinet",
    });
    const directory = vi.fn<ApiClient["directory"]>(async (shareId, path) => ({
      shareId,
      path,
      entries:
        path === "projects" ? [{ name: "restored.txt", kind: "file" }] : [],
    }));

    render(<App api={fakeApi({ directory })} navigation={navigation} />);
    expect(
      await screen.findByRole("heading", { name: "Crabinet" }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(directory).toHaveBeenCalledWith(
        "work",
        "projects/Crabinet",
        undefined,
        expect.any(AbortSignal),
        true,
      ),
    );

    fireEvent.click(screen.getByRole("link", { name: "projects" }));
    expect(await screen.findByText("restored.txt")).toBeVisible();
    expect(navigation.visits.at(-1)?.route.path).toBe("projects");

    navigation.restore({ shareId: "work", path: "projects/Crabinet" });
    await waitFor(() =>
      expect(directory).toHaveBeenLastCalledWith(
        "work",
        "projects/Crabinet",
        undefined,
        expect.any(AbortSignal),
        true,
      ),
    );
  });

  it("shows empty shares and empty directories without inventing write controls", async () => {
    const noShares: Session = { ...session, shares: [] };
    const { unmount } = render(
      <App
        api={fakeApi({ session: vi.fn().mockResolvedValue(noShares) })}
        navigation={new MemoryNavigation()}
      />,
    );
    expect(
      await screen.findByRole("heading", { name: "No shared folders" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /upload|create/i }),
    ).not.toBeInTheDocument();

    unmount();
    render(<App api={fakeApi()} navigation={new MemoryNavigation()} />);
    expect(
      await screen.findByRole("heading", { name: "This folder is empty" }),
    ).toBeVisible();
  });

  it("blocks native file drops without attempting an upload in a read-only share", async () => {
    const uploadFile = vi.fn<ApiClient["uploadFile"]>();
    render(
      <App api={fakeApi({ uploadFile })} navigation={new MemoryNavigation()} />,
    );
    await screen.findByRole("heading", { name: "This folder is empty" });
    const files = [new File(["blocked"], "blocked.txt")];

    dispatchDrag("dragenter", { types: ["Files"], files });
    expect(await screen.findByTestId("upload-drop-overlay")).toHaveTextContent(
      "Upload unavailable",
    );
    expect(screen.getByTestId("upload-drop-overlay")).toHaveTextContent(
      "Reference is read only",
    );
    dispatchDrag("drop", { types: ["Files"], files });

    expect(screen.queryByTestId("upload-drop-overlay")).not.toBeInTheDocument();
    expect(uploadFile).not.toHaveBeenCalled();
  });

  it("recovers from a directory that disappeared while browsing", async () => {
    const navigation = new MemoryNavigation({
      shareId: "read-only",
      path: "old/nested",
    });
    const directory = vi.fn<ApiClient["directory"]>(async (_shareId, path) => {
      if (path === "old/nested") {
        throw new ApiError("not-found", "gone", { status: 404 });
      }
      return { shareId: "read-only", path, entries: [] };
    });

    render(<App api={fakeApi({ directory })} navigation={navigation} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This folder is no longer available",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Go to parent folder" }),
    );
    expect(navigation.visits.at(-1)?.route.path).toBe("old");
    expect(
      await screen.findByRole("heading", { name: "This folder is empty" }),
    ).toBeVisible();
  });

  it("shows a recoverable generic error and retries the current folder", async () => {
    const directory = vi
      .fn<ApiClient["directory"]>()
      .mockRejectedValueOnce(new ApiError("network", "internal host leaked"))
      .mockResolvedValueOnce(emptyPage);

    render(
      <App api={fakeApi({ directory })} navigation={new MemoryNavigation()} />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "We could not load this folder",
    );
    expect(screen.queryByText(/internal host/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(
      await screen.findByRole("heading", { name: "This folder is empty" }),
    ).toBeVisible();
    expect(directory).toHaveBeenCalledTimes(2);
  });
});

describe("writable file operations", () => {
  const writablePage: DirectoryPage = {
    shareId: "work",
    path: "projects",
    entries: [
      { name: "notes.txt", kind: "file", size: 3 },
      { name: "empty", kind: "directory" },
    ],
  };

  const writableNavigation = () =>
    new MemoryNavigation({ shareId: "work", path: "projects" });

  it("creates files and folders with validation and the in-memory CSRF token", async () => {
    const createFile = vi.fn<ApiClient["createFile"]>(
      async (shareId, path) => ({
        shareId,
        path,
        outcome: "success",
      }),
    );
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async () => writablePage),
          createFile,
        })}
        navigation={writableNavigation()}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "New file" }));
    const name = screen.getByLabelText("File name");
    fireEvent.input(name, { target: { value: "../escape" } });
    fireEvent.submit(name.closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "one valid name",
    );

    fireEvent.input(name, { target: { value: "todo.md" } });
    fireEvent.submit(name.closest("form")!);
    await waitFor(() =>
      expect(createFile).toHaveBeenCalledWith(
        "work",
        "projects/todo.md",
        "csrf-in-memory",
        expect.any(AbortSignal),
      ),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renames only after fetching a fresh validator", async () => {
    const navigation = writableNavigation();
    navigation.restore({
      shareId: "work",
      path: "projects",
      previewPath: "projects/notes.txt",
    });
    const metadata = vi.fn<ApiClient["metadata"]>(async (shareId, path) => ({
      shareId,
      path,
      name: path.split("/").at(-1)!,
      kind: "file",
      size: 3,
      etag: 'W/"fresh"',
    }));
    const moveEntry = vi.fn<ApiClient["moveEntry"]>(
      async (shareId, _source, destination) => ({
        shareId,
        path: destination,
        outcome: "success",
      }),
    );
    const api = fakeApi({
      directory: vi.fn(async () => writablePage),
      preview: vi.fn(async (_shareId, path) => ({
        kind: path.endsWith(".md")
          ? ("markdown_source" as const)
          : ("text" as const),
        source: "# Notes",
        language: path.endsWith(".md") ? "markdown" : undefined,
        size: 7,
        truncated: false,
      })),
      metadata,
      moveEntry,
    });
    render(<App api={api} navigation={navigation} />);

    expect(
      await screen.findByRole("heading", { name: "notes.txt" }),
    ).toBeVisible();

    const preview = screen.getByRole("complementary", { name: "notes.txt" });
    fireEvent.click(
      within(preview).getByRole("button", { name: "Rename notes.txt" }),
    );
    fireEvent.input(await screen.findByLabelText("New name"), {
      target: { value: "renamed.md" },
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Confirm" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() =>
      expect(moveEntry).toHaveBeenCalledWith(
        "work",
        "projects/notes.txt",
        "projects/renamed.md",
        'W/"fresh"',
        "csrf-in-memory",
        expect.any(AbortSignal),
      ),
    );
    await waitFor(() =>
      expect(navigation.visits.at(-1)).toEqual({
        route: {
          shareId: "work",
          path: "projects",
          previewPath: "projects/renamed.md",
        },
        replace: true,
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "renamed.md" }),
    ).toBeVisible();
    expect(await screen.findByRole("tab", { name: "Readable" })).toBeVisible();
  });

  it("moves through the touch-friendly folder picker", async () => {
    const navigation = writableNavigation();
    navigation.restore({
      shareId: "work",
      path: "projects",
      previewPath: "projects/notes.txt",
    });
    const moveEntry = vi.fn<ApiClient["moveEntry"]>(
      async (shareId, _source, destination) => ({
        shareId,
        path: destination,
        outcome: "success",
      }),
    );
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async (shareId, path) => ({
            shareId,
            path,
            entries: path === "projects" ? writablePage.entries : [],
          })),
          moveEntry,
        })}
        navigation={navigation}
      />,
    );

    const preview = await screen.findByRole("complementary", {
      name: "notes.txt",
    });
    fireEvent.click(
      within(preview).getByRole("button", { name: "Move notes.txt" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Move notes.txt",
    });
    fireEvent.click(
      await within(dialog).findByRole("button", { name: "Shared folder" }),
    );
    await waitFor(() =>
      expect(
        within(dialog).getByRole("button", { name: "Move here" }),
      ).toBeEnabled(),
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Move here" }));
    await waitFor(() =>
      expect(moveEntry).toHaveBeenCalledWith(
        "work",
        "projects/notes.txt",
        "notes.txt",
        'W/"test"',
        "csrf-in-memory",
        expect.any(AbortSignal),
      ),
    );
    await waitFor(() =>
      expect(navigation.visits.at(-1)).toEqual({
        route: {
          shareId: "work",
          path: "projects",
          previewPath: "notes.txt",
        },
        replace: true,
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "notes.txt" }),
    ).toBeVisible();
  });

  it("requires an exact destructive confirmation and reports non-empty folders honestly", async () => {
    const deleteEntry = vi
      .fn<ApiClient["deleteEntry"]>()
      .mockRejectedValue(
        new ApiError("conflict", "not empty", { status: 409 }),
      );
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async () => writablePage),
          metadata: vi.fn(async (shareId, path) => ({
            shareId,
            path,
            name: "empty",
            kind: "directory" as const,
            etag: 'W/"directory"',
          })),
          deleteEntry,
        })}
        navigation={writableNavigation()}
      />,
    );

    const actions = await screen.findByLabelText("Actions for empty");
    fireEvent.click(
      within(actions).getByRole("button", { name: "Delete empty" }),
    );
    const confirmation = screen.getByLabelText("Type empty to confirm");
    fireEvent.input(confirmation, { target: { value: "wrong" } });
    fireEvent.submit(confirmation.closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("exactly");
    expect(deleteEntry).not.toHaveBeenCalled();

    fireEvent.input(confirmation, { target: { value: "empty" } });
    fireEvent.submit(confirmation.closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "item changed or the destination already exists",
    );
    expect(
      screen.getByText(/non-empty folders are never deleted/i),
    ).toBeInTheDocument();
  });

  it("uses a checkbox for files and closes only the deleted file's active preview", async () => {
    const navigation = writableNavigation();
    navigation.restore({
      shareId: "work",
      path: "projects",
      previewPath: "projects/notes.txt",
    });
    const deleteEntry = vi.fn<ApiClient["deleteEntry"]>(
      async (shareId, path) => ({ shareId, path, outcome: "success" }),
    );
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async () => writablePage),
          deleteEntry,
        })}
        navigation={navigation}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "notes.txt" }),
    ).toBeVisible();
    const preview = screen.getByRole("complementary", { name: "notes.txt" });
    fireEvent.click(
      within(preview).getByRole("button", { name: "Delete notes.txt" }),
    );

    const dialog = await screen.findByRole("dialog", {
      name: "Delete file notes.txt",
    });
    expect(
      within(dialog).queryByLabelText(/Type notes\.txt to confirm/),
    ).not.toBeInTheDocument();
    const confirmation = within(dialog).getByRole("checkbox", {
      name: "I understand that notes.txt will be permanently deleted",
    });
    const deleteButton = within(dialog).getByRole("button", {
      name: "Delete",
      exact: true,
    });
    expect(deleteButton).toBeDisabled();
    fireEvent.click(confirmation);
    await waitFor(() => expect(deleteButton).toBeEnabled());
    fireEvent.click(deleteButton);

    await waitFor(() => expect(deleteEntry).toHaveBeenCalledOnce());
    expect(
      screen.queryByRole("heading", { name: "notes.txt" }),
    ).not.toBeInTheDocument();
    expect(navigation.visits.at(-1)).toEqual({
      route: { shareId: "work", path: "projects" },
      replace: true,
    });
  });

  it("keeps another active preview open when a different file is deleted", async () => {
    const navigation = writableNavigation();
    navigation.restore({
      shareId: "work",
      path: "projects",
      previewPath: "projects/other.txt",
    });
    render(
      <App
        api={fakeApi({ directory: vi.fn(async () => writablePage) })}
        navigation={navigation}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "other.txt" }),
    ).toBeVisible();
    fireEvent.click(
      within(await screen.findByLabelText("Actions for notes.txt")).getByRole(
        "button",
        { name: "Delete notes.txt" },
      ),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Delete file notes.txt",
    });
    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "I understand that notes.txt will be permanently deleted",
      }),
    );
    await waitFor(() =>
      expect(
        within(dialog).getByRole("button", { name: "Delete", exact: true }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Delete", exact: true }),
    );

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "other.txt" })).toBeVisible(),
    );
    expect(navigation.visits).toEqual([]);
  });

  it("keeps edits explicit and refuses to hide a concurrent-write conflict", async () => {
    const saveText = vi
      .fn<ApiClient["saveText"]>()
      .mockRejectedValue(new ApiError("conflict", "stale", { status: 409 }));
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async () => writablePage),
          text: vi.fn(async (shareId, path) => ({
            shareId,
            path,
            text: "old",
            size: 3,
            mimeType: "text/plain",
            etag: '"content"',
          })),
          saveText,
        })}
        navigation={writableNavigation()}
      />,
    );

    const rowActions = await screen.findByLabelText("Actions for notes.txt");
    expect(
      within(rowActions).queryByRole("button", { name: "Edit notes.txt" }),
    ).not.toBeInTheDocument();
    const copyPath = within(rowActions).getByRole("button", {
      name: "Copy full path for notes.txt",
    });
    expect(copyPath).toHaveAttribute(
      "data-tooltip",
      "Copy full path for notes.txt",
    );
    expect(
      within(await screen.findByLabelText("Actions for empty")).getByRole(
        "button",
        { name: "Copy full path for empty" },
      ),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("link", { name: "notes.txt" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit notes.txt" }),
    );
    const editor = await screen.findByLabelText("UTF-8 text content");
    fireEvent.input(editor, { target: { value: "new" } });
    expect(screen.getByText("Unsaved changes")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "changed after you opened it",
    );
    expect(editor).toBeEnabled();
    expect(editor).toHaveValue("new");
    expect(saveText).toHaveBeenCalledWith(
      "work",
      "projects/notes.txt",
      "new",
      'W/"test"',
      "csrf-in-memory",
      expect.any(AbortSignal),
    );
  });

  it("keeps a denied save draft and retries with a refreshed session", async () => {
    const refreshedSession = { ...session, csrfToken: "refreshed-csrf" };
    const getSession = vi
      .fn<ApiClient["session"]>()
      .mockResolvedValueOnce(session)
      .mockResolvedValue(refreshedSession);
    const saveText = vi
      .fn<ApiClient["saveText"]>()
      .mockRejectedValueOnce(
        new ApiError("forbidden", "denied", { status: 403 }),
      )
      .mockRejectedValueOnce(
        new ApiError("forbidden", "denied", { status: 403 }),
      )
      .mockImplementation(async (shareId, path) => ({
        shareId,
        path,
        outcome: "success",
      }));
    const loadText = vi.fn<ApiClient["text"]>(async (shareId, path) => ({
      shareId,
      path,
      text: "old",
      size: 3,
      mimeType: "text/plain",
      etag: '"content"',
    }));
    render(
      <App
        api={fakeApi({
          session: getSession,
          directory: vi.fn(async () => writablePage),
          text: loadText,
          saveText,
        })}
        navigation={writableNavigation()}
      />,
    );

    fireEvent.click(await screen.findByRole("link", { name: "notes.txt" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit notes.txt" }),
    );
    const editor = await screen.findByLabelText("UTF-8 text content");
    fireEvent.input(editor, { target: { value: "unsaved draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Your edits are still here",
    );
    expect(editor).toHaveValue("unsaved draft");
    expect(editor).toBeEnabled();
    expect(loadText).toHaveBeenCalledTimes(1);
    expect(saveText).toHaveBeenNthCalledWith(
      2,
      "work",
      "projects/notes.txt",
      "unsaved draft",
      'W/"test"',
      "refreshed-csrf",
      expect.any(AbortSignal),
    );

    fireEvent.click(screen.getByRole("button", { name: "Retry save" }));
    await waitFor(() => expect(saveText).toHaveBeenCalledTimes(3));
    expect(saveText).toHaveBeenNthCalledWith(
      3,
      "work",
      "projects/notes.txt",
      "unsaved draft",
      'W/"test"',
      "refreshed-csrf",
      expect.any(AbortSignal),
    );
    expect(
      screen.queryByRole("dialog", { name: "Edit notes.txt" }),
    ).not.toBeInTheDocument();
  });

  it("keeps the draft visible when sign-in expires during a save", async () => {
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async () => writablePage),
          saveText: vi.fn(async () => {
            throw new ApiError("unauthorized", "expired", { status: 401 });
          }),
        })}
        navigation={writableNavigation()}
      />,
    );

    fireEvent.click(await screen.findByRole("link", { name: "notes.txt" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit notes.txt" }),
    );
    const editor = await screen.findByLabelText("UTF-8 text content");
    fireEvent.input(editor, { target: { value: "keep this draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Sign in again in another tab",
    );
    expect(editor).toHaveValue("keep this draft");
    expect(screen.getByRole("button", { name: "Retry save" })).toBeEnabled();
  });

  it("keeps the draft without retrying when write access is revoked", async () => {
    const readOnlySession = {
      ...session,
      shares: session.shares.map((share) =>
        share.id === "work" ? { ...share, access: "read" as const } : share,
      ),
    };
    const getSession = vi
      .fn<ApiClient["session"]>()
      .mockResolvedValueOnce(session)
      .mockResolvedValue(readOnlySession);
    const saveText = vi
      .fn<ApiClient["saveText"]>()
      .mockRejectedValue(new ApiError("forbidden", "denied", { status: 403 }));
    render(
      <App
        api={fakeApi({
          session: getSession,
          directory: vi.fn(async () => writablePage),
          saveText,
        })}
        navigation={writableNavigation()}
      />,
    );

    fireEvent.click(await screen.findByRole("link", { name: "notes.txt" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit notes.txt" }),
    );
    const editor = await screen.findByLabelText("UTF-8 text content");
    fireEvent.input(editor, { target: { value: "keep private draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Write access is unavailable",
    );
    expect(editor).toHaveValue("keep private draft");
    expect(saveText).toHaveBeenCalledTimes(1);
  });

  it("uploads dropped files independently, exposes conflicts, and supports replacement", async () => {
    const uploadFile = vi.fn<ApiClient["uploadFile"]>(
      async (shareId, directory, file, _csrf, options) => {
        options?.onProgress?.(file.size, file.size);
        return {
          shareId,
          outcomes: [
            {
              path: `${directory}/${file.name}`,
              outcome:
                file.name === "exists.txt" && !options?.replace
                  ? "conflict"
                  : options?.replace
                    ? "replaced"
                    : "created",
            },
          ],
        };
      },
    );
    render(
      <App
        api={fakeApi({
          directory: vi.fn(async () => writablePage),
          uploadFile,
        })}
        navigation={writableNavigation()}
      />,
    );
    await screen.findByRole("button", { name: "Upload files" });
    await screen.findByRole("link", { name: "notes.txt" });
    dispatchDrag("dragenter", {
      types: ["application/x-crabinet-entry"],
      files: [],
    });
    expect(screen.queryByTestId("upload-drop-overlay")).not.toBeInTheDocument();

    const internalFile = new File(["internal"], "preview.png", {
      type: "image/png",
    });
    dispatchDrag("dragstart", { types: ["Files"], files: [internalFile] });
    dispatchDrag("dragenter", { types: ["Files"], files: [internalFile] });
    dispatchDrag("drop", { types: ["Files"], files: [internalFile] });
    expect(screen.queryByTestId("upload-drop-overlay")).not.toBeInTheDocument();
    expect(uploadFile).not.toHaveBeenCalled();

    const files = [
      new File(["one"], "new.txt", { type: "text/plain" }),
      new File(["two"], "exists.txt", { type: "text/plain" }),
    ];
    dispatchDrag("dragenter", { types: ["Files"], files });
    expect(await screen.findByTestId("upload-drop-overlay")).toHaveTextContent(
      "Drop files to upload",
    );
    expect(screen.getByTestId("upload-drop-overlay")).toHaveTextContent(
      "Working files / projects",
    );
    dispatchDrag(
      "drop",
      { types: [], files },
      screen.getByTestId("upload-drop-overlay"),
    );
    expect(screen.queryByTestId("upload-drop-overlay")).not.toBeInTheDocument();

    expect(await screen.findByText("Succeeded")).toBeVisible();
    expect(screen.getByText("Needs attention")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Replace existing file" }),
    );
    await waitFor(() =>
      expect(uploadFile).toHaveBeenLastCalledWith(
        "work",
        "projects",
        expect.objectContaining({ name: "exists.txt" }),
        "csrf-in-memory",
        expect.objectContaining({ replace: true, etag: 'W/"test"' }),
      ),
    );
    expect(await screen.findByText("Replaced")).toBeVisible();
  });

  it("cancels an in-flight upload and returns to login when a mutation session expires", async () => {
    const uploadFile = vi.fn<ApiClient["uploadFile"]>(
      async (_shareId, _directory, _file, _csrf, options) =>
        await new Promise((_resolve, reject) => {
          options?.signal?.addEventListener("abort", () =>
            reject(new ApiError("aborted", "cancelled")),
          );
        }),
    );
    const api = fakeApi({
      directory: vi.fn(async () => writablePage),
      uploadFile,
      createDirectory: vi
        .fn<ApiClient["createDirectory"]>()
        .mockRejectedValue(
          new ApiError("unauthorized", "expired", { status: 401 }),
        ),
    });
    render(<App api={api} navigation={writableNavigation()} />);

    const picker = await screen.findByLabelText("Choose files to upload");
    fireEvent.change(picker, {
      target: { files: [new File(["data"], "slow.txt")] },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect((await screen.findAllByText("Cancelled")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: "New folder" }));
    fireEvent.input(screen.getByLabelText("Folder name"), {
      target: { value: "expired" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(
      await screen.findByText(
        "Your session expired. Sign in again to continue.",
      ),
    ).toBeVisible();
  });
});

describe("security review regressions", () => {
  const projectEntries: DirectoryPage["entries"] = [
    { name: "notes.txt", kind: "file", size: 3 },
    { name: "empty", kind: "directory" },
  ];
  const listing = vi.fn<ApiClient["directory"]>(async (shareId, path) => ({
    shareId,
    path,
    entries:
      path === "projects"
        ? projectEntries
        : path === ""
          ? [{ name: "projects", kind: "directory" }]
          : [],
  }));
  const projects = () =>
    new MemoryNavigation({ shareId: "work", path: "projects" });

  function dragTransfer(initial: Record<string, string> = {}) {
    const data = new Map(Object.entries(initial));
    return {
      data,
      types: [] as string[],
      files: [] as File[],
      effectAllowed: "",
      dropEffect: "",
      setData: (type: string, value: string) => data.set(type, value),
      getData: (type: string) => data.get(type) ?? "",
    };
  }

  function fireDrag(
    type: "dragstart" | "drop",
    target: Element,
    dataTransfer: ReturnType<typeof dragTransfer>,
  ) {
    const event = new Event(type, { bubbles: true, cancelable: true });
    Object.defineProperty(event, "dataTransfer", { value: dataTransfer });
    fireEvent(target, event);
  }

  it("resolves a deep-linked preview's kind before offering deletion", async () => {
    const navigation = projects();
    navigation.restore({
      shareId: "work",
      path: "projects",
      previewPath: "archive",
    });
    const metadata = vi.fn<ApiClient["metadata"]>(async (shareId, path) => ({
      shareId,
      path,
      name: "archive",
      kind: "directory",
      etag: 'W/"folder"',
    }));
    const deleteEntry = vi.fn<ApiClient["deleteEntry"]>(
      async (shareId, path) => ({ shareId, path, outcome: "success" }),
    );
    render(
      <App
        api={fakeApi({ directory: listing, metadata, deleteEntry })}
        navigation={navigation}
      />,
    );

    const preview = await screen.findByRole("complementary", {
      name: "archive",
    });
    fireEvent.click(
      within(preview).getByRole("button", { name: "Delete archive" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Delete folder archive",
    });
    expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();
    const confirmation = within(dialog).getByLabelText(
      "Type archive to confirm",
    );
    fireEvent.input(confirmation, { target: { value: "archive" } });
    const button = within(dialog).getByRole("button", {
      name: "Delete",
      exact: true,
    });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    await waitFor(() =>
      expect(deleteEntry).toHaveBeenCalledWith(
        "work",
        "archive",
        'W/"folder"',
        "csrf-in-memory",
        expect.any(AbortSignal),
      ),
    );
  });

  it("deletes with the validator captured when the dialog opened", async () => {
    const etags = ['W/"reviewed"', 'W/"changed-later"'];
    const metadata = vi.fn<ApiClient["metadata"]>(async (shareId, path) => ({
      shareId,
      path,
      name: "notes.txt",
      kind: "file",
      etag: etags.shift() ?? 'W/"unexpected"',
    }));
    const deleteEntry = vi.fn<ApiClient["deleteEntry"]>(
      async (shareId, path) => ({ shareId, path, outcome: "success" }),
    );
    render(
      <App
        api={fakeApi({ directory: listing, metadata, deleteEntry })}
        navigation={projects()}
      />,
    );

    fireEvent.click(
      within(await screen.findByLabelText("Actions for notes.txt")).getByRole(
        "button",
        { name: "Delete notes.txt" },
      ),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Delete file notes.txt",
    });
    expect(within(dialog).getByRole("status")).toHaveTextContent(
      "Checking the current version",
    );
    fireEvent.click(within(dialog).getByRole("checkbox"));
    const button = within(dialog).getByRole("button", {
      name: "Delete",
      exact: true,
    });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledOnce());
    expect(deleteEntry.mock.calls[0]?.[2]).toBe('W/"reviewed"');
    expect(metadata).toHaveBeenCalledOnce();
  });

  it("blocks an operation when the item's kind changed since it was listed", async () => {
    const deleteEntry = vi.fn<ApiClient["deleteEntry"]>();
    render(
      <App
        api={fakeApi({
          directory: listing,
          metadata: vi.fn(async (shareId, path) => ({
            shareId,
            path,
            name: "notes.txt",
            kind: "directory" as const,
            etag: 'W/"now-a-folder"',
          })),
          deleteEntry,
        })}
        navigation={projects()}
      />,
    );

    fireEvent.click(
      within(await screen.findByLabelText("Actions for notes.txt")).getByRole(
        "button",
        { name: "Delete notes.txt" },
      ),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Delete file notes.txt",
    });
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "This item is now a folder",
    );
    fireEvent.click(within(dialog).getByRole("checkbox"));
    expect(
      within(dialog).getByRole("button", { name: "Delete", exact: true }),
    ).toBeDisabled();
    fireEvent.submit(within(dialog).getByRole("checkbox").closest("form")!);
    expect(deleteEntry).not.toHaveBeenCalled();
  });

  it("refuses to move a folder into itself", async () => {
    const moveEntry = vi.fn<ApiClient["moveEntry"]>();
    render(
      <App
        api={fakeApi({
          directory: listing,
          metadata: vi.fn(async (shareId, path) => ({
            shareId,
            path,
            name: "empty",
            kind: "directory" as const,
            etag: 'W/"folder"',
          })),
          moveEntry,
        })}
        navigation={projects()}
      />,
    );

    fireEvent.click(
      within(await screen.findByLabelText("Actions for empty")).getByRole(
        "button",
        { name: "Move empty" },
      ),
    );
    const dialog = screen.getByRole("dialog", { name: "Move empty" });
    fireEvent.click(
      await within(dialog).findByRole("button", { name: "Expand projects" }),
    );
    fireEvent.click(
      await within(dialog).findByRole("button", { name: "empty" }),
    );
    expect(
      within(dialog).getByText("Choose a different folder outside this item."),
    ).toBeVisible();
    expect(
      within(dialog).getByRole("button", { name: "Move here" }),
    ).toBeDisabled();
    expect(moveEntry).not.toHaveBeenCalled();
  });

  it("stops retrying a failed destination listing until asked", async () => {
    let rootFailures = 0;
    const directory = vi.fn<ApiClient["directory"]>(async (shareId, path) => {
      if (path === "" && rootFailures++ < 1) {
        throw new ApiError("server", "unavailable", { status: 500 });
      }
      return listing(shareId, path);
    });
    render(<App api={fakeApi({ directory })} navigation={projects()} />);

    fireEvent.click(
      within(await screen.findByLabelText("Actions for notes.txt")).getByRole(
        "button",
        { name: "Move notes.txt" },
      ),
    );
    const dialog = screen.getByRole("dialog", { name: "Move notes.txt" });
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Folders could not be loaded.",
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    const rootCalls = () =>
      directory.mock.calls.filter(([, path]) => path === "").length;
    expect(rootCalls()).toBe(1);

    fireEvent.click(within(dialog).getByRole("button", { name: "Try again" }));
    expect(
      await within(dialog).findByRole("button", { name: "projects" }),
    ).toBeVisible();
    expect(rootCalls()).toBe(2);
  });

  it("keeps the newest sidebar listing when an older request finishes last", async () => {
    let releaseStale: (page: DirectoryPage) => void = () => undefined;
    const signals: AbortSignal[] = [];
    let treeCalls = 0;
    const directory = vi.fn<ApiClient["directory"]>(
      async (shareId, path, _cursor, signal) => {
        if (shareId !== "read-only") return listing(shareId, path);
        if (signal) signals.push(signal);
        treeCalls += 1;
        if (treeCalls === 1) {
          return await new Promise<DirectoryPage>((resolve) => {
            releaseStale = resolve;
          });
        }
        return {
          shareId,
          path,
          entries: [{ name: "Fresh", kind: "directory" }],
        };
      },
    );
    render(<App api={fakeApi({ directory })} navigation={projects()} />);
    const sidebar = within(
      await screen.findByRole("complementary", { name: "Shared folders" }),
    );

    fireEvent.click(sidebar.getByRole("button", { name: "Expand Reference" }));
    fireEvent.click(
      sidebar.getByRole("button", { name: "Collapse Reference" }),
    );
    fireEvent.click(sidebar.getByRole("button", { name: "Expand Reference" }));
    expect(await sidebar.findByRole("link", { name: "Fresh" })).toBeVisible();

    releaseStale({
      shareId: "read-only",
      path: "",
      entries: [{ name: "Stale", kind: "directory" }],
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(signals[0]?.aborted).toBe(true);
    expect(sidebar.queryByRole("link", { name: "Stale" })).toBeNull();
    expect(sidebar.getByRole("link", { name: "Fresh" })).toBeVisible();
  });

  it("accepts only entry drags produced by this page", async () => {
    render(
      <App api={fakeApi({ directory: listing })} navigation={projects()} />,
    );
    const row = (
      await screen.findByRole("link", { name: "notes.txt" })
    ).closest<HTMLElement>(".entry-row")!;
    const sidebar = within(
      screen.getByRole("complementary", { name: "Shared folders" }),
    );
    const target = sidebar
      .getByRole("link", { name: "Working files" })
      .closest<HTMLElement>(".tree-row")!;
    const type = "application/x-crabinet-entry";

    const forged = dragTransfer({
      [type]: JSON.stringify({
        shareId: "work",
        path: "projects/notes.txt",
        entry: { name: "notes.txt", kind: "file" },
      }),
    });
    fireDrag("drop", target, forged);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    const genuine = dragTransfer();
    fireDrag("dragstart", row, genuine);
    const payload = JSON.parse(genuine.getData(type)) as {
      entry: { name: string };
    };
    const tampered = dragTransfer({
      [type]: JSON.stringify({
        ...payload,
        entry: { ...payload.entry, name: "other.txt" },
      }),
    });
    fireDrag("drop", target, tampered);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    fireDrag("drop", target, genuine);
    expect(
      await screen.findByRole("dialog", { name: "Move notes.txt" }),
    ).toBeVisible();
  });

  it("replaces an upload only with the version shown in the conflict", async () => {
    const etags = ['W/"shown"', 'W/"changed-later"'];
    const metadata = vi.fn<ApiClient["metadata"]>(async (shareId, path) => ({
      shareId,
      path,
      name: "exists.txt",
      kind: "file",
      etag: etags.shift() ?? 'W/"unexpected"',
    }));
    const uploadFile = vi.fn<ApiClient["uploadFile"]>(
      async (shareId, directory, file, _csrf, options) => ({
        shareId,
        outcomes: [
          {
            path: `${directory}/${file.name}`,
            outcome: options?.replace ? "replaced" : "conflict",
          },
        ],
      }),
    );
    render(
      <App
        api={fakeApi({ directory: listing, metadata, uploadFile })}
        navigation={projects()}
      />,
    );

    fireEvent.change(await screen.findByLabelText("Choose files to upload"), {
      target: { files: [new File(["new"], "exists.txt")] },
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "Replace existing file" }),
    );
    expect(await screen.findByText("Replaced")).toBeVisible();
    expect(metadata).toHaveBeenCalledOnce();
    expect(uploadFile).toHaveBeenLastCalledWith(
      "work",
      "projects",
      expect.objectContaining({ name: "exists.txt" }),
      "csrf-in-memory",
      expect.objectContaining({ replace: true, etag: 'W/"shown"' }),
    );
  });

  it("offers no replacement when the conflicting name is a folder", async () => {
    render(
      <App
        api={fakeApi({
          directory: listing,
          metadata: vi.fn(async (shareId, path) => ({
            shareId,
            path,
            name: "empty",
            kind: "directory" as const,
            etag: 'W/"folder"',
          })),
          uploadFile: vi.fn(async (shareId, directory, file) => ({
            shareId,
            outcomes: [
              {
                path: `${directory}/${file.name}`,
                outcome: "conflict" as const,
              },
            ],
          })),
        })}
        navigation={projects()}
      />,
    );

    fireEvent.change(await screen.findByLabelText("Choose files to upload"), {
      target: { files: [new File(["new"], "empty")] },
    });
    expect(
      await screen.findByText("A folder with this name already exists."),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Replace existing file" }),
    ).not.toBeInTheDocument();
  });

  it("retries a start-folder save once after another tab rotated the session", async () => {
    const updateDefaultFolder = vi
      .fn<ApiClient["updateDefaultFolder"]>()
      .mockRejectedValueOnce(
        new ApiError("forbidden", "stale", { status: 403, code: "forbidden" }),
      )
      .mockImplementation(async (folder) => folder);
    const sessionRequest = vi
      .fn<ApiClient["session"]>()
      .mockResolvedValueOnce(session)
      .mockResolvedValue({ ...session, csrfToken: "rotated" });
    render(
      <App
        api={fakeApi({ session: sessionRequest, updateDefaultFolder })}
        navigation={new MemoryNavigation()}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    const select = within(
      screen.getByRole("dialog", { name: "Settings" }),
    ).getByRole("combobox", { name: "Start folder" });
    fireEvent.change(select, { target: { value: "work" } });
    await waitFor(() => expect(select).toHaveValue("work"));
    expect(updateDefaultFolder.mock.calls.map((call) => call[1])).toEqual([
      "csrf-in-memory",
      "rotated",
    ]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows a saved start folder that is no longer shared instead of the default", async () => {
    render(
      <App
        api={fakeApi({
          session: vi.fn(async () => ({
            ...session,
            defaultFolder: { shareId: "revoked", path: "" },
          })),
        })}
        navigation={new MemoryNavigation()}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    const select = within(
      screen.getByRole("dialog", { name: "Settings" }),
    ).getByRole("combobox", { name: "Start folder" });
    expect(select).toHaveValue("/");
    expect(
      within(select).getByRole("option", {
        name: "Current: a folder you can no longer access",
      }),
    ).toBeDisabled();
  });
});

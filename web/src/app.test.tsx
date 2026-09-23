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
    login: overrides.login ?? vi.fn(async () => session),
    logout: overrides.logout ?? vi.fn(async () => undefined),
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
    expect(screen.getByLabelText("Username")).toHaveAttribute(
      "autocomplete",
      "username",
    );
    expect(screen.getByLabelText("Password")).toHaveAttribute(
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
    fireEvent.input(screen.getByLabelText("Username"), {
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
    fireEvent.input(screen.getByLabelText("Username"), {
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
    fireEvent.input(screen.getByLabelText("New name"), {
      target: { value: "renamed.md" },
    });
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
    const dialog = screen.getByRole("dialog", { name: "Move notes.txt" });
    fireEvent.click(
      await within(dialog).findByRole("button", { name: "Shared folder" }),
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

    const dialog = screen.getByRole("dialog", {
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
    expect(deleteButton).toBeEnabled();
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
    expect(editor).toBeDisabled();
    expect(saveText).toHaveBeenCalledWith(
      "work",
      "projects/notes.txt",
      "new",
      'W/"test"',
      "csrf-in-memory",
      expect.any(AbortSignal),
    );
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

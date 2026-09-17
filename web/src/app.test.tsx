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

function fakeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    session: overrides.session ?? vi.fn(async () => session),
    login: overrides.login ?? vi.fn(async () => session),
    logout: overrides.logout ?? vi.fn(async () => undefined),
    directory: overrides.directory ?? vi.fn(async () => emptyPage),
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
      await screen.findByRole("heading", { name: "Sign in to Index" }),
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
    await screen.findByRole("heading", { name: "Sign in to Index" });
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
    await screen.findByRole("heading", { name: "Sign in to Index" });
    fireEvent.input(screen.getByLabelText("Username"), {
      target: { value: "joan" },
    });
    fireEvent.input(screen.getByLabelText("Password"), {
      target: { value: "secret" },
    });
    fireEvent.submit(
      screen.getByRole("button", { name: "Sign in" }).closest("form")!,
    );

    expect(await screen.findByText("Read only")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByRole("heading", { name: "Sign in to Index" });
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
      screen.getByRole("heading", { name: "Sign in to Index" }),
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
      "Index is unavailable",
    );
    expect(
      screen.queryByText(/internal connection detail/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Sign in to Index" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Read only")).toBeVisible();
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
    expect(screen.getByLabelText("Shared folder")).toBeInstanceOf(
      HTMLSelectElement,
    );
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

    expect(await screen.findByText("Grüße 東京 🚀")).toBeVisible();
    expect(screen.getByText("<img src=x onerror=alert(1)>.txt")).toBeVisible();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("Read only")).toBeVisible();
    expect(
      screen.getByRole("option", { name: "Working files — Read & write" }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("link", { name: "Grüße 東京 🚀" }));
    expect(navigation.visits.at(-1)?.route).toEqual({
      shareId: "read-only",
      path: "Grüße 東京 🚀",
    });

    fireEvent.change(screen.getByLabelText("Shared folder"), {
      target: { value: "work" },
    });
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
      path: "projects/Index",
    });
    const directory = vi.fn<ApiClient["directory"]>(async (shareId, path) => ({
      shareId,
      path,
      entries:
        path === "projects" ? [{ name: "restored.txt", kind: "file" }] : [],
    }));

    render(<App api={fakeApi({ directory })} navigation={navigation} />);
    expect(
      await screen.findByRole("heading", { name: "Index" }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(directory).toHaveBeenCalledWith(
        "work",
        "projects/Index",
        undefined,
        expect.any(AbortSignal),
      ),
    );

    fireEvent.click(screen.getByRole("link", { name: "projects" }));
    expect(await screen.findByText("restored.txt")).toBeVisible();
    expect(navigation.visits.at(-1)?.route.path).toBe("projects");

    navigation.restore({ shareId: "work", path: "projects/Index" });
    await waitFor(() =>
      expect(directory).toHaveBeenLastCalledWith(
        "work",
        "projects/Index",
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

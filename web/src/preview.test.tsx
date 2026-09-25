import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  type ApiClient,
  type DirectoryPage,
  type PreviewDocument,
  type Session,
} from "./api";
import { App } from "./app";
import type { BrowserNavigation, BrowserRoute } from "./navigation";

const session: Session = {
  user: { id: "u-1", username: "joan", displayName: "Joan" },
  shares: [{ id: "docs", name: "Documents", access: "read" }],
  csrfToken: "memory-only-csrf",
};

const files: DirectoryPage = {
  shareId: "docs",
  path: "",
  entries: [
    { name: "unsafe.md", kind: "file", size: 42 },
    { name: "demo.html", kind: "file", size: 42 },
    { name: "code.rs", kind: "file", size: 42 },
    { name: "photo.png", kind: "file", size: 2048 },
  ],
};

class MemoryNavigation implements BrowserNavigation {
  private route: BrowserRoute;
  private readonly listeners = new Set<(route: BrowserRoute) => void>();
  readonly visits: BrowserRoute[] = [];

  constructor(route: BrowserRoute = { shareId: "docs", path: "" }) {
    this.route = route;
  }

  current() {
    return this.route;
  }

  go(route: BrowserRoute) {
    this.route = route;
    this.visits.push(route);
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

function previewDocument(
  source: string,
  overrides: Partial<PreviewDocument> = {},
): PreviewDocument {
  return {
    kind: "text",
    source,
    size: new TextEncoder().encode(source).byteLength,
    truncated: false,
    ...overrides,
  };
}

function fakeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    session: overrides.session ?? vi.fn(async () => session),
    authMethods:
      overrides.authMethods ??
      vi.fn(async () => ({ passwordEnabled: true, oidcEnabled: false })),
    login: overrides.login ?? vi.fn(async () => session),
    logout: overrides.logout ?? vi.fn(async () => undefined),
    directory: overrides.directory ?? vi.fn(async () => files),
    preview:
      overrides.preview ?? vi.fn(async () => previewDocument("plain text")),
    metadata: overrides.metadata ?? vi.fn(),
    text: overrides.text ?? vi.fn(),
    createDirectory: overrides.createDirectory ?? vi.fn(),
    createFile: overrides.createFile ?? vi.fn(),
    saveText: overrides.saveText ?? vi.fn(),
    moveEntry: overrides.moveEntry ?? vi.fn(),
    deleteEntry: overrides.deleteEntry ?? vi.fn(),
    uploadFile: overrides.uploadFile ?? vi.fn(),
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("secure file previews", () => {
  it("reloads the open preview when its directory reports a file change", async () => {
    class TestEventSource extends EventTarget {
      static instance: TestEventSource;
      readyState = 1;

      constructor() {
        super();
        TestEventSource.instance = this;
      }

      close() {}
    }
    vi.stubGlobal("EventSource", TestEventSource);
    const preview = vi
      .fn()
      .mockResolvedValueOnce(previewDocument("before save"))
      .mockResolvedValue(previewDocument("after save"));
    const api = fakeApi({ preview });

    render(<App api={api} navigation={new MemoryNavigation()} />);
    fireEvent.click(await screen.findByRole("link", { name: "code.rs" }));
    expect(await screen.findByLabelText("File source")).toHaveTextContent(
      "before save",
    );

    TestEventSource.instance.dispatchEvent(new Event("invalidate"));
    await waitFor(() =>
      expect(screen.getByLabelText("File source")).toHaveTextContent(
        "after save",
      ),
    );
    expect(preview).toHaveBeenCalledTimes(2);
  });

  it("renders hostile code as text, supports wrapping, and never writes storage", async () => {
    const source =
      '<img src=x onerror="alert(1)"><script>localStorage.pwned=1</script>';
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const api = fakeApi({
      preview: vi.fn(async () =>
        previewDocument(source, { kind: "code", language: "javascript" }),
      ),
    });

    render(<App api={api} navigation={new MemoryNavigation()} />);
    fireEvent.click(await screen.findByRole("link", { name: "code.rs" }));

    const sourceRegion = await screen.findByLabelText("File source");
    expect(sourceRegion).toHaveTextContent(source);
    expect(sourceRegion).toHaveClass("source-code-wrap");
    expect(document.querySelector("main img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    expect(storageSpy).not.toHaveBeenCalled();

    fireEvent.click(
      screen.getByRole("button", { name: "Disable line wrapping" }),
    );
    expect(sourceRegion).not.toHaveClass("source-code-wrap");
    expect(
      screen.getByRole("button", { name: "Enable line wrapping" }),
    ).toHaveAttribute("aria-pressed", "false");
    storageSpy.mockRestore();
  });

  it("offers keyboard-operated Markdown modes without activating hostile markup", async () => {
    const hostile = [
      "# Safe heading",
      "<script>top.location='https://attacker.invalid'</script>",
      "![beacon](https://attacker.invalid/pixel)",
      "[run](javascript:alert(document.cookie))",
      '<form action="/api/v1/auth/logout"><button>submit</button></form>',
    ].join("\n\n");
    const api = fakeApi({
      preview: vi.fn(async () =>
        previewDocument(hostile, {
          kind: "markdown_source",
          language: "markdown",
        }),
      ),
    });

    render(<App api={api} navigation={new MemoryNavigation()} />);
    fireEvent.click(await screen.findByRole("link", { name: "unsafe.md" }));

    const readable = await screen.findByRole("tab", { name: "Readable" });
    expect(readable).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("markdown-document")).toHaveTextContent(
      "top.location",
    );
    expect(
      document.querySelector("main script, main img, main form"),
    ).toBeNull();
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();

    fireEvent.keyDown(readable, { key: "ArrowRight" });
    const sourceTab = screen.getByRole("tab", { name: "Source" });
    expect(sourceTab).toHaveAttribute("aria-selected", "true");
    expect(sourceTab).toHaveFocus();
    expect(screen.getByLabelText("Markdown source").textContent).toBe(hostile);

    fireEvent.keyDown(sourceTab, { key: "Home" });
    expect(readable).toHaveAttribute("aria-selected", "true");
    expect(readable).toHaveFocus();
  });

  it("uses rendered and inert-source HTML tabs in an empty-sandbox iframe", async () => {
    const api = fakeApi({
      preview: vi.fn(async () =>
        previewDocument("<script>alert(1)</script>", {
          kind: "html_source",
          language: "html",
        }),
      ),
    });
    const navigation = new MemoryNavigation({
      shareId: "docs",
      path: "",
      previewPath: "demo.html",
    });

    render(<App api={api} navigation={navigation} />);

    const panel = await screen.findByRole("complementary", {
      name: "demo.html",
    });
    const frame = await within(panel).findByTitle(
      "Sandboxed HTML preview for demo.html",
    );
    expect(frame).toHaveAttribute("sandbox", "");
    expect(frame).toHaveAttribute(
      "src",
      "/api/v1/shares/docs/preview/html/rendered?path=demo.html&v=0-0",
    );
    expect(frame.getAttribute("sandbox")?.split(/\s+/).filter(Boolean)).toEqual(
      [],
    );
    expect(panel).toHaveTextContent(
      "Scripts, forms, navigation, storage, popups, and network requests are disabled",
    );
    fireEvent.click(within(panel).getByRole("tab", { name: "Source" }));
    expect(frame).toHaveAttribute(
      "src",
      "/api/v1/shares/docs/preview/html?path=demo.html&v=0-0",
    );
    const renderedNewTab = within(panel).getByRole("link", {
      name: "Open rendered HTML in new tab",
    });
    expect(renderedNewTab).toHaveAttribute(
      "href",
      "/api/v1/shares/docs/preview/html/rendered?path=demo.html",
    );
    expect(renderedNewTab).toHaveAttribute("rel", "noopener noreferrer");
    expect(
      within(panel).getByRole("link", { name: "Open HTML source in new tab" }),
    ).toHaveAttribute("rel", "noopener noreferrer");
    expect(
      within(panel).getByRole("link", { name: "Download demo.html" }),
    ).toHaveAttribute("href", "/api/v1/shares/docs/download?path=demo.html");
    expect(
      within(panel).getByRole("link", { name: "Download demo.html" }),
    ).toHaveAttribute("data-tooltip", "Download demo.html");
    expect(
      within(panel).getByRole("link", { name: "Download demo.html" }),
    ).not.toHaveAttribute("title");
  });

  it("preserves deep links and restores focus to the opening file on close", async () => {
    const navigation = new MemoryNavigation();
    render(<App api={fakeApi()} navigation={navigation} />);

    const trigger = await screen.findByRole("link", { name: "code.rs" });
    fireEvent.click(trigger);
    expect(navigation.visits.at(-1)).toEqual({
      shareId: "docs",
      path: "",
      previewPath: "code.rs",
    });
    const previewHeading = await screen.findByRole("heading", {
      name: "code.rs",
    });
    await waitFor(() => expect(previewHeading).toHaveFocus());

    fireEvent.click(
      screen.getByRole("button", { name: "Close preview of code.rs" }),
    );
    expect(navigation.visits.at(-1)).toEqual({ shareId: "docs", path: "" });
    expect(trigger).toHaveFocus();
    expect(
      screen.queryByRole("complementary", { name: "code.rs" }),
    ).not.toBeInTheDocument();
  });

  it("opens an expanded modal raster preview from validated metadata", async () => {
    const navigation = new MemoryNavigation({
      shareId: "docs",
      path: "",
      previewPath: "photo.png",
    });
    const api = fakeApi({
      preview: vi.fn<ApiClient["preview"]>(async () => ({
        kind: "image",
        source: "",
        mimeType: "image/png",
        width: 800,
        height: 600,
        size: 2048,
        truncated: false,
      })),
      metadata: vi.fn(async () => ({
        shareId: "docs",
        path: "photo.png",
        name: "photo.png",
        kind: "file" as const,
        size: 2048,
        accessedAtMs: 1_700_000_000_000,
        createdAtMs: 1_690_000_000_000,
        etag: 'W/"photo"',
      })),
    });
    render(<App api={api} navigation={navigation} />);

    const image = await screen.findByRole("img", {
      name: "Preview of photo.png",
    });
    expect(image).toHaveAttribute(
      "src",
      "/api/v1/shares/docs/preview/image?path=photo.png&v=0-0",
    );
    const imageLink = screen.getByRole("link", {
      name: "Open photo.png in a new tab",
    });
    expect(imageLink).toHaveAttribute(
      "href",
      "/api/v1/shares/docs/preview/image?path=photo.png&v=0-0",
    );
    expect(imageLink).toHaveAttribute("target", "_blank");
    expect(imageLink).toHaveAttribute("rel", "noopener noreferrer");
    expect(imageLink).toHaveAttribute("draggable", "false");
    expect(image).toHaveAttribute("draggable", "false");
    expect(screen.getByText(/800 × 600/)).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Reset zoom" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Zoom out" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Zoom in" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand preview" }));
    expect(navigation.visits.at(-1)).toEqual({
      shareId: "docs",
      path: "",
      previewPath: "photo.png",
      previewMode: "full",
    });
    const fullScreenPanel = screen.getByRole("dialog", {
      name: "photo.png",
    });
    expect(fullScreenPanel).toHaveClass("is-fullscreen");
    expect(screen.getByText("Expanded preview")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Restore side preview" }),
    ).toHaveAttribute("data-tooltip", "Restore side preview");
    expect(document.querySelector(".preview-modal-backdrop")).toBeVisible();
    expect(document.documentElement).toHaveClass("preview-fullscreen-open");
    const details = screen.getByLabelText("File details");
    expect(details).toHaveTextContent("2.0 kB");
    expect(details).toHaveTextContent("image/png");
    expect(details).not.toHaveTextContent("Unavailable");

    fireEvent.click(document.querySelector(".preview-modal-backdrop")!);
    expect(navigation.visits.at(-1)).toEqual({
      shareId: "docs",
      path: "",
      previewPath: "photo.png",
      previewMode: "side",
    });
    await waitFor(() =>
      expect(document.documentElement).not.toHaveClass(
        "preview-fullscreen-open",
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "Expand preview" }));
    fireEvent.keyDown(window, { key: "Escape" });
    expect(navigation.visits.at(-1)).toEqual({
      shareId: "docs",
      path: "",
      previewPath: "photo.png",
      previewMode: "side",
    });
  });

  it("aborts stale previews and ignores a late session error from the old file", async () => {
    const requests = new Map<
      string,
      {
        signal: AbortSignal | undefined;
        resolve: (document: PreviewDocument) => void;
        reject: (error: unknown) => void;
      }
    >();
    const preview = vi.fn<ApiClient["preview"]>(
      (_shareId, path, signal) =>
        new Promise((resolve, reject) => {
          requests.set(path, { signal, resolve, reject });
        }),
    );
    const navigation = new MemoryNavigation({
      shareId: "docs",
      path: "",
      previewPath: "unsafe.md",
    });

    render(<App api={fakeApi({ preview })} navigation={navigation} />);
    await waitFor(() => expect(requests.has("unsafe.md")).toBe(true));
    navigation.restore({
      shareId: "docs",
      path: "",
      previewPath: "code.rs",
    });
    await waitFor(() => expect(requests.has("code.rs")).toBe(true));
    expect(requests.get("unsafe.md")?.signal?.aborted).toBe(true);

    requests.get("code.rs")!.resolve(previewDocument("new file"));
    expect(await screen.findByText("new file")).toBeVisible();
    requests
      .get("unsafe.md")!
      .reject(new ApiError("unauthorized", "late expiry", { status: 401 }));

    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: "Sign in to Crabinet" }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByText("new file")).toBeVisible();
  });

  it("returns to sign-in when the current preview reports session expiry", async () => {
    const api = fakeApi({
      preview: vi
        .fn()
        .mockRejectedValue(
          new ApiError("unauthorized", "expired", { status: 401 }),
        ),
    });
    render(
      <App
        api={api}
        navigation={
          new MemoryNavigation({
            shareId: "docs",
            path: "",
            previewPath: "code.rs",
          })
        }
      />,
    );

    expect(
      await screen.findByText(
        "Your session expired. Sign in again to continue.",
      ),
    ).toBeVisible();
  });

  it.each([
    ["preview_too_large", 413, "File is too large to preview"],
    ["binary_file", 415, "Binary preview is not supported"],
    ["invalid_utf8", 415, "Text encoding is not supported"],
    ["unsupported_entry", 415, "This item cannot be previewed"],
    ["not_found", 404, "Preview no longer available"],
  ])("shows a specific safe error for %s", async (code, status, title) => {
    const kind = status === 404 ? "not-found" : "server";
    const api = fakeApi({
      preview: vi
        .fn()
        .mockRejectedValue(
          new ApiError(kind, "sensitive backend detail", { code, status }),
        ),
    });
    render(
      <App
        api={api}
        navigation={
          new MemoryNavigation({
            shareId: "docs",
            path: "",
            previewPath: "code.rs",
          })
        }
      />,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(title);
    expect(
      screen.queryByText("sensitive backend detail"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Download code.rs" }),
    ).toBeVisible();
  });

  it("announces empty and truncated previews without hiding the download path", async () => {
    const preview = vi
      .fn<ApiClient["preview"]>()
      .mockResolvedValueOnce(previewDocument(""))
      .mockResolvedValueOnce(
        previewDocument("partial", { truncated: true, kind: "text" }),
      );
    const navigation = new MemoryNavigation({
      shareId: "docs",
      path: "",
      previewPath: "empty.txt",
    });
    render(<App api={fakeApi({ preview })} navigation={navigation} />);

    expect(await screen.findByText("This file is empty.")).toBeVisible();
    navigation.restore({
      shareId: "docs",
      path: "",
      previewPath: "partial.txt",
    });
    expect(
      await screen.findByText(
        "This preview is truncated. Download the file to see all content.",
      ),
    ).toBeVisible();
  });
});

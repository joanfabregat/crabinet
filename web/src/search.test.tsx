import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient, type SearchPage } from "./api";
import { SearchPanel } from "./search";
import {
  routeFromUrl,
  type BrowserNavigation,
  type BrowserRoute,
} from "./navigation";

const shares = [
  { id: "documents", name: "Documents", access: "read" as const },
  { id: "images", name: "Images", access: "read" as const },
];
const entry = {
  shareId: "documents",
  path: "reports/invoice.pdf",
  name: "invoice.pdf",
  kind: "file" as const,
  size: 12000,
};
const page: SearchPage = {
  entries: [entry],
  indexing: false,
  incomplete: false,
};
function setup(
  search: ApiClient["search"] = vi.fn(async (): Promise<SearchPage> => page),
  route: BrowserRoute = { shareId: "documents", path: "reports" },
) {
  const go = vi.fn();
  const navigation = {
    go,
    current: () => route,
    subscribe: () => () => undefined,
  } as BrowserNavigation;
  const expired = vi.fn();
  const api = { search } as unknown as ApiClient;
  render(
    <SearchPanel
      api={api}
      route={route}
      navigation={navigation}
      shares={shares}
      hidden={false}
      onSessionExpired={expired}
    />,
  );
  return {
    search: vi.mocked(search),
    go,
    expired,
    input: screen.getByRole("combobox", { name: "Search files" }),
  };
}

describe("search", () => {
  it("widens the idle bar on focus, not on press, and focuses the input from anywhere on it", () => {
    const { input } = setup();
    const controls = input.closest(".search-controls")!;
    const wrap = input.closest(".search-input-wrap")!;
    // A press must not move the input before a touch's tap lands on it.
    fireEvent.pointerDown(input);
    expect(controls).not.toHaveClass("is-expanded");
    fireEvent.pointerDown(wrap);
    expect(input).toHaveFocus();
    expect(controls).toHaveClass("is-expanded");
    // Touch Safari keeps focus on a background tap, so the press ends it.
    fireEvent.pointerDown(document.body);
    expect(controls).not.toHaveClass("is-expanded");
    expect(input).not.toHaveFocus();
  });
  it("opens an icon-only filter panel and dismisses it by Escape, toggle, or outside click", async () => {
    setup();
    const button = screen.getByRole("button", { name: "Search filters" });
    expect(button).toHaveTextContent("");
    fireEvent.click(button);
    expect(
      screen.getByRole("dialog", { name: "Search filters" }),
    ).toBeVisible();
    expect(button).toHaveAttribute("aria-expanded", "true");
    expect(document.querySelector(".modal-backdrop")).toBeNull();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(button).toHaveFocus();
    fireEvent.click(button);
    fireEvent.click(button);
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(button);
    fireEvent.pointerDown(document.body);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
  it("debounces suggestions, searches the share by default, and opens a keyboard-selected result", async () => {
    const { search, input, go } = setup();
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "inv" } });
    fireEvent.input(input, { target: { value: "invoice" } });
    await screen.findByRole("option", { name: /invoice.pdf/ });
    expect(search).toHaveBeenCalledTimes(1);
    expect(search.mock.calls[0]?.[0]).toEqual({
      q: "invoice",
      share: "documents",
      path: "",
      showHidden: false,
      limit: 8,
    });
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.submit(screen.getByRole("search"));
    expect(go).toHaveBeenCalledWith(
      expect.objectContaining({
        searchQuery: "invoice",
        searchScope: "share",
        previewPath: entry.path,
        previewShareId: "documents",
      }),
    );
  });
  it("suggests typed filters without making an invalid search request", async () => {
    const { input, search } = setup();
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "type:im" } });
    fireEvent.click(
      await within(
        await screen.findByRole("listbox", { name: "Search suggestions" }),
      ).findByRole("option", { name: "Images" }),
    );
    expect(input).toHaveValue("type:image ");
    expect(search).not.toHaveBeenCalled();
    fireEvent.input(input, { target: { value: "size:" } });
    fireEvent.click(
      await screen.findByRole("option", { name: "Choose a size filter…" }),
    );
    expect(
      screen.getByRole("dialog", { name: "Search filters" }),
    ).toBeVisible();
  });
  it("builds type, extension, size range and date filters with visual controls", () => {
    const { go } = setup();
    fireEvent.click(screen.getByRole("button", { name: "Search filters" }));
    const dialog = screen.getByRole("dialog", { name: "Search filters" });
    fireEvent.click(within(dialog).getByLabelText("PDF"));
    fireEvent.input(within(dialog).getByLabelText("Extension"), {
      target: { value: "pdf" },
    });
    fireEvent.change(within(dialog).getByLabelText("Size comparison"), {
      target: { value: "between" },
    });
    fireEvent.input(within(dialog).getByLabelText("File size"), {
      target: { value: "10" },
    });
    fireEvent.input(within(dialog).getByLabelText("Maximum file size"), {
      target: { value: "100" },
    });
    fireEvent.input(within(dialog).getByLabelText("On or after"), {
      target: { value: "2026-01-01" },
    });
    fireEvent.submit(
      within(dialog)
        .getByRole("button", { name: "Apply filters" })
        .closest("form")!,
    );
    expect(go).toHaveBeenCalledWith(
      expect.objectContaining({
        searchQuery:
          "type:pdf ext:pdf size:>=10kb size:<=100kb modified:>=2026-01-01",
      }),
    );
  });
  it("keeps scope and results in the route and excludes ungranted suggestions", async () => {
    const search = vi.fn(async () => ({
      ...page,
      entries: [
        { ...entry, shareId: "private" },
        { ...entry, shareId: "images" },
      ],
    }));
    const { input, go } = setup(search);
    fireEvent.change(screen.getByLabelText("Search scope"), {
      target: { value: "all" },
    });
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "invoice" } });
    await screen.findByRole("option", { name: /invoice.pdf/ });
    expect(screen.getAllByRole("option", { name: /invoice.pdf/ })).toHaveLength(
      1,
    );
    fireEvent.click(screen.getByRole("option", { name: /invoice.pdf/ }));
    expect(go).toHaveBeenCalledWith(
      expect.objectContaining({ searchScope: "all", previewShareId: "images" }),
    );
  });
  it("searches another share from the scope menu while staying in the current one", async () => {
    const { search, input, go } = setup();
    const scope = screen.getByLabelText("Search scope");
    expect(
      within(scope).getByRole("option", { name: "Documents (current)" }),
    ).toBeInTheDocument();
    fireEvent.change(scope, { target: { value: "share:images" } });
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "invoice" } });
    await waitFor(() =>
      expect(search.mock.calls.at(-1)?.[0]).toMatchObject({
        q: "invoice",
        share: "images",
        path: "",
      }),
    );
    fireEvent.submit(screen.getByRole("search"));
    expect(go).toHaveBeenLastCalledWith(
      expect.objectContaining({
        shareId: "documents",
        searchShareId: "images",
        searchScope: "share",
        searchQuery: "invoice",
      }),
    );
  });
  it("groups all-shares results under share headings", async () => {
    setup(
      vi.fn(async () => ({
        ...page,
        entries: [
          {
            ...entry,
            shareId: "images",
            path: "invoice.png",
            name: "invoice.png",
          },
          entry,
        ],
      })),
      {
        shareId: "documents",
        path: "",
        searchQuery: "invoice",
        searchScope: "all",
      },
    );
    const documents = await screen.findByRole("region", {
      name: /^Documents\s+1 match$/,
    });
    const images = screen.getByRole("region", { name: /^Images\s+1 match$/ });
    // Groups follow the share order, and locations omit the heading's share.
    expect(
      documents.compareDocumentPosition(images) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      within(documents).getByRole("link", { name: "reports" }),
    ).toBeInTheDocument();
    expect(
      within(images).getByRole("link", { name: "Images" }),
    ).toBeInTheDocument();
  });
  it("numbers five pages around the current one, with gaps where more exist", async () => {
    const results = (offset: number, pagesAfter: number) => {
      const { go } = setup(
        vi.fn(async () => ({
          ...page,
          nextOffset: pagesAfter ? offset + 50 : undefined,
          pagesAfter,
        })),
        {
          shareId: "documents",
          path: "",
          searchQuery: "invoice",
          searchScope: "share",
          searchOffset: offset,
        },
      );
      return go;
    };
    const labels = async () => {
      const nav = await screen.findByRole("navigation", {
        name: "Result pages",
      });
      return Array.from(nav.children, (item) =>
        item.matches(".search-page-gap")
          ? "…"
          : (item.textContent ?? "").trim(),
      );
    };

    // First page: the next four pages, then a gap since more follow.
    let go = results(0, 5);
    expect(await labels()).toEqual([
      "Previous",
      "1",
      "2",
      "3",
      "4",
      "5",
      "…",
      "Next",
    ]);
    expect(
      screen.getByRole("button", { name: "Previous page" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Page 1" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    fireEvent.click(screen.getByRole("button", { name: "Page 4" }));
    expect(go).toHaveBeenCalledWith(
      expect.objectContaining({ searchOffset: 150 }),
    );
    cleanup();

    // Middle: two pages each side and a gap on both.
    go = results(450, 5);
    expect(await labels()).toEqual([
      "Previous",
      "…",
      "8",
      "9",
      "10",
      "11",
      "12",
      "…",
      "Next",
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(go).toHaveBeenCalledWith(
      expect.objectContaining({ searchOffset: 500 }),
    );
    cleanup();

    // Last page: the window ends here and the next step is off.
    results(300, 0);
    expect(await labels()).toEqual([
      "Previous",
      "…",
      "3",
      "4",
      "5",
      "6",
      "7",
      "Next",
    ]);
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
  });
  it("renders hostile filenames as text and reports incomplete coverage", async () => {
    const name = "<img src=x onerror=alert(1)>.pdf";
    setup(
      vi.fn(async () => ({
        ...page,
        incomplete: true,
        entries: [{ ...entry, name, path: `reports/${name}` }],
      })),
      {
        shareId: "documents",
        path: "",
        searchQuery: "type:pdf",
        searchScope: "share",
      },
    );
    expect(await screen.findByText(name)).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent("incomplete");
    expect(document.querySelector(".search-results img")).toBeNull();
  });
  it("cancels obsolete requests and ignores their results", async () => {
    let resolve: (page: SearchPage) => void = () => undefined;
    const search = vi.fn(
      (_request: unknown, _signal?: AbortSignal) =>
        new Promise<SearchPage>((done) => {
          void _request;
          void _signal;
          resolve = done;
        }),
    );
    const { input } = setup(search);
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "old" } });
    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    fireEvent.input(input, { target: { value: "new" } });
    expect(search.mock.calls[0]?.[1]?.aborted).toBe(true);
    resolve(page);
    expect(screen.queryByRole("option", { name: /invoice.pdf/ })).toBeNull();
  });
  it("handles session expiry and invalid filters", async () => {
    const search = vi.fn(async (): Promise<SearchPage> => {
      throw new ApiError("unauthorized", "expired", { status: 401 });
    });
    const { input, expired } = setup(search);
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "invoice" } });
    await waitFor(() => expect(expired).toHaveBeenCalledOnce());
  });
  it("retries a busy index without requiring the query to be retyped", async () => {
    const search = vi
      .fn<ApiClient["search"]>()
      .mockRejectedValueOnce(
        new ApiError("rate-limited", "busy", { status: 429 }),
      )
      .mockResolvedValue(page);
    const { input } = setup(search);
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: "invoice" } });
    expect(
      await screen.findByRole(
        "option",
        { name: /invoice.pdf/ },
        { timeout: 3500 },
      ),
    ).toBeVisible();
    expect(search).toHaveBeenCalledTimes(2);
  });
  it("round trips a search and cross-share preview URL", () => {
    expect(
      routeFromUrl(
        new URL(
          "https://example.com/documents/reports?search=invoice+type%3Apdf&scope=all&preview=photos%2Finvoice.pdf&previewShare=images&offset=50",
        ),
      ),
    ).toEqual({
      shareId: "documents",
      path: "reports",
      searchQuery: "invoice type:pdf",
      searchScope: "all",
      searchOffset: 50,
      previewPath: "photos/invoice.pdf",
      previewShareId: "images",
    });
  });
});

import { useEffect, useId, useRef, useState } from "preact/hooks";
import {
  ChevronLeft,
  ChevronRight,
  Search,
  SlidersHorizontal,
  X,
  FolderOpen,
} from "lucide-preact";
import {
  ApiError,
  type ApiClient,
  type SearchEntry,
  type SearchPage,
  type SearchRequest,
  type Share,
} from "./api";
import {
  type BrowserNavigation,
  type BrowserRoute,
  directoryUrl,
  parentPath,
} from "./navigation";
import { EntryIcon } from "./file-icons";

const types = [
  "pdf",
  "image",
  "video",
  "audio",
  "document",
  "code",
  "folder",
  "file",
  "other",
];
const typeLabels: Record<string, string> = {
  pdf: "PDF",
  image: "Images",
  video: "Video",
  audio: "Audio",
  document: "Documents",
  code: "Code",
  folder: "Folders",
  file: "All files",
  other: "Other files",
};
const unitLabels: Record<string, string> = {
  b: "B",
  kb: "KB",
  mb: "MB",
  gb: "GB",
  kib: "KiB",
  mib: "MiB",
  gib: "GiB",
};
type Scope = "share" | "folder" | "all";
/** The scope menu can also name another share, which searches its whole tree. */
type ScopeChoice = Scope | `share:${string}`;
const otherShare = (scope: ScopeChoice) =>
  scope.startsWith("share:") ? scope.slice("share:".length) : undefined;
const routeScope = (route: BrowserRoute): ScopeChoice =>
  route.searchShareId
    ? `share:${route.searchShareId}`
    : (route.searchScope ?? "share");
const shortcutLabel =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad/.test(navigator.userAgent)
    ? "⌘K"
    : "Ctrl K";
const PAGE_SIZE = 50;
/**
 * The first and last pages around a window of `size` pages centred on the
 * current one, with a gap wherever pages are skipped:
 * 1 … 5 6 7 8 9 … 25.
 */
function pageItems(
  current: number,
  last: number,
  size: number,
): (number | "gap")[] {
  const half = Math.floor(size / 2);
  const start = Math.max(1, Math.min(current - half, last - size + 1));
  const end = Math.min(last, start + size - 1);
  const pages: (number | "gap")[] = [];
  if (start > 1) pages.push(1);
  if (start > 2) pages.push("gap");
  for (let page = start; page <= end; page++) pages.push(page);
  if (end < last - 1) pages.push("gap");
  if (end < last) pages.push(last);
  return pages;
}
const NARROW = "(max-width: 600px)";
/** Whether the viewport is phone-sized; the page bar keeps one row there. */
function useNarrow() {
  const media = () =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia(NARROW)
      : undefined;
  const [narrow, setNarrow] = useState(() => media()?.matches ?? false);
  useEffect(() => {
    const query = media();
    if (!query) return;
    const update = () => setNarrow(query.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return narrow;
}
const tokens = (query: string): string[] => query.match(/"[^"]*"|\S+/g) ?? [];
const filterToken = (token: string) =>
  /^(type|ext|size|modified):/i.test(token);

function requestFor(
  query: string,
  scope: ScopeChoice,
  route: BrowserRoute,
  hidden: boolean,
  limit: number,
): SearchRequest {
  return {
    q: query,
    ...(scope === "all" ? {} : { share: otherShare(scope) ?? route.shareId! }),
    path: scope === "folder" ? route.path : "",
    showHidden: hidden,
    limit,
  };
}

function useSearch(
  api: ApiClient,
  request: SearchRequest | undefined,
  onExpired: () => void,
  delay: number,
) {
  const [page, setPage] = useState<SearchPage>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  const expiry = useRef(onExpired);
  expiry.current = onExpired;
  const key = request ? JSON.stringify(request) : "";
  useEffect(() => {
    setPage(undefined);
    setError(undefined);
    if (!key) {
      setLoading(false);
      return;
    }
    setLoading(true);
    const controller = new AbortController();
    let refresh: ReturnType<typeof setTimeout> | undefined;
    const run = () => {
      api.search(JSON.parse(key) as SearchRequest, controller.signal).then(
        (result) => {
          if (controller.signal.aborted) return;
          setPage(result);
          setLoading(false);
          // Only an index still being built changes the answer on its own.
          if (result.indexing) refresh = setTimeout(run, 2000);
        },
        (cause: unknown) => {
          if (controller.signal.aborted) return;
          if (cause instanceof ApiError && cause.status === 429) {
            refresh = setTimeout(run, 2000);
            return;
          }
          setLoading(false);
          if (cause instanceof ApiError && cause.status === 401) {
            expiry.current();
            return;
          }
          setError(
            cause instanceof ApiError && cause.status === 400
              ? "Check your filters: use type:image, ext:pdf, size:>10kb, or modified:>=2026-01-01. Close any quoted phrase."
              : cause instanceof ApiError && cause.status === 404
                ? "Search is unavailable for this share."
                : "Search could not finish. Try again.",
          );
        },
      );
    };
    const timer = setTimeout(run, delay);
    return () => {
      controller.abort();
      clearTimeout(timer);
      clearTimeout(refresh);
    };
  }, [api, key, delay, revision]);
  return {
    page,
    error,
    loading,
    retry: () => setRevision((value) => value + 1),
  };
}

interface Props {
  renderLayout?: (
    controls: preact.ComponentChildren,
    results: preact.ComponentChildren,
  ) => preact.ComponentChildren;
  api: ApiClient;
  route: BrowserRoute;
  navigation: BrowserNavigation;
  shares: Share[];
  hidden: boolean;
  onSessionExpired: () => void;
}

export function SearchPanel({
  renderLayout,
  api,
  route,
  navigation,
  shares,
  hidden,
  onSessionExpired,
}: Props) {
  const [draft, setDraft] = useState(route.searchQuery ?? "");
  const [scope, setScope] = useState<ScopeChoice>(routeScope(route));
  const [focused, setFocused] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [active, setActive] = useState(-1);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const filterButton = useRef<HTMLButtonElement>(null);
  const controlsRef = useRef<HTMLDivElement>(null);
  const listId = useId();
  // The idle bar stays narrow until something in it is focused. A press
  // elsewhere collapses it and ends the search's focus: blur alone cannot
  // drive this, because Safari does not focus a clicked button, and touch
  // Safari keeps focus when the page background is tapped.
  const [engaged, setEngaged] = useState(false);
  useEffect(() => {
    const outside = (event: PointerEvent) => {
      const controls = controlsRef.current;
      if (!(event.target instanceof Node) || controls?.contains(event.target))
        return;
      setEngaged(false);
      const focused = document.activeElement;
      if (focused instanceof HTMLElement && controls?.contains(focused))
        focused.blur();
    };
    document.addEventListener("pointerdown", outside);
    return () => document.removeEventListener("pointerdown", outside);
  }, []);
  useEffect(() => {
    setDraft(route.searchQuery ?? "");
    setScope(routeScope(route));
    setDismissed(true);
  }, [
    route.searchQuery,
    route.searchScope,
    route.searchShareId,
    route.shareId,
    route.path,
  ]);
  useEffect(() => {
    const focus = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener("keydown", focus);
    return () => window.removeEventListener("keydown", focus);
  }, []);
  const tail = /\s$/.test(draft) ? "" : (tokens(draft).at(-1) ?? "");
  const typePrefix = /^type:([a-z]*)$/i.exec(tail);
  const special = typePrefix !== null || /^size:$/i.test(tail);
  const typeOptions = typePrefix
    ? types.filter((type) => type.startsWith(typePrefix[1]!.toLowerCase()))
    : [];
  const suggestion = useSearch(
    api,
    focused && !dismissed && draft.trim() && !special
      ? requestFor(draft, scope, route, hidden, 8)
      : undefined,
    onSessionExpired,
    250,
  );
  const full = route.searchQuery !== undefined;
  const results = useSearch(
    api,
    full
      ? {
          ...requestFor(
            route.searchQuery!,
            routeScope(route),
            route,
            hidden,
            PAGE_SIZE,
          ),
          offset: route.searchOffset ?? 0,
          count: true,
        }
      : undefined,
    onSessionExpired,
    0,
  );
  const entries = (suggestion.page?.entries ?? []).filter((entry) =>
    shares.some((share) => share.id === entry.shareId),
  );
  const count = special
    ? typePrefix
      ? typeOptions.length
      : 1
    : entries.length;
  const popup = focused && !dismissed && !!draft.trim();
  const change = (value: string) => {
    setDraft(value);
    setActive(-1);
    setDismissed(false);
  };
  // Another share is searched from the share where the search started, which
  // stays the route's share: "(current)" and closing search refer to it.
  const scopeRoute = (choice: ScopeChoice) => {
    const shareId = otherShare(choice);
    return shareId === undefined
      ? { searchScope: choice as Scope, searchShareId: undefined }
      : { searchScope: "share" as const, searchShareId: shareId };
  };
  const submit = (q = draft, selectedScope = scope) => {
    setDismissed(true);
    navigation.go({
      ...route,
      ...scopeRoute(selectedScope),
      searchQuery: q,
      searchOffset: undefined,
      previewPath: undefined,
      previewShareId: undefined,
      unresolved: false,
    });
  };
  const preview = (entry: SearchEntry, fromResults = false) => {
    setDismissed(true);
    if (entry.kind === "directory") {
      navigation.go({ shareId: entry.shareId, path: entry.path });
    } else {
      navigation.go({
        ...route,
        ...(fromResults
          ? { searchScope: route.searchScope }
          : scopeRoute(scope)),
        searchQuery: fromResults ? route.searchQuery : draft,
        previewPath: entry.path,
        previewShareId: entry.shareId,
        unresolved: false,
      });
    }
  };
  const choose = (index: number) => {
    if (typePrefix) {
      const type = typeOptions[index];
      if (type) {
        change(`${draft.slice(0, draft.length - tail.length)}type:${type} `);
        input.current?.focus();
      }
    } else if (special) {
      setFiltersOpen(true);
      setDismissed(true);
    } else if (entries[index]) preview(entries[index]!);
  };
  const clear = () => {
    change("");
    if (full) navigation.go({ shareId: route.shareId, path: route.path });
    input.current?.focus();
  };
  const expanded = engaged || filtersOpen || full || draft !== "";
  const shareName =
    shares.find((share) => share.id === route.shareId)?.name ?? "this share";
  const folderName = route.path.split("/").at(-1) || shareName;
  const filterCount = tokens(draft).filter(filterToken).length;
  const controls = (
    <div
      ref={controlsRef}
      class={`search-controls${expanded ? " is-expanded" : ""}`}
      onFocusIn={() => setEngaged(true)}
      onFocusOut={(event) => {
        // Tabbing out collapses; a null target is handled by the pointer listener.
        const next = event.relatedTarget;
        if (next instanceof Node && !event.currentTarget.contains(next))
          setEngaged(false);
      }}
    >
      <form
        class="search-row"
        role="search"
        onSubmit={(event) => {
          event.preventDefault();
          if (popup && active >= 0) choose(active);
          else submit();
        }}
      >
        <div
          class="search-input-wrap"
          onPointerDown={(event) => {
            // Only focus widens the idle bar. Widening on press would move
            // the input from under a touch before the tap focuses it, so a
            // press anywhere on the idle bar focuses the input directly.
            if (!expanded && event.target !== input.current) {
              event.preventDefault();
              input.current?.focus();
            }
          }}
        >
          <button
            type="submit"
            class="icon-button search-submit"
            aria-label="Search"
            onClick={(event) => {
              // With nothing typed, the icon only focuses the field.
              if (!draft.trim() && !full) {
                event.preventDefault();
                input.current?.focus();
              }
            }}
          >
            <Search size={17} aria-hidden="true" />
          </button>
          <input
            ref={input}
            type="text"
            role="combobox"
            aria-label="Search files"
            placeholder="Search files…"
            aria-keyshortcuts="Control+K Meta+K"
            value={draft}
            maxLength={1024}
            aria-autocomplete="list"
            aria-expanded={popup}
            aria-controls={popup ? listId : undefined}
            aria-activedescendant={
              popup && active >= 0 && active < count
                ? `${listId}-${active}`
                : undefined
            }
            onInput={(event) => change(event.currentTarget.value)}
            onFocus={() => {
              setFocused(true);
              setDismissed(false);
              setFiltersOpen(false);
            }}
            onBlur={() => setFocused(false)}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.preventDefault();
                event.stopPropagation();
                setDismissed(true);
                setActive(-1);
              }
              if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                setDismissed(false);
                if (count)
                  setActive((value) =>
                    event.key === "ArrowDown"
                      ? (value + 1) % count
                      : value <= 0
                        ? count - 1
                        : value - 1,
                  );
              }
            }}
          />
          {draft && (
            <button
              type="button"
              class="icon-button"
              aria-label="Clear search"
              onClick={clear}
            >
              <X size={16} aria-hidden="true" />
            </button>
          )}
          {!expanded && (
            <kbd class="search-shortcut" aria-hidden="true">
              {shortcutLabel}
            </kbd>
          )}
          {popup && (
            <div class="search-suggestions">
              <div id={listId} role="listbox" aria-label="Search suggestions">
                {special ? (
                  typePrefix ? (
                    typeOptions.map((type, index) => (
                      <button
                        key={type}
                        type="button"
                        role="option"
                        id={`${listId}-${index}`}
                        aria-selected={active === index}
                        onMouseDown={(event) => event.preventDefault()}
                        onClick={() => choose(index)}
                      >
                        {typeLabels[type]}
                      </button>
                    ))
                  ) : (
                    <button
                      type="button"
                      role="option"
                      id={`${listId}-0`}
                      aria-selected={active === 0}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => choose(0)}
                    >
                      Choose a size filter…
                    </button>
                  )
                ) : (
                  entries.map((entry, index) => (
                    <button
                      type="button"
                      role="option"
                      key={`${entry.shareId}/${entry.path}`}
                      id={`${listId}-${index}`}
                      aria-selected={active === index}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => preview(entry)}
                    >
                      <EntryIcon entry={entry} size={18} aria-hidden="true" />
                      <span>
                        <strong>
                          <Highlighted name={entry.name} query={draft} />
                        </strong>
                        <small>
                          {resultLocation(entry, shares, scope === "all")}
                        </small>
                      </span>
                    </button>
                  ))
                )}
              </div>
              {suggestion.loading && <p role="status">Searching…</p>}
              {suggestion.error && <p role="alert">{suggestion.error}</p>}
              {suggestion.page && !entries.length && (
                <p>
                  {suggestion.page.incomplete || suggestion.page.indexing
                    ? "Indexing—more matches may appear."
                    : "No matching files."}
                </p>
              )}
              {suggestion.page?.indexing && !!entries.length && (
                <p role="status">Indexing—results may be incomplete.</p>
              )}
              {!special && (
                <button
                  type="button"
                  class="search-all-results"
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => submit()}
                >
                  Show all results ↵
                </button>
              )}
            </div>
          )}
          <select
            aria-label="Search scope"
            value={scope}
            onChange={(event) => {
              const next = event.currentTarget.value as ScopeChoice;
              setScope(next);
              setActive(-1);
              setDismissed(false);
              if (full) submit(draft, next);
            }}
          >
            {(route.path || scope === "folder") && (
              <option value="folder">Current folder ({folderName})</option>
            )}
            <optgroup label="Shares">
              <option value="share">{shareName} (current)</option>
              {shares
                .filter(
                  (share) =>
                    share.id !== route.shareId && share.searchEnabled !== false,
                )
                .map((share) => (
                  <option key={share.id} value={`share:${share.id}`}>
                    {share.name}
                  </option>
                ))}
            </optgroup>
            <option value="all">All shares</option>
          </select>
          <button
            ref={filterButton}
            type="button"
            class="icon-button search-filter-toggle"
            aria-label={
              filterCount
                ? `Search filters (${String(filterCount)} applied)`
                : "Search filters"
            }
            title="Search filters"
            aria-haspopup="dialog"
            aria-expanded={filtersOpen}
            aria-controls={filtersOpen ? `${listId}-filters` : undefined}
            onClick={() => {
              setFiltersOpen((open) => !open);
              setDismissed(true);
            }}
          >
            <SlidersHorizontal size={17} aria-hidden="true" />
            {filterCount > 0 && (
              <span class="search-filter-count" aria-hidden="true">
                {filterCount}
              </span>
            )}
          </button>
        </div>
      </form>
      {filtersOpen && (
        <FilterPicker
          id={`${listId}-filters`}
          query={draft}
          onClose={() => {
            setFiltersOpen(false);
            filterButton.current?.focus();
          }}
          onApply={(q) => {
            change(q);
            setFiltersOpen(false);
            submit(q);
          }}
        />
      )}
    </div>
  );
  const resultEntries = (results.page?.entries ?? []).filter((entry) =>
    shares.some((share) => share.id === entry.shareId),
  );
  const offset = route.searchOffset ?? 0;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;
  const narrow = useNarrow();
  // Without a count, the next page is the last one known.
  const lastPage = Math.max(
    currentPage,
    results.page?.pageCount ??
      currentPage + (results.page?.nextOffset === undefined ? 0 : 1),
  );
  // The page header or a share heading names the share, so rows show paths.
  const resultRow = (entry: SearchEntry) => (
    <li key={`${entry.shareId}/${entry.path}`}>
      <EntryIcon entry={entry} size={20} aria-hidden="true" />
      <div class="search-result-name">
        <a
          href={directoryUrl(entry.shareId, entry.path)}
          onClick={(event) => {
            if (plainClick(event)) {
              event.preventDefault();
              preview(entry, true);
            }
          }}
        >
          <Highlighted name={entry.name} query={route.searchQuery ?? ""} />
        </a>
        <a
          class="search-result-location"
          href={directoryUrl(entry.shareId, parentPath(entry.path))}
          title="Open containing folder"
          onClick={(event) => {
            if (plainClick(event)) {
              event.preventDefault();
              navigation.go({
                shareId: entry.shareId,
                path: parentPath(entry.path),
              });
            }
          }}
        >
          <FolderOpen size={13} aria-hidden="true" />
          {resultLocation(entry, shares)}
        </a>
      </div>
      <span class="search-result-size">
        {entry.size === undefined ? "" : formatSize(entry.size)}
      </span>
      <span class="search-result-date">
        {entry.modified ? formatDate(entry.modified) : ""}
      </span>
    </li>
  );
  const resultContent = full && (
    <section class="search-results" aria-label="Search results">
      <div class="search-results-heading">
        <h1 id="search-results-title" tabIndex={-1}>
          {route.searchQuery?.trim()
            ? `Results for “${route.searchQuery.trim()}”`
            : "All files"}
        </h1>
        <button
          type="button"
          class="icon-button"
          aria-label="Close search"
          title="Close search"
          onClick={clear}
        >
          <X size={18} aria-hidden="true" />
        </button>
      </div>
      {results.loading && <p role="status">Searching…</p>}
      {results.error && (
        <div role="alert">
          <p>{results.error}</p>
          <button
            type="button"
            class="button button-secondary"
            onClick={results.retry}
          >
            Retry search
          </button>
        </div>
      )}
      {results.page && (
        <>
          {(results.page.indexing || results.page.incomplete) && (
            <p class="search-status" role="status">
              {results.page.indexing
                ? "Indexing—results may be incomplete."
                : "Some folders could not be fully indexed. Results may be incomplete."}
            </p>
          )}
          {!results.page.entries.length && (
            <p class="search-status">
              {results.page.incomplete || results.page.indexing
                ? "No matches in the available index yet."
                : "No matching files."}
            </p>
          )}
          {route.searchScope === "all" ? (
            // All-shares results are grouped by share, like Trash.
            <div class="search-result-groups">
              {shares
                .map((share) => ({
                  share,
                  entries: resultEntries.filter(
                    (entry) => entry.shareId === share.id,
                  ),
                }))
                .filter((group) => group.entries.length)
                .map((group, index) => (
                  <section
                    key={group.share.id}
                    class="search-result-group"
                    aria-labelledby={`${listId}-group-${index}`}
                  >
                    <h2
                      class="search-group-title"
                      id={`${listId}-group-${index}`}
                    >
                      {group.share.name}{" "}
                      <span class="search-group-count">
                        <span aria-hidden="true">—</span> {group.entries.length}{" "}
                        {group.entries.length === 1 ? "match" : "matches"}
                      </span>
                    </h2>
                    <ul class="search-result-list">
                      {group.entries.map((entry) => resultRow(entry))}
                    </ul>
                  </section>
                ))}
            </div>
          ) : (
            <ul class="search-result-list">
              {resultEntries.map((entry) => resultRow(entry))}
            </ul>
          )}
          {(offset > 0 || results.page.nextOffset !== undefined) && (
            <nav class="search-pagination" aria-label="Result pages">
              <button
                type="button"
                class="button button-secondary search-page-step"
                aria-label="Previous page"
                disabled={offset === 0}
                onClick={() =>
                  navigation.go({
                    ...route,
                    searchOffset: Math.max(0, offset - PAGE_SIZE),
                  })
                }
              >
                <ChevronLeft size={18} aria-hidden="true" />
                <span class="search-page-step-label">Previous</span>
              </button>
              {pageItems(currentPage, lastPage, narrow ? 3 : 5).map(
                (item, index) =>
                  item === "gap" ? (
                    <span
                      key={`gap-${index}`}
                      class="search-page-gap"
                      aria-hidden="true"
                    >
                      …
                    </span>
                  ) : (
                    <button
                      key={item}
                      type="button"
                      class={`button button-secondary search-page${
                        item === currentPage ? " is-current" : ""
                      }`}
                      aria-label={`Page ${item}`}
                      aria-current={item === currentPage ? "page" : undefined}
                      onClick={() =>
                        item !== currentPage &&
                        navigation.go({
                          ...route,
                          searchOffset: Math.max(
                            0,
                            offset + (item - currentPage) * PAGE_SIZE,
                          ),
                        })
                      }
                    >
                      {item}
                    </button>
                  ),
              )}
              <button
                type="button"
                class="button button-secondary search-page-step"
                aria-label="Next page"
                disabled={results.page.nextOffset === undefined}
                onClick={() =>
                  navigation.go({
                    ...route,
                    searchOffset: results.page!.nextOffset,
                  })
                }
              >
                <span class="search-page-step-label">Next</span>
                <ChevronRight size={18} aria-hidden="true" />
              </button>
            </nav>
          )}
          <div class="search-pagination">
            {!results.page.entries.length && route.searchScope !== "all" && (
              <button
                type="button"
                class="button button-secondary"
                onClick={() => {
                  setScope("all");
                  submit(draft, "all");
                }}
              >
                Search all shares
              </button>
            )}
          </div>
        </>
      )}
    </section>
  );
  return renderLayout ? (
    renderLayout(controls, resultContent)
  ) : (
    <>
      {controls}
      {resultContent}
    </>
  );
}

/**
 * The containing folder as a path. Where results mix shares, the share name
 * comes first, set apart by a colon; a share's root shows its name.
 */
function resultLocation(entry: SearchEntry, shares: Share[], mixed = false) {
  const shareName =
    shares.find((share) => share.id === entry.shareId)?.name ?? entry.shareId;
  const folder = parentPath(entry.path);
  if (!folder) return shareName;
  return mixed ? `${shareName}: ${folder}` : folder;
}

// Matches the folder listing's units.
function formatSize(size: number) {
  if (size < 1_000) return `${size} B`;
  if (size < 1_000_000) return `${(size / 1_000).toFixed(1)} kB`;
  if (size < 1_000_000_000) return `${(size / 1_000_000).toFixed(1)} MB`;
  return `${(size / 1_000_000_000).toFixed(1)} GB`;
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? ""
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

/** A click without modifier keys, which the app handles in place. */
function plainClick(event: MouseEvent) {
  return !(event.ctrlKey || event.metaKey || event.shiftKey || event.altKey);
}

/**
 * Marks the parts of a name that match the query's words. Names whose
 * lowercase form changes length are shown unmarked rather than misaligned.
 */
function Highlighted({ name, query }: { name: string; query: string }) {
  const lower = name.toLowerCase();
  const words = tokens(query)
    .filter((token) => !filterToken(token))
    .map((token) => token.replace(/^"|"$/g, "").toLowerCase())
    .filter(Boolean);
  if (!words.length || lower.length !== name.length) return <>{name}</>;
  const marked = new Array<boolean>(name.length).fill(false);
  for (const word of words) {
    for (
      let at = lower.indexOf(word);
      at !== -1;
      at = lower.indexOf(word, at + word.length)
    )
      marked.fill(true, at, at + word.length);
  }
  const parts: preact.ComponentChildren[] = [];
  let start = 0;
  for (let index = 1; index <= name.length; index++) {
    if (index === name.length || marked[index] !== marked[start]) {
      const text = name.slice(start, index);
      parts.push(marked[start] ? <mark key={start}>{text}</mark> : text);
      start = index;
    }
  }
  return <>{parts}</>;
}

function FilterPicker({
  id,
  query,
  onClose,
  onApply,
}: {
  id: string;
  query: string;
  onClose: () => void;
  onApply: (query: string) => void;
}) {
  const panel = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    panel.current?.querySelector<HTMLElement>("input, select")?.focus();
    const outside = (event: PointerEvent) => {
      if (
        event.target instanceof Node &&
        !panel.current?.closest(".search-controls")?.contains(event.target)
      ) {
        close.current();
      }
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        close.current();
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, []);
  const parsed = tokens(query);
  const [edited, setEdited] = useState<string[]>([]);
  const edit = (family: string) =>
    setEdited((old) => (old.includes(family) ? old : [...old, family]));
  const [selected, setSelected] = useState(
    parsed
      .filter((t) => /^type:/i.test(t))
      .map((t) => t.slice(5).toLowerCase()),
  );
  const [ext, setExt] = useState(
    parsed.find((t) => /^ext:/i.test(t))?.slice(4) ?? "",
  );
  const sizes = parsed
    .filter((t) => /^size:/i.test(t))
    .map((t) => /^size:(>=|<=|>|<|=)?(\d+)([a-z]*)$/i.exec(t));
  const [operator, setOperator] = useState(
    sizes.length > 1 ? "between" : (sizes[0]?.[1] ?? ">"),
  );
  const [size, setSize] = useState(sizes[0]?.[2] ?? "");
  const [upper, setUpper] = useState(sizes[1]?.[2] ?? "");
  const [unit, setUnit] = useState(sizes[0]?.[3]?.toLowerCase() || "kb");
  const dates = parsed.filter((t) => /^modified:/i.test(t));
  const [after, setAfter] = useState(
    dates
      .find((t) => /^modified:>=?/i.test(t))
      ?.replace(/^modified:>=?/i, "") ?? "",
  );
  const [before, setBefore] = useState(
    dates
      .find((t) => /^modified:<=?/i.test(t))
      ?.replace(/^modified:<=?/i, "") ?? "",
  );
  return (
    <div
      ref={panel}
      id={id}
      class="search-filter-popover"
      role="dialog"
      aria-labelledby={`${id}-title`}
    >
      <div class="search-filter-heading">
        <h2 id={`${id}-title`}>Search filters</h2>
        <button
          type="button"
          class="icon-button"
          aria-label="Close search filters"
          onClick={onClose}
        >
          <X size={16} aria-hidden="true" />
        </button>
      </div>
      <form
        class="search-filter-form"
        onSubmit={(event) => {
          event.preventDefault();
          const next = parsed.filter(
            (t) =>
              !edited.some((family) =>
                t.toLowerCase().startsWith(`${family}:`),
              ),
          );
          if (edited.includes("type"))
            selected.forEach((type) => next.push(`type:${type}`));
          if (edited.includes("ext") && ext.trim())
            next.push(`ext:${ext.trim().replace(/^\./, "").toLowerCase()}`);
          if (edited.includes("size") && size) {
            next.push(
              `size:${operator === "between" ? ">=" : operator}${size}${unit}`,
            );
            if (operator === "between" && upper)
              next.push(`size:<=${upper}${unit}`);
          }
          if (edited.includes("modified") && after)
            next.push(`modified:>=${after}`);
          if (edited.includes("modified") && before)
            next.push(`modified:<${before}`);
          onApply(next.join(" "));
        }}
      >
        <div
          class="search-filter-row"
          role="group"
          aria-labelledby={`${id}-type`}
        >
          <span id={`${id}-type`} class="search-filter-label">
            Type
          </span>
          <div class="search-type-options">
            {types.map((type) => (
              <label key={type} class="search-type-option">
                <input
                  type="checkbox"
                  checked={selected.includes(type)}
                  onChange={(event) => {
                    edit("type");
                    setSelected(
                      event.currentTarget.checked
                        ? [...selected, type]
                        : selected.filter((t) => t !== type),
                    );
                  }}
                />
                {typeLabels[type]}
              </label>
            ))}
          </div>
        </div>
        <label class="search-filter-row">
          <span class="search-filter-label">Extension</span>
          <input
            type="text"
            placeholder="pdf"
            value={ext}
            maxLength={32}
            pattern="\.?[A-Za-z0-9]+"
            onInput={(event) => {
              edit("ext");
              setExt(event.currentTarget.value);
            }}
          />
        </label>
        <div
          class="search-filter-row"
          role="group"
          aria-labelledby={`${id}-size`}
        >
          <span id={`${id}-size`} class="search-filter-label">
            Size
          </span>
          <div class="search-filter-fields">
            <select
              aria-label="Size comparison"
              value={operator}
              onChange={(event) => {
                edit("size");
                setOperator(event.currentTarget.value);
              }}
            >
              <option value=">">Over</option>
              <option value="<">Under</option>
              <option value=">=">At least</option>
              <option value="<=">At most</option>
              <option value="=">Exactly</option>
              <option value="between">Between</option>
            </select>
            <input
              aria-label="File size"
              type="number"
              inputMode="numeric"
              min="0"
              step="1"
              value={size}
              onInput={(event) => {
                edit("size");
                setSize(event.currentTarget.value);
              }}
            />
            {operator === "between" && (
              <>
                <span aria-hidden="true">–</span>
                <input
                  aria-label="Maximum file size"
                  type="number"
                  inputMode="numeric"
                  min={size || "0"}
                  step="1"
                  value={upper}
                  required={!!size}
                  onInput={(event) => {
                    edit("size");
                    setUpper(event.currentTarget.value);
                  }}
                />
              </>
            )}
            <select
              aria-label="Size unit"
              value={unit}
              onChange={(event) => {
                edit("size");
                setUnit(event.currentTarget.value);
              }}
            >
              {Object.keys(unitLabels).map((unit) => (
                <option key={unit} value={unit}>
                  {unitLabels[unit]}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div
          class="search-filter-row"
          role="group"
          aria-labelledby={`${id}-modified`}
        >
          <span id={`${id}-modified`} class="search-filter-label">
            Modified <small>UTC</small>
          </span>
          <div class="search-filter-fields">
            <input
              aria-label="On or after"
              type="date"
              value={after}
              onInput={(event) => {
                edit("modified");
                setAfter(event.currentTarget.value);
              }}
            />
            <span aria-hidden="true">–</span>
            <input
              aria-label="Before"
              type="date"
              value={before}
              onInput={(event) => {
                edit("modified");
                setBefore(event.currentTarget.value);
              }}
            />
          </div>
        </div>
        <div class="search-filter-actions">
          <button
            type="button"
            class="button button-secondary"
            onClick={() =>
              onApply(parsed.filter((t) => !filterToken(t)).join(" "))
            }
          >
            Clear filters
          </button>
          <button type="submit" class="button button-primary">
            Apply filters
          </button>
        </div>
      </form>
    </div>
  );
}

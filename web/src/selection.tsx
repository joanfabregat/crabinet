import { useEffect, useRef, useState } from "preact/hooks";
import { FolderDown, Trash2, X } from "lucide-preact";

import {
  ApiError,
  archiveUrl,
  maxArchivePaths,
  type ApiClient,
  type DirectoryEntry,
} from "./api";
import { useToast } from "./toast";

/**
 * The selected entries of one listed folder, by name, and the anchor of the
 * next Shift-click range: the row toggled last.
 */
export interface SelectionState {
  readonly names: ReadonlySet<string>;
  readonly anchor?: string;
}

export const emptySelection: SelectionState = { names: new Set() };

/**
 * Toggles `name`. With `range`, every row between the anchor and `name`
 * (in listing order, both included) takes the state `name` toggles to, as in
 * common file managers; without an anchor in the listing it toggles `name`
 * alone. The toggled row becomes the next anchor.
 */
export function toggleSelection(
  state: SelectionState,
  order: readonly string[],
  name: string,
  range: boolean,
): SelectionState {
  const selecting = !state.names.has(name);
  const names = new Set(state.names);
  const to = order.indexOf(name);
  const from = state.anchor === undefined ? -1 : order.indexOf(state.anchor);
  const affected =
    range && from !== -1 && to !== -1
      ? order.slice(Math.min(from, to), Math.max(from, to) + 1)
      : [name];
  for (const each of affected) {
    if (selecting) names.add(each);
    else names.delete(each);
  }
  return { names, anchor: name };
}

/** Selects every listed entry, or clears the selection if all are selected. */
export function toggleAll(
  state: SelectionState,
  order: readonly string[],
): SelectionState {
  if (order.length > 0 && order.every((name) => state.names.has(name)))
    return emptySelection;
  return { names: new Set(order), anchor: state.anchor };
}

/**
 * Drops selected names that are no longer listed, for example after a
 * refresh. Returns `state` itself when nothing changed.
 */
export function pruneSelection(
  state: SelectionState,
  order: readonly string[],
): SelectionState {
  const listed = new Set(order);
  const kept = [...state.names].filter((name) => listed.has(name));
  const anchorListed = state.anchor === undefined || listed.has(state.anchor);
  if (kept.length === state.names.size && anchorListed) return state;
  return {
    names: new Set(kept),
    anchor: anchorListed ? state.anchor : undefined,
  };
}

/**
 * Selection for the listing at `location`. It starts empty for every new
 * location and drops entries that leave the listing.
 */
export function useEntrySelection(order: readonly string[], location: string) {
  const [state, setState] = useState<{
    location: string;
    selection: SelectionState;
  }>({ location, selection: emptySelection });
  const current =
    state.location === location ? state.selection : emptySelection;
  const pruned = pruneSelection(current, order);

  // Persist the pruning, so an entry that disappears and comes back later
  // is not selected again. `pruneSelection` returns the same object when
  // nothing changed, so this settles after one update.
  useEffect(() => {
    if (state.location !== location || pruned !== state.selection)
      setState({ location, selection: pruned });
  }, [location, pruned, state]);

  const update = (change: (selection: SelectionState) => SelectionState) =>
    setState({ location, selection: change(pruned) });

  return {
    selection: pruned,
    toggle: (name: string, range: boolean) =>
      update((selection) => toggleSelection(selection, order, name, range)),
    toggleAll: () => update((selection) => toggleAll(selection, order)),
    deselect: (names: readonly string[]) =>
      update((selection) => ({
        names: new Set(
          [...selection.names].filter((name) => !names.includes(name)),
        ),
        anchor: selection.anchor,
      })),
    clear: () => update(() => emptySelection),
  };
}

/**
 * Checks an archive with the server, then downloads it. The server walks
 * everything before it answers, so a refusal (too large, too deep, busy)
 * becomes an error toast here instead of replacing the page.
 */
export function useArchiveDownload(
  api: ApiClient,
  shareId: string,
  onSessionExpired: () => void,
) {
  const showToast = useToast();
  const [checking, setChecking] = useState(false);
  const busy = useRef(false);

  const download = async (
    paths: string | readonly string[],
    name: string | undefined,
  ) => {
    if (busy.current) return;
    const count = typeof paths === "string" ? 1 : paths.length;
    if (count > maxArchivePaths) {
      showToast(
        `Select at most ${maxArchivePaths.toLocaleString("en-US")} items to download as one ZIP.`,
        { tone: "error" },
      );
      return;
    }
    busy.current = true;
    setChecking(true);
    try {
      await api.checkArchive(shareId, paths);
      // The response is an attachment, so following it keeps this page.
      const link = document.createElement("a");
      link.href = archiveUrl(shareId, paths);
      link.click();
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else showToast(archiveErrorMessage(cause, name), { tone: "error" });
    } finally {
      busy.current = false;
      setChecking(false);
    }
  };

  return { checking, download };
}

/**
 * The toast for a refused archive of `name`, or of a selection of several
 * entries when `name` is undefined.
 */
export function archiveErrorMessage(
  cause: unknown,
  name: string | undefined,
): string {
  const error = cause instanceof ApiError ? cause : undefined;
  const subject = name ?? "The selection";
  if (error?.code === "too_large")
    return `${subject} is too large or has too many items to download as one ZIP.`;
  if (error?.code === "path_too_deep")
    return `${subject} has folders nested too deeply to download as a ZIP.`;
  if (error?.kind === "rate-limited")
    return "Too many downloads are in progress. Try again shortly.";
  if (error?.kind === "not-found")
    return name === undefined
      ? "Some selected items are no longer available."
      : `${name} is no longer available.`;
  return `Could not download ${name ?? "the selection"} as a ZIP.`;
}

/** Whether a click should keep the browser's own link behavior. */
export function isModifiedClick(event: MouseEvent): boolean {
  return (
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  );
}

export interface TrashedEntry {
  id: string;
  entry: DirectoryEntry;
  path: string;
}

export interface BulkTrashOutcome {
  moved: TrashedEntry[];
  failed: Array<{ entry: DirectoryEntry; path: string }>;
  /** The session ended part way; the remaining items were not attempted. */
  sessionExpired: boolean;
}

/**
 * Moves entries to Trash one at a time through the per-entry delete API,
 * so each keeps its own validator check, audit event, and server limits.
 * A failure does not stop the others; an expired session does.
 */
export async function moveEntriesToTrash(
  items: ReadonlyArray<{ entry: DirectoryEntry; path: string }>,
  moveOne: (entry: DirectoryEntry, path: string) => Promise<string>,
  onProgress?: (done: number) => void,
): Promise<BulkTrashOutcome> {
  const outcome: BulkTrashOutcome = {
    moved: [],
    failed: [],
    sessionExpired: false,
  };
  for (const [index, item] of items.entries()) {
    try {
      const id = await moveOne(item.entry, item.path);
      outcome.moved.push({ id, ...item });
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized") {
        outcome.sessionExpired = true;
        break;
      }
      outcome.failed.push(item);
    }
    onProgress?.(index + 1);
  }
  return outcome;
}

export function bulkTrashMessage(
  outcome: BulkTrashOutcome,
  total: number,
): string {
  const moved = outcome.moved.length;
  const items = (count: number) => `${count} ${count === 1 ? "item" : "items"}`;
  if (moved === total) return `Moved ${items(total)} to Trash.`;
  if (moved === 0) return `Could not move ${items(total)} to Trash.`;
  return `Moved ${moved} of ${items(total)} to Trash. ${total - moved} could not be moved.`;
}

/**
 * Shown directly above the file list while entries are selected: a
 * select-all checkbox, the count, and the bulk actions.
 */
export function SelectionBar({
  count,
  total,
  writable,
  busy,
  onToggleAll,
  onDownload,
  onDelete,
  onClear,
}: {
  count: number;
  total: number;
  writable: boolean;
  busy: boolean;
  onToggleAll: () => void;
  onDownload: () => void;
  onDelete: () => void;
  onClear: () => void;
}) {
  const allSelected = count === total;
  return (
    <div class="selection-bar" role="toolbar" aria-label="Selection actions">
      <input
        class="selection-checkbox"
        type="checkbox"
        aria-label="Select all"
        checked={allSelected}
        indeterminate={!allSelected}
        onChange={onToggleAll}
      />
      <span class="selection-count" role="status" aria-live="polite">
        {count} selected
      </span>
      <button
        class="button button-secondary toolbar-button"
        type="button"
        aria-busy={busy || undefined}
        disabled={busy}
        onClick={onDownload}
      >
        <FolderDown size={18} aria-hidden="true" />
        <span class="toolbar-label">Download as ZIP</span>
      </button>
      {writable && (
        <button
          class="button button-secondary toolbar-button selection-delete"
          type="button"
          disabled={busy}
          onClick={onDelete}
        >
          <Trash2 size={18} aria-hidden="true" />
          <span class="toolbar-label">Delete</span>
        </button>
      )}
      <button
        class="icon-button tooltip-action"
        type="button"
        aria-label="Clear selection"
        data-tooltip="Clear selection"
        onClick={onClear}
      >
        <X size={18} aria-hidden="true" />
      </button>
    </div>
  );
}

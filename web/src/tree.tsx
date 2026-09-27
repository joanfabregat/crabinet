import { ChevronDown, ChevronRight, FolderPlus, Trash2 } from "lucide-preact";
import { Fragment } from "preact";
import { useCallback, useEffect, useRef, useState } from "preact/hooks";

import {
  type ApiClient,
  type DirectoryEntry,
  type DirectoryPage,
  type Share,
} from "./api";
import { EntryIcon } from "./file-icons";
import { CopyPathButton } from "./copy-path-button";
import { directoryUrl, trashUrl, type BrowserNavigation } from "./navigation";
import { isValidPathComponent, isValidVirtualPath } from "./virtual-path";

const dragType = "application/x-crabinet-entry";
// Drag payloads can come from other tabs, windows, or pages that know the
// MIME type. Only entries dragged from this page instance carry this nonce.
const dragNonce = crypto.randomUUID();

interface DraggedEntry {
  shareId: string;
  path: string;
  entry: DirectoryEntry;
}

interface DragPayload extends DraggedEntry {
  nonce: string;
}

interface TreeState {
  page?: DirectoryPage;
  loading?: boolean;
  error?: boolean;
}

function key(shareId: string, path: string) {
  return `${shareId}\u0000${path}`;
}

function joinPath(parent: string, child: string) {
  return parent ? `${parent}/${child}` : child;
}

function directories(page?: DirectoryPage, showHidden = true) {
  return (
    page?.entries.filter(
      (entry) =>
        entry.kind === "directory" &&
        entry.name !== ".crabinet" &&
        (showHidden || !entry.name.startsWith(".")),
    ) ?? []
  );
}

function mergePage(current: DirectoryPage | undefined, next: DirectoryPage) {
  if (!current) return next;
  const seen = new Set(
    current.entries.map((entry) => `${entry.kind}:${entry.name}`),
  );
  return {
    ...next,
    entries: [
      ...current.entries,
      ...next.entries.filter(
        (entry) => !seen.has(`${entry.kind}:${entry.name}`),
      ),
    ],
  };
}

export function beginEntryDrag(
  event: DragEvent,
  shareId: string,
  path: string,
  entry: DirectoryEntry,
) {
  event.dataTransfer?.setData(
    dragType,
    JSON.stringify({
      shareId,
      path,
      entry: { name: entry.name, kind: entry.kind },
      nonce: dragNonce,
    } satisfies DragPayload),
  );
  if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
}

function readDraggedEntry(event: DragEvent): DraggedEntry | undefined {
  try {
    const raw = event.dataTransfer?.getData(dragType);
    if (!raw) return undefined;
    const value = JSON.parse(raw) as Partial<DragPayload>;
    if (
      value.nonce !== dragNonce ||
      typeof value.shareId !== "string" ||
      typeof value.path !== "string" ||
      !isValidVirtualPath(value.path) ||
      !value.entry ||
      !isValidPathComponent(value.entry.name) ||
      value.entry.name !== value.path.split("/").at(-1) ||
      (value.entry.kind !== "file" && value.entry.kind !== "directory")
    ) {
      return undefined;
    }
    return {
      shareId: value.shareId,
      path: value.path,
      entry: { name: value.entry.name, kind: value.entry.kind },
    };
  } catch {
    return undefined;
  }
}

interface ShareTreeProps {
  api: ApiClient;
  shares: Share[];
  revision: number;
  showHidden: boolean;
  activeShareId: string;
  activePath: string;
  activeView?: "trash";
  navigation: BrowserNavigation;
  onMove: (
    entry: DirectoryEntry,
    sourcePath: string,
    destinationDirectory: string,
  ) => void;
  onSessionExpired: () => void;
}

export function ShareTree({
  api,
  shares,
  revision,
  showHidden,
  activeShareId,
  activePath,
  activeView,
  navigation,
  onMove,
  onSessionExpired,
}: ShareTreeProps) {
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [state, setState] = useState<Record<string, TreeState>>({});
  const showHiddenRef = useRef(showHidden);
  showHiddenRef.current = showHidden;
  // One in-flight listing per node: a newer request aborts the older one so
  // a slow, stale response can never overwrite a fresher listing.
  const requests = useRef(new Map<string, AbortController>());

  useEffect(() => {
    const active = requests.current;
    return () => {
      active.forEach((controller) => controller.abort());
      active.clear();
    };
  }, []);

  const load = useCallback(
    async (shareId: string, path: string, cursor?: string) => {
      const nodeKey = key(shareId, path);
      requests.current.get(nodeKey)?.abort();
      const controller = new AbortController();
      requests.current.set(nodeKey, controller);
      const current = () =>
        !controller.signal.aborted &&
        requests.current.get(nodeKey) === controller &&
        showHiddenRef.current === showHidden;
      setState((previous) => ({
        ...previous,
        [nodeKey]: { ...previous[nodeKey], loading: true, error: false },
      }));
      try {
        const page = await api.directory(
          shareId,
          path,
          cursor,
          controller.signal,
          showHidden,
        );
        if (!current()) return;
        setState((previous) => ({
          ...previous,
          [nodeKey]: {
            page: mergePage(cursor ? previous[nodeKey]?.page : undefined, page),
          },
        }));
      } catch (error) {
        if (!current()) return;
        if (
          typeof error === "object" &&
          error !== null &&
          "kind" in error &&
          error.kind === "unauthorized"
        ) {
          onSessionExpired();
        } else {
          setState((previous) => ({
            ...previous,
            [nodeKey]: { ...previous[nodeKey], loading: false, error: true },
          }));
        }
      } finally {
        if (requests.current.get(nodeKey) === controller) {
          requests.current.delete(nodeKey);
        }
      }
    },
    [api, onSessionExpired, showHidden],
  );

  useEffect(() => {
    for (const nodeKey of expanded) {
      const separator = nodeKey.indexOf("\u0000");
      if (separator < 0) continue;
      const shareId = nodeKey.slice(0, separator);
      const path = nodeKey.slice(separator + 1);
      void load(shareId, path);
    }
  }, [expanded, load, revision]);

  const toggle = (shareId: string, path: string) => {
    const nodeKey = key(shareId, path);
    const opening = !expanded.has(nodeKey);
    setExpanded((current) => {
      const next = new Set(current);
      if (opening) next.add(nodeKey);
      else next.delete(nodeKey);
      return next;
    });
  };

  const expand = (shareId: string, path: string) => {
    const nodeKey = key(shareId, path);
    setExpanded((current) =>
      current.has(nodeKey) ? current : new Set(current).add(nodeKey),
    );
  };

  const drop = (
    event: DragEvent,
    destinationShare: Share,
    destinationDirectory: string,
  ) => {
    event.preventDefault();
    const dragged = readDraggedEntry(event);
    if (
      !dragged ||
      dragged.shareId !== destinationShare.id ||
      destinationShare.access !== "read-write"
    ) {
      return;
    }
    onMove(dragged.entry, dragged.path, destinationDirectory);
  };

  return (
    <aside class="share-tree" aria-label="Shared folders">
      <div class="tree-scroll">
        <ul class="tree-list tree-roots">
          {shares.map((share) => (
            <Fragment key={share.id}>
              <TreeNode
                apiState={state}
                showHidden={showHidden}
                expanded={expanded}
                level={0}
                name={share.name}
                path=""
                share={share}
                activeShareId={activeShareId}
                activePath={activePath}
                activeView={activeView}
                navigation={navigation}
                onToggle={toggle}
                onExpand={expand}
                onLoadMore={load}
                onDrop={drop}
              />
              <li class="tree-item">
                <div
                  class={`tree-row tree-trash-row${activeView === "trash" && activeShareId === share.id ? " is-selected" : ""}`}
                  style={{ "--tree-level": 1 }}
                >
                  <a
                    class="tree-link"
                    href={trashUrl(share.id)}
                    aria-current={
                      activeView === "trash" && activeShareId === share.id
                        ? "page"
                        : undefined
                    }
                    onClick={(event) => {
                      event.preventDefault();
                      navigation.go({
                        shareId: share.id,
                        path: "",
                        view: "trash",
                      });
                    }}
                  >
                    <Trash2 size={17} aria-hidden="true" />
                    <span>Trash</span>
                  </a>
                </div>
              </li>
            </Fragment>
          ))}
        </ul>
      </div>
    </aside>
  );
}

interface TreeNodeProps {
  apiState: Record<string, TreeState>;
  showHidden: boolean;
  expanded: Set<string>;
  level: number;
  name: string;
  path: string;
  share: Share;
  activeShareId: string;
  activePath: string;
  activeView?: "trash";
  navigation: BrowserNavigation;
  onToggle: (shareId: string, path: string) => void;
  onExpand: (shareId: string, path: string) => void;
  onLoadMore: (shareId: string, path: string, cursor?: string) => Promise<void>;
  onDrop: (event: DragEvent, share: Share, path: string) => void;
}

function TreeNode(props: TreeNodeProps) {
  const {
    apiState,
    showHidden,
    expanded,
    level,
    name,
    path,
    share,
    activeShareId,
    activePath,
    activeView,
    navigation,
    onToggle,
    onExpand,
    onLoadMore,
    onDrop,
  } = props;
  const nodeKey = key(share.id, path);
  const open = expanded.has(nodeKey);
  const nodeState = apiState[nodeKey];
  const selected =
    activeView !== "trash" && activeShareId === share.id && activePath === path;
  const childDirectories = directories(nodeState?.page, showHidden);

  return (
    <li class="tree-item">
      <div
        class={`tree-row${selected ? " is-selected" : ""}`}
        style={{ "--tree-level": level }}
        onDragOver={(event) => {
          if (share.access !== "read-write") return;
          event.preventDefault();
          if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
        }}
        onDrop={(event) => onDrop(event, share, path)}
      >
        <button
          class="tree-toggle"
          type="button"
          aria-label={`${open ? "Collapse" : "Expand"} ${name}`}
          aria-expanded={open}
          onClick={() => onToggle(share.id, path)}
        >
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>
        <a
          class="tree-link"
          href={directoryUrl(share.id, path)}
          aria-current={selected ? "page" : undefined}
          onClick={(event) => {
            event.preventDefault();
            onExpand(share.id, path);
            navigation.go({ shareId: share.id, path });
          }}
        >
          <EntryIcon
            entry={{ kind: "directory", name }}
            size={17}
            aria-hidden="true"
          />
          <span>{name}</span>
        </a>
        {level === 0 && (
          <span
            class={`tree-access access-${share.access}`}
            aria-label={
              share.access === "read" ? "Read only" : "Read and write"
            }
            title={share.access === "read" ? "Read only" : "Read and write"}
          >
            {share.access === "read" ? "R" : "RW"}
          </span>
        )}
        <CopyPathButton
          value={`${share.id}${path ? `/${path}` : ""}`}
          label={`Copy full path for ${name}`}
          className="tree-copy"
          size={16}
        />
      </div>
      {open && (
        <ul class="tree-list">
          {childDirectories.map((entry) => {
            const childPath = joinPath(path, entry.name);
            return (
              <TreeNode
                {...props}
                key={childPath}
                level={level + 1}
                name={entry.name}
                path={childPath}
              />
            );
          })}
          {nodeState?.loading && !nodeState.page && (
            <li class="tree-status">Loading…</li>
          )}
          {nodeState?.error && (
            <li class="tree-status">
              <button
                type="button"
                onClick={() => void onLoadMore(share.id, path)}
              >
                Try again
              </button>
            </li>
          )}
          {nodeState?.page?.nextCursor && !nodeState.loading && (
            <li class="tree-status">
              <button
                type="button"
                onClick={() =>
                  void onLoadMore(share.id, path, nodeState.page?.nextCursor)
                }
              >
                More folders…
              </button>
            </li>
          )}
          {nodeState?.page &&
            !nodeState.loading &&
            !nodeState.error &&
            !nodeState.page.nextCursor &&
            childDirectories.length === 0 && (
              <li
                class="tree-status tree-empty"
                style={{ "--tree-level": level }}
              >
                No subfolders
              </li>
            )}
        </ul>
      )}
    </li>
  );
}

export function FolderPicker({
  api,
  share,
  selected,
  onSelect,
  onSessionExpired,
}: {
  api: ApiClient;
  share: Share;
  selected: string;
  onSelect: (path: string) => void;
  onSessionExpired: () => void;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set([""]));
  const [pages, setPages] = useState<Record<string, DirectoryPage>>({});
  const [loading, setLoading] = useState<Set<string>>(() => new Set());
  const [failed, setFailed] = useState<Set<string>>(() => new Set());
  const requests = useRef(new Map<string, AbortController>());

  useEffect(() => {
    const active = requests.current;
    return () => {
      active.forEach((controller) => controller.abort());
      active.clear();
    };
  }, []);

  const load = useCallback(
    async (path: string, cursor?: string) => {
      requests.current.get(path)?.abort();
      const controller = new AbortController();
      requests.current.set(path, controller);
      const current = () =>
        !controller.signal.aborted && requests.current.get(path) === controller;
      setLoading((state) => new Set(state).add(path));
      setFailed((state) => {
        if (!state.has(path)) return state;
        const next = new Set(state);
        next.delete(path);
        return next;
      });
      try {
        const page = await api.directory(
          share.id,
          path,
          cursor,
          controller.signal,
        );
        if (!current()) return;
        setPages((state) => ({
          ...state,
          [path]: mergePage(cursor ? state[path] : undefined, page),
        }));
      } catch (error) {
        if (!current()) return;
        if (
          typeof error === "object" &&
          error !== null &&
          "kind" in error &&
          error.kind === "unauthorized"
        ) {
          onSessionExpired();
        } else {
          // Failures wait for an explicit retry instead of looping.
          setFailed((state) => new Set(state).add(path));
        }
      } finally {
        if (requests.current.get(path) === controller) {
          requests.current.delete(path);
          setLoading((state) => {
            const next = new Set(state);
            next.delete(path);
            return next;
          });
        }
      }
    },
    [api, onSessionExpired, share.id],
  );

  useEffect(() => {
    void load("");
  }, [load]);

  const toggle = (path: string) => {
    const opening = !expanded.has(path);
    setExpanded((current) => {
      const next = new Set(current);
      if (opening) next.add(path);
      else next.delete(path);
      return next;
    });
    if (opening && !pages[path]) void load(path);
  };

  const render = (path: string, name: string, level: number) => {
    const open = expanded.has(path);
    return (
      <li key={path || "root"}>
        <div
          class={`picker-row${selected === path ? " is-selected" : ""}`}
          style={{ "--tree-level": level }}
        >
          <button
            class="tree-toggle"
            type="button"
            aria-label={`${open ? "Collapse" : "Expand"} ${name}`}
            aria-expanded={open}
            onClick={() => toggle(path)}
          >
            {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </button>
          <FolderPlus size={17} aria-hidden="true" />
          <button
            class="picker-choice"
            type="button"
            onClick={() => onSelect(path)}
          >
            {name}
          </button>
        </div>
        {open && (
          <ul class="tree-list">
            {directories(pages[path]).map((entry) =>
              render(joinPath(path, entry.name), entry.name, level + 1),
            )}
            {loading.has(path) && <li class="tree-status">Loading…</li>}
            {failed.has(path) && !loading.has(path) && (
              <li class="tree-status" role="alert">
                Folders could not be loaded.{" "}
                <button
                  type="button"
                  onClick={() => void load(path, pages[path]?.nextCursor)}
                >
                  Try again
                </button>
              </li>
            )}
            {pages[path]?.nextCursor &&
              !loading.has(path) &&
              !failed.has(path) && (
                <li class="tree-status">
                  <button
                    type="button"
                    onClick={() => void load(path, pages[path]?.nextCursor)}
                  >
                    More folders…
                  </button>
                </li>
              )}
          </ul>
        )}
      </li>
    );
  };

  return (
    <div class="folder-picker" role="group" aria-label="Destination folder">
      <ul class="tree-list">{render("", share.name, 0)}</ul>
    </div>
  );
}

import {
  ChevronDown,
  ChevronRight,
  FilePlus2,
  FolderPlus,
} from "lucide-preact";
import { useCallback, useEffect, useRef, useState } from "preact/hooks";

import {
  type ApiClient,
  type DirectoryEntry,
  type DirectoryPage,
  type Share,
} from "./api";
import { EntryIcon } from "./file-icons";
import { CopyPathButton } from "./copy-path-button";
import { directoryUrl, type BrowserNavigation } from "./navigation";
import { isValidVirtualPath } from "./virtual-path";

const dragType = "application/x-crabinet-entry";

interface DraggedEntry {
  shareId: string;
  path: string;
  entry: DirectoryEntry;
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
    JSON.stringify({ shareId, path, entry } satisfies DraggedEntry),
  );
  if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
}

function readDraggedEntry(event: DragEvent): DraggedEntry | undefined {
  try {
    const raw = event.dataTransfer?.getData(dragType);
    if (!raw) return undefined;
    const value = JSON.parse(raw) as Partial<DraggedEntry>;
    if (
      typeof value.shareId !== "string" ||
      typeof value.path !== "string" ||
      !isValidVirtualPath(value.path) ||
      !value.entry ||
      typeof value.entry.name !== "string" ||
      (value.entry.kind !== "file" && value.entry.kind !== "directory")
    ) {
      return undefined;
    }
    return value as DraggedEntry;
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
  navigation: BrowserNavigation;
  onCreateFile: () => void;
  onCreateFolder: () => void;
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
  navigation,
  onCreateFile,
  onCreateFolder,
  onMove,
  onSessionExpired,
}: ShareTreeProps) {
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [state, setState] = useState<Record<string, TreeState>>({});
  const showHiddenRef = useRef(showHidden);
  showHiddenRef.current = showHidden;
  const activeShare = shares.find((share) => share.id === activeShareId);

  const load = useCallback(
    async (shareId: string, path: string, cursor?: string) => {
      const nodeKey = key(shareId, path);
      setState((current) => ({
        ...current,
        [nodeKey]: { ...current[nodeKey], loading: true, error: false },
      }));
      try {
        const page = await api.directory(
          shareId,
          path,
          cursor,
          undefined,
          showHidden,
        );
        if (showHiddenRef.current !== showHidden) return;
        setState((current) => ({
          ...current,
          [nodeKey]: {
            page: mergePage(cursor ? current[nodeKey]?.page : undefined, page),
          },
        }));
      } catch (error) {
        if (showHiddenRef.current !== showHidden) return;
        if (
          typeof error === "object" &&
          error !== null &&
          "kind" in error &&
          error.kind === "unauthorized"
        ) {
          onSessionExpired();
        } else {
          setState((current) => ({
            ...current,
            [nodeKey]: { ...current[nodeKey], loading: false, error: true },
          }));
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
      {activeShare?.access === "read-write" && (
        <div class="tree-create-actions" aria-label="Create in current folder">
          <button
            class="button button-primary"
            type="button"
            onClick={onCreateFile}
          >
            <FilePlus2 size={18} aria-hidden="true" />
            New file
          </button>
          <button
            class="button button-secondary"
            type="button"
            onClick={onCreateFolder}
          >
            <FolderPlus size={18} aria-hidden="true" />
            New folder
          </button>
        </div>
      )}
      <div class="tree-scroll">
        <ul class="tree-list tree-roots">
          {shares.map((share) => (
            <TreeNode
              key={share.id}
              apiState={state}
              showHidden={showHidden}
              expanded={expanded}
              level={0}
              name={share.name}
              path=""
              share={share}
              activeShareId={activeShareId}
              activePath={activePath}
              navigation={navigation}
              onToggle={toggle}
              onExpand={expand}
              onLoadMore={load}
              onDrop={drop}
            />
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
    navigation,
    onToggle,
    onExpand,
    onLoadMore,
    onDrop,
  } = props;
  const nodeKey = key(share.id, path);
  const open = expanded.has(nodeKey);
  const nodeState = apiState[nodeKey];
  const selected = activeShareId === share.id && activePath === path;
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

  const load = useCallback(
    async (path: string, cursor?: string) => {
      setLoading((current) => new Set(current).add(path));
      try {
        const page = await api.directory(share.id, path, cursor);
        setPages((current) => ({
          ...current,
          [path]: mergePage(cursor ? current[path] : undefined, page),
        }));
      } catch (error) {
        if (
          typeof error === "object" &&
          error !== null &&
          "kind" in error &&
          error.kind === "unauthorized"
        ) {
          onSessionExpired();
        }
      } finally {
        setLoading((current) => {
          const next = new Set(current);
          next.delete(path);
          return next;
        });
      }
    },
    [api, onSessionExpired, share.id],
  );

  useEffect(() => {
    if (!pages[""] && !loading.has("")) void load("");
  }, [load, loading, pages]);

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
            {pages[path]?.nextCursor && !loading.has(path) && (
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

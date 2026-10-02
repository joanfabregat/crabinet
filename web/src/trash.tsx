import { useEffect, useRef, useState } from "preact/hooks";
import { Shredder, Trash2, Undo2 } from "lucide-preact";

import {
  ApiError,
  withCsrfRetry,
  type ApiClient,
  type Session,
  type Share,
  type TrashItem,
} from "./api";
import { EntryIcon } from "./file-icons";
import { Modal, shareStateMessages } from "./operations";
import { useToast } from "./toast";
import { FolderPicker } from "./tree";
import { isValidPathComponent } from "./virtual-path";

interface TrashViewProps {
  api: ApiClient;
  shares: Share[];
  csrfToken: string;
  userId: string;
  onSessionExpired: () => void;
  onSessionRefreshed: (session: Session) => void;
  onChanged: () => void;
}

/** One share's Trash, shown under its own divider. */
interface ShareTrash {
  share: Share;
  items: TrashItem[];
  failed: boolean;
  /** Where the next page starts; absent once every item is loaded. */
  nextCursor?: string;
  loadingMore?: boolean;
  /** The last attempt to load more failed. */
  moreFailed?: boolean;
}

/** Appends a page, dropping items already shown. */
function mergeItems(current: TrashItem[], next: TrashItem[]): TrashItem[] {
  const seen = new Set(current.map((item) => item.id));
  return [...current, ...next.filter((item) => !seen.has(item.id))];
}

/**
 * Empty Trash requests sent for one share before giving up. Each request
 * works for up to about 20 seconds, so this covers a very large Trash.
 */
const maxEmptyTrashRequests = 50;

/** An item together with the share whose Trash holds it. */
interface TrashTarget {
  share: Share;
  item: TrashItem;
}

// Matches the timestamps in the preview panel.
const absoluteTimeFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

const relativeTimeFormat = new Intl.RelativeTimeFormat(undefined, {
  numeric: "auto",
});

const relativeUnits: [Intl.RelativeTimeFormatUnit, number][] = [
  ["second", 60],
  ["minute", 60],
  ["hour", 24],
  ["day", 60],
  ["month", 12],
];

/** "3 minutes ago" or "in 30 days", in the largest unit that stays readable. */
function relativeTime(time: Date, now: number): string {
  let value = (time.valueOf() - now) / 1000;
  for (const [unit, limit] of relativeUnits) {
    if (Math.abs(value) < limit) {
      return relativeTimeFormat.format(Math.round(value), unit);
    }
    // Days carry over into months at their average length.
    value /= unit === "day" ? 30.44 : limit;
  }
  return relativeTimeFormat.format(Math.round(value), "year");
}

/** A relative time whose absolute date stays available as a tooltip. */
function TrashTime({ value, now }: { value: string; now: number }) {
  const time = new Date(value);
  if (Number.isNaN(time.valueOf())) return <>{value}</>;
  return (
    <time dateTime={value} title={absoluteTimeFormat.format(time)}>
      {relativeTime(time, now)}
    </time>
  );
}

function parentOf(path: string): string {
  return path.split("/").slice(0, -1).join("/");
}

function nameOf(path: string): string {
  return path.split("/").at(-1) ?? path;
}

function targetKey({ share, item }: TrashTarget): string {
  return `${share.id}\u0000${item.id}`;
}

export function TrashView({
  api,
  shares,
  csrfToken,
  userId,
  onSessionExpired,
  onSessionRefreshed,
  onChanged,
}: TrashViewProps) {
  const [groups, setGroups] = useState<ShareTrash[]>([]);
  const loadMoreControllers = useRef(new Map<string, AbortController>());
  const [retentionDays, setRetentionDays] = useState<number>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [busyKey, setBusyKey] = useState<string>();
  const [restoreTarget, setRestoreTarget] = useState<TrashTarget>();
  const [purgeTarget, setPurgeTarget] = useState<TrashTarget>();
  const [confirmEmpty, setConfirmEmpty] = useState(false);
  const [emptying, setEmptying] = useState(false);
  const [destinationDirectory, setDestinationDirectory] = useState("");
  const [destinationName, setDestinationName] = useState("");
  const showToast = useToast();

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    loadMoreControllers.current.forEach((pending) => pending.abort());
    loadMoreControllers.current.clear();
    void Promise.allSettled(
      shares.map((share) => api.trash(share.id, undefined, controller.signal)),
    ).then((results) => {
      if (controller.signal.aborted) return;
      if (
        results.some(
          (result) =>
            result.status === "rejected" &&
            result.reason instanceof ApiError &&
            result.reason.kind === "unauthorized",
        )
      ) {
        onSessionExpired();
        return;
      }
      // One server setting, so every share reports the same value.
      setRetentionDays(
        results.find((result) => result.status === "fulfilled")?.value
          .retentionDays,
      );
      setGroups(
        shares.map((share, index) => {
          const result = results[index]!;
          return result.status === "fulfilled"
            ? {
                share,
                items: result.value.items,
                failed: false,
                nextCursor: result.value.nextCursor,
              }
            : { share, items: [], failed: true };
        }),
      );
      setLoading(false);
    });
    return () => controller.abort();
  }, [api, shares, revision, onSessionExpired]);

  useEffect(() => {
    const pending = loadMoreControllers.current;
    return () => pending.forEach((controller) => controller.abort());
  }, []);

  const updateGroup = (shareId: string, change: Partial<ShareTrash>) =>
    setGroups((current) =>
      current.map((group) =>
        group.share.id === shareId ? { ...group, ...change } : group,
      ),
    );

  /** Loads the next page of one share's Trash below what is shown. */
  const loadMore = async (group: ShareTrash) => {
    const shareId = group.share.id;
    if (!group.nextCursor || loadMoreControllers.current.has(shareId)) return;
    const controller = new AbortController();
    loadMoreControllers.current.set(shareId, controller);
    updateGroup(shareId, { loadingMore: true, moreFailed: false });
    try {
      const page = await api.trash(
        shareId,
        group.nextCursor,
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setGroups((current) =>
        current.map((entry) =>
          entry.share.id === shareId
            ? {
                ...entry,
                items: mergeItems(entry.items, page.items),
                nextCursor: page.nextCursor,
                loadingMore: false,
              }
            : entry,
        ),
      );
    } catch (cause) {
      if (controller.signal.aborted) return;
      if (cause instanceof ApiError && cause.kind === "unauthorized") {
        onSessionExpired();
        return;
      }
      updateGroup(shareId, { loadingMore: false, moreFailed: true });
    } finally {
      if (loadMoreControllers.current.get(shareId) === controller)
        loadMoreControllers.current.delete(shareId);
    }
  };

  const removeItem = ({ share, item }: TrashTarget) =>
    setGroups((current) =>
      current.map((group) =>
        group.share.id === share.id
          ? {
              ...group,
              items: group.items.filter((entry) => entry.id !== item.id),
            }
          : group,
      ),
    );

  const mutate = async (
    target: TrashTarget,
    operation: (token: string) => Promise<void>,
  ) => {
    setBusyKey(targetKey(target));
    setError(undefined);
    try {
      await withCsrfRetry(
        api,
        csrfToken,
        userId,
        onSessionRefreshed,
        operation,
      );
      setRestoreTarget(undefined);
      setPurgeTarget(undefined);
      removeItem(target);
      onChanged();
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else throw cause;
    } finally {
      setBusyKey(undefined);
    }
  };

  const restore = async (target: TrashTarget, destination?: string) => {
    const { share, item } = target;
    try {
      await mutate(target, (token) =>
        api.restoreTrash(share.id, item.id, destination, token),
      );
      const restoredPath = destination ?? item.originalPath;
      showToast(`Restored ${nameOf(restoredPath)}.`, {
        action: {
          label: "Undo",
          onClick: () => void moveBackToTrash(share, restoredPath),
        },
      });
    } catch (cause) {
      if (
        destination === undefined &&
        cause instanceof ApiError &&
        (cause.kind === "conflict" ||
          cause.kind === "not-found" ||
          cause.code === "path_too_deep")
      ) {
        setDestinationDirectory("");
        setDestinationName(nameOf(item.originalPath));
        setRestoreTarget(target);
      } else if (cause instanceof ApiError && cause.code === "path_too_deep") {
        setError(
          `Could not restore this item there. ${shareStateMessages.path_too_deep} Choose a folder nearer the top.`,
        );
      } else {
        setError(
          "Could not restore this item. Check the destination and try again.",
        );
      }
    }
  };

  /** Undoes a restore by moving the restored item back to Trash. */
  const moveBackToTrash = async (share: Share, path: string) => {
    try {
      const metadata = await api.metadata(share.id, path);
      await withCsrfRetry(api, csrfToken, userId, onSessionRefreshed, (token) =>
        api.deleteEntry(share.id, path, metadata.etag, token),
      );
      showToast(`Moved ${nameOf(path)} back to Trash.`);
      onChanged();
      setRevision((value) => value + 1);
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else
        showToast(`Could not move ${nameOf(path)} back to Trash.`, {
          tone: "error",
        });
    }
  };

  const purge = async (target: TrashTarget) => {
    try {
      await mutate(target, (token) =>
        api.purgeTrash(target.share.id, target.item.id, token),
      );
      showToast(`Permanently deleted ${nameOf(target.item.originalPath)}.`);
    } catch (cause) {
      setError(
        cause instanceof ApiError && cause.code === "path_too_deep"
          ? "This item contains folders nested more than 64 levels deep and cannot be deleted from Trash here. Ask an administrator."
          : "Could not permanently delete this item. Try again.",
      );
    }
  };

  // Only shares with write access can be emptied. The server empties a
  // share's whole Trash, including pages not loaded here.
  const emptiable = groups.filter(
    (group) =>
      group.share.access === "read-write" &&
      (group.items.length > 0 || group.nextCursor !== undefined),
  );
  const loadedCount = emptiable.reduce(
    (count, group) => count + group.items.length,
    0,
  );
  const moreThanLoaded = emptiable.some(
    (group) => group.nextCursor !== undefined,
  );

  const emptyTrash = async () => {
    setEmptying(true);
    setError(undefined);
    let purged = 0;
    let failed = 0;
    let unfinished = false;
    try {
      for (const group of emptiable) {
        // One request empties the share unless its time budget runs out;
        // then the server says more remains and the next request continues.
        for (let request = 0; request < maxEmptyTrashRequests; request += 1) {
          const result = await withCsrfRetry(
            api,
            csrfToken,
            userId,
            onSessionRefreshed,
            (token) => api.emptyTrash(group.share.id, token),
          );
          purged += result.purged;
          failed += result.failed;
          unfinished = result.moreRemaining;
          if (!result.moreRemaining) break;
        }
        if (unfinished) break;
      }
      setConfirmEmpty(false);
      showToast(
        `Permanently deleted ${purged} ${purged === 1 ? "item" : "items"}.`,
      );
      if (unfinished)
        setError(
          "Trash is still being emptied. Use Empty Trash again to delete the rest.",
        );
      else if (failed > 0)
        setError(
          failed === 1
            ? "1 item could not be deleted and remains in Trash."
            : `${failed} items could not be deleted and remain in Trash.`,
        );
      onChanged();
      setRevision((value) => value + 1);
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else {
        setError("Could not empty all of Trash. What remains is listed below.");
        onChanged();
        setRevision((value) => value + 1);
      }
      setConfirmEmpty(false);
    } finally {
      setEmptying(false);
    }
  };

  const destination = destinationDirectory
    ? `${destinationDirectory}/${destinationName}`
    : destinationName;
  const now = Date.now();
  const shown = groups.filter(
    (group) => group.items.length > 0 || group.failed,
  );
  const allFailed = groups.length > 0 && groups.every((group) => group.failed);
  const retry = () => setRevision((value) => value + 1);

  return (
    <section class="directory-panel trash-panel" aria-labelledby="trash-title">
      <div class="directory-heading">
        <div>
          <p class="eyebrow">All shared folders</p>
          <h1 id="trash-title">Trash</h1>
        </div>
        <div class="directory-heading-actions">
          {emptiable.length > 0 && !loading && (
            <button
              type="button"
              class="button button-danger"
              disabled={Boolean(busyKey) || emptying}
              onClick={() => setConfirmEmpty(true)}
            >
              <Trash2 size={18} aria-hidden="true" />
              Empty Trash
            </button>
          )}
        </div>
      </div>
      <p class="muted">
        {retentionDays
          ? `Deleted items remain here for ${retentionDays} ${retentionDays === 1 ? "day" : "days"}.`
          : "Deleted items remain here until they expire."}{" "}
        Restoring and permanent deletion require write access.
      </p>
      {error && (
        <div class="notice notice-danger" role="alert">
          {error}
        </div>
      )}
      {loading ? (
        <p role="status">Loading Trash…</p>
      ) : allFailed ? (
        <div class="notice notice-danger" role="alert">
          Could not load Trash. <RetryButton onClick={retry} />
        </div>
      ) : shown.length === 0 ? (
        <div class="trash-empty" role="status">
          <span class="trash-empty-icon" aria-hidden="true">
            <Trash2 size={30} strokeWidth={1.6} />
          </span>
          <h2>Trash is empty.</h2>
          <p>
            Deleted files and folders appear here, so they can be restored{" "}
            {retentionDays
              ? `for ${retentionDays} ${retentionDays === 1 ? "day" : "days"}.`
              : "until they expire."}
          </p>
        </div>
      ) : (
        <div class="trash-groups">
          {shown.map((group, index) => (
            <section
              key={group.share.id}
              class="trash-group"
              aria-labelledby={`trash-group-${index}`}
            >
              <h2 class="trash-group-title" id={`trash-group-${index}`}>
                {group.share.name}{" "}
                <span class="trash-group-count">
                  <span aria-hidden="true">—</span> {group.items.length}
                  {group.nextCursor ? "+" : ""}{" "}
                  {group.items.length === 1 && !group.nextCursor
                    ? "item"
                    : "items"}
                </span>
              </h2>
              {group.failed ? (
                <div class="notice notice-danger" role="alert">
                  Could not load Trash for {group.share.name}.{" "}
                  <RetryButton onClick={retry} />
                </div>
              ) : (
                <ul class="trash-list">
                  {group.items.map((item) => (
                    <TrashRow
                      key={item.id}
                      share={group.share}
                      item={item}
                      now={now}
                      disabled={Boolean(busyKey) || emptying}
                      onRestore={() =>
                        void restore({ share: group.share, item })
                      }
                      onPurge={() =>
                        setPurgeTarget({ share: group.share, item })
                      }
                    />
                  ))}
                </ul>
              )}
              {!group.failed && group.moreFailed && (
                <div class="notice notice-danger" role="alert">
                  More items could not be loaded. Use Load more to try again.
                </div>
              )}
              {!group.failed && group.nextCursor && (
                <div class="load-more">
                  <button
                    type="button"
                    class="button button-secondary"
                    aria-label={`Load more from ${group.share.name}`}
                    disabled={group.loadingMore || emptying}
                    aria-busy={group.loadingMore ? "true" : undefined}
                    onClick={() => void loadMore(group)}
                  >
                    {group.loadingMore ? "Loading…" : "Load more"}
                  </button>
                </div>
              )}
            </section>
          ))}
        </div>
      )}
      {restoreTarget && (
        <Modal
          title={`Restore ${nameOf(restoreTarget.item.originalPath)}`}
          busy={Boolean(busyKey)}
          onClose={() => setRestoreTarget(undefined)}
          wide
        >
          <p>
            The original path is unavailable. Choose a folder in{" "}
            {restoreTarget.share.name} and a name for the restored item.
          </p>
          <FolderPicker
            api={api}
            share={restoreTarget.share}
            selected={destinationDirectory}
            onSelect={setDestinationDirectory}
            onSessionExpired={onSessionExpired}
          />
          <label for="restore-name">Name</label>
          <input
            id="restore-name"
            value={destinationName}
            onInput={(event) => setDestinationName(event.currentTarget.value)}
          />
          <p class="muted">Destination: {destination || "Choose a name"}</p>
          <div class="dialog-actions">
            <button
              type="button"
              class="button button-secondary"
              disabled={Boolean(busyKey)}
              onClick={() => setRestoreTarget(undefined)}
            >
              Cancel
            </button>
            <button
              type="button"
              class="button button-primary"
              disabled={
                Boolean(busyKey) || !isValidPathComponent(destinationName)
              }
              onClick={() => void restore(restoreTarget, destination)}
            >
              Restore here
            </button>
          </div>
        </Modal>
      )}
      {purgeTarget && (
        <Modal
          title={`Permanently delete ${nameOf(purgeTarget.item.originalPath)}`}
          busy={Boolean(busyKey)}
          onClose={() => setPurgeTarget(undefined)}
        >
          <p>
            This permanently deletes {nameOf(purgeTarget.item.originalPath)}{" "}
            from Trash. It cannot be undone.
          </p>
          <div class="dialog-actions">
            <button
              type="button"
              class="button button-secondary"
              disabled={Boolean(busyKey)}
              onClick={() => setPurgeTarget(undefined)}
            >
              Cancel
            </button>
            <button
              type="button"
              class="button button-danger"
              disabled={Boolean(busyKey)}
              onClick={() => void purge(purgeTarget)}
            >
              Delete permanently
            </button>
          </div>
        </Modal>
      )}
      {confirmEmpty && (
        <Modal
          title="Empty Trash?"
          busy={emptying}
          onClose={() => setConfirmEmpty(false)}
        >
          <p>
            {moreThanLoaded
              ? `Permanently delete all ${loadedCount}+ items from Trash?`
              : `Permanently delete ${loadedCount} ${loadedCount === 1 ? "item" : "items"} from Trash?`}{" "}
            This cannot be undone. Items in read-only shared folders will remain
            in Trash.
          </p>
          <div class="dialog-actions">
            <button
              type="button"
              class="button button-secondary"
              disabled={emptying}
              onClick={() => setConfirmEmpty(false)}
            >
              Cancel
            </button>
            <button
              type="button"
              class="button button-danger"
              disabled={emptying}
              onClick={() => void emptyTrash()}
            >
              {emptying ? "Emptying…" : "Empty Trash"}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function TrashRow({
  share,
  item,
  now,
  disabled,
  onRestore,
  onPurge,
}: {
  share: Share;
  item: TrashItem;
  now: number;
  disabled: boolean;
  onRestore: () => void;
  onPurge: () => void;
}) {
  const name = nameOf(item.originalPath);
  return (
    <li class="trash-item">
      <EntryIcon
        entry={{ kind: item.kind, name }}
        size={22}
        aria-hidden="true"
      />
      <div class="trash-details">
        <strong>{name}</strong>
        <span class="entry-meta">
          From {parentOf(item.originalPath) || share.name} · Deleted{" "}
          <TrashTime value={item.deletedAt} now={now} /> by {item.deletedBy} ·
          Expires <TrashTime value={item.expiresAt} now={now} />
        </span>
      </div>
      {share.access === "read-write" && (
        <div class="trash-actions">
          <button
            type="button"
            class="icon-button tooltip-action"
            aria-label={`Restore ${name}`}
            data-tooltip="Restore"
            disabled={disabled}
            onClick={onRestore}
          >
            <Undo2 size={18} aria-hidden="true" />
          </button>
          <button
            type="button"
            class="icon-button icon-button-danger tooltip-action"
            aria-label={`Permanently delete ${name}`}
            data-tooltip="Delete permanently"
            disabled={disabled}
            onClick={onPurge}
          >
            <Shredder size={18} aria-hidden="true" />
          </button>
        </div>
      )}
    </li>
  );
}

function RetryButton({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" class="notice-action" onClick={onClick}>
      Try again
    </button>
  );
}

import { useEffect, useState } from "preact/hooks";
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
import { Modal } from "./operations";
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
}

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
    void Promise.allSettled(
      shares.map((share) => api.trash(share.id, controller.signal)),
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
            ? { share, items: result.value.items, failed: false }
            : { share, items: [], failed: true };
        }),
      );
      setLoading(false);
    });
    return () => controller.abort();
  }, [api, shares, revision, onSessionExpired]);

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
        (cause.kind === "conflict" || cause.kind === "not-found")
      ) {
        setDestinationDirectory("");
        setDestinationName(nameOf(item.originalPath));
        setRestoreTarget(target);
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
    } catch {
      setError("Could not permanently delete this item. Try again.");
    }
  };

  // Only shares with write access can be emptied.
  const purgeable = groups
    .filter((group) => group.share.access === "read-write")
    .flatMap((group) =>
      group.items.map((item) => ({ share: group.share, item })),
    );

  const emptyTrash = async () => {
    setEmptying(true);
    setError(undefined);
    let purged = 0;
    try {
      // Empty the displayed snapshot. Items added by another user while this
      // runs are preserved and will appear after the final refresh.
      for (const target of purgeable) {
        await withCsrfRetry(
          api,
          csrfToken,
          userId,
          onSessionRefreshed,
          (token) => api.purgeTrash(target.share.id, target.item.id, token),
        );
        purged += 1;
        removeItem(target);
      }
      setConfirmEmpty(false);
      showToast(
        `Permanently deleted ${purged} ${purged === 1 ? "item" : "items"}.`,
      );
      onChanged();
      setRevision((value) => value + 1);
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else {
        setError("Could not empty all of Trash. What remains is listed below.");
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
          {purgeable.length > 0 && !loading && (
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
                  <span aria-hidden="true">—</span> {group.items.length}{" "}
                  {group.items.length === 1 ? "item" : "items"}
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
            Permanently delete {purgeable.length}{" "}
            {purgeable.length === 1 ? "item" : "items"} from Trash? This cannot
            be undone. Items in read-only shared folders, and items added while
            this runs, will remain in Trash.
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

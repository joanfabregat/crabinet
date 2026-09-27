import { useEffect, useState } from "preact/hooks";
import { RefreshCw, Shredder, Trash2, Undo2 } from "lucide-preact";

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
import { FolderPicker } from "./tree";
import { isValidPathComponent } from "./virtual-path";

interface TrashViewProps {
  api: ApiClient;
  share: Share;
  csrfToken: string;
  userId: string;
  onSessionExpired: () => void;
  onSessionRefreshed: (session: Session) => void;
  onChanged: () => void;
}

function displayTime(value: string): string {
  const time = new Date(value);
  return Number.isNaN(time.valueOf()) ? value : time.toLocaleString();
}

function nameOf(path: string): string {
  return path.split("/").at(-1) ?? path;
}

export function TrashView({
  api,
  share,
  csrfToken,
  userId,
  onSessionExpired,
  onSessionRefreshed,
  onChanged,
}: TrashViewProps) {
  const [items, setItems] = useState<TrashItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [busyId, setBusyId] = useState<string>();
  const [restoreItem, setRestoreItem] = useState<TrashItem>();
  const [purgeItem, setPurgeItem] = useState<TrashItem>();
  const [confirmEmpty, setConfirmEmpty] = useState(false);
  const [emptying, setEmptying] = useState(false);
  const [destinationDirectory, setDestinationDirectory] = useState("");
  const [destinationName, setDestinationName] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    api.trash(share.id, controller.signal).then(
      (page) => {
        if (!controller.signal.aborted) {
          setItems(page.items);
          setLoading(false);
        }
      },
      (cause: unknown) => {
        if (controller.signal.aborted) return;
        if (cause instanceof ApiError && cause.kind === "unauthorized")
          onSessionExpired();
        else {
          setError("Could not load Trash. Try again.");
          setLoading(false);
        }
      },
    );
    return () => controller.abort();
  }, [api, share.id, revision, onSessionExpired]);

  const mutate = async (
    id: string,
    operation: (token: string) => Promise<void>,
  ) => {
    setBusyId(id);
    setError(undefined);
    try {
      await withCsrfRetry(
        api,
        csrfToken,
        userId,
        onSessionRefreshed,
        operation,
      );
      setRestoreItem(undefined);
      setPurgeItem(undefined);
      setItems((current) => current.filter((item) => item.id !== id));
      onChanged();
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else throw cause;
    } finally {
      setBusyId(undefined);
    }
  };

  const restore = async (item: TrashItem, destination?: string) => {
    try {
      await mutate(item.id, (token) =>
        api.restoreTrash(share.id, item.id, destination, token),
      );
    } catch (cause) {
      if (
        destination === undefined &&
        cause instanceof ApiError &&
        (cause.kind === "conflict" || cause.kind === "not-found")
      ) {
        setDestinationDirectory("");
        setDestinationName(nameOf(item.originalPath));
        setRestoreItem(item);
      } else {
        setError(
          "Could not restore this item. Check the destination and try again.",
        );
      }
    }
  };

  const purge = async (item: TrashItem) => {
    try {
      await mutate(item.id, (token) =>
        api.purgeTrash(share.id, item.id, token),
      );
    } catch {
      setError("Could not permanently delete this item. Try again.");
    }
  };

  const emptyTrash = async () => {
    setEmptying(true);
    setError(undefined);
    try {
      // Empty the displayed snapshot. Items added by another user while this
      // runs are preserved and will appear after the final refresh.
      for (const item of items) {
        await withCsrfRetry(
          api,
          csrfToken,
          userId,
          onSessionRefreshed,
          (token) => api.purgeTrash(share.id, item.id, token),
        );
        setItems((current) =>
          current.filter((currentItem) => currentItem.id !== item.id),
        );
      }
      setConfirmEmpty(false);
      onChanged();
      setRevision((value) => value + 1);
    } catch (cause) {
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        onSessionExpired();
      else {
        setError("Could not empty all of Trash. Refresh to see what remains.");
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

  return (
    <section class="directory-panel trash-panel" aria-labelledby="trash-title">
      <div class="directory-heading">
        <div>
          <p class="eyebrow">{share.name}</p>
          <h1 id="trash-title">Trash</h1>
        </div>
        {share.access === "read-write" && items.length > 0 && !loading && (
          <button
            type="button"
            class="icon-button icon-button-danger tooltip-action"
            aria-label="Empty Trash"
            data-tooltip="Empty Trash"
            disabled={Boolean(busyId) || emptying}
            onClick={() => setConfirmEmpty(true)}
          >
            <Trash2 size={18} aria-hidden="true" />
          </button>
        )}
      </div>
      <p class="muted">
        Deleted items remain here until they expire. Restoring and permanent
        deletion require write access.
      </p>
      {error && (
        <div class="notice notice-danger" role="alert">
          {error}{" "}
          <button
            type="button"
            class="icon-button tooltip-action"
            aria-label="Refresh Trash"
            data-tooltip="Refresh Trash"
            onClick={() => setRevision((value) => value + 1)}
          >
            <RefreshCw size={18} aria-hidden="true" />
          </button>
        </div>
      )}
      {loading ? (
        <p role="status">Loading Trash…</p>
      ) : items.length === 0 ? (
        <p role="status">Trash is empty.</p>
      ) : (
        <ul class="trash-list">
          {items.map((item) => (
            <li key={item.id} class="trash-item">
              <EntryIcon
                entry={{ kind: item.kind, name: nameOf(item.originalPath) }}
                size={22}
                aria-hidden="true"
              />
              <div class="trash-details">
                <strong>{nameOf(item.originalPath)}</strong>
                <span class="entry-meta">
                  Original path: {item.originalPath}
                </span>
                <span class="entry-meta">
                  Deleted: {displayTime(item.deletedAt)} by {item.deletedBy}
                </span>
                <span class="entry-meta">
                  Expires: {displayTime(item.expiresAt)}
                </span>
              </div>
              {share.access === "read-write" && (
                <div class="trash-actions">
                  <button
                    type="button"
                    class="icon-button tooltip-action"
                    aria-label={`Restore ${nameOf(item.originalPath)}`}
                    data-tooltip="Restore"
                    disabled={Boolean(busyId) || emptying}
                    onClick={() => void restore(item)}
                  >
                    <Undo2 size={18} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    class="icon-button icon-button-danger tooltip-action"
                    aria-label={`Permanently delete ${nameOf(item.originalPath)}`}
                    data-tooltip="Delete permanently"
                    disabled={Boolean(busyId) || emptying}
                    onClick={() => setPurgeItem(item)}
                  >
                    <Shredder size={18} aria-hidden="true" />
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {restoreItem && (
        <Modal
          title={`Restore ${nameOf(restoreItem.originalPath)}`}
          busy={Boolean(busyId)}
          onClose={() => setRestoreItem(undefined)}
          wide
        >
          <p>
            The original path is unavailable. Choose a folder in {share.name}{" "}
            and a name for the restored item.
          </p>
          <FolderPicker
            api={api}
            share={share}
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
              disabled={Boolean(busyId)}
              onClick={() => setRestoreItem(undefined)}
            >
              Cancel
            </button>
            <button
              type="button"
              class="button button-primary"
              disabled={
                Boolean(busyId) || !isValidPathComponent(destinationName)
              }
              onClick={() => void restore(restoreItem, destination)}
            >
              Restore here
            </button>
          </div>
        </Modal>
      )}
      {purgeItem && (
        <Modal
          title={`Permanently delete ${nameOf(purgeItem.originalPath)}`}
          busy={Boolean(busyId)}
          onClose={() => setPurgeItem(undefined)}
        >
          <p>
            This permanently deletes {nameOf(purgeItem.originalPath)} from
            Trash. It cannot be undone.
          </p>
          <div class="dialog-actions">
            <button
              type="button"
              class="button button-secondary"
              disabled={Boolean(busyId)}
              onClick={() => setPurgeItem(undefined)}
            >
              Cancel
            </button>
            <button
              type="button"
              class="button button-danger"
              disabled={Boolean(busyId)}
              onClick={() => void purge(purgeItem)}
            >
              Delete permanently
            </button>
          </div>
        </Modal>
      )}
      {confirmEmpty && (
        <Modal
          title={`Empty ${share.name} Trash?`}
          busy={emptying}
          onClose={() => setConfirmEmpty(false)}
        >
          <p>
            Permanently delete {items.length}{" "}
            {items.length === 1 ? "item" : "items"} from {share.name} Trash?
            This cannot be undone. Items added while this runs will remain in
            Trash.
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

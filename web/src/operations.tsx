import { type JSX } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import {
  Ellipsis,
  FilePlus2,
  FolderInput,
  FolderPlus,
  Pencil,
  Trash2,
  Upload,
  X,
} from "lucide-preact";

import {
  ApiError,
  type ApiClient,
  type DirectoryEntry,
  type EntryMetadata,
  type Session,
} from "./api";
import { CopyPathButton } from "./copy-path-button";
import { isValidPathComponent } from "./virtual-path";
import { FolderPicker } from "./tree";

export type EntryOperation =
  | { kind: "create-file" }
  | { kind: "create-folder" }
  | {
      kind: "rename" | "delete" | "edit" | "move";
      entry: DirectoryEntry;
      path: string;
      destinationDirectory?: string;
    };

export interface UploadSelection {
  id: string;
  files: File[];
}

export function WriteToolbar({
  onCreateFile,
  onCreateFolder,
  onUpload,
}: {
  onCreateFile: () => void;
  onCreateFolder: () => void;
  onUpload: (files: File[]) => void;
}) {
  const input = useRef<HTMLInputElement>(null);

  const choose = (files: FileList | null) => {
    if (files?.length) onUpload(Array.from(files));
    if (input.current) input.current.value = "";
  };

  return (
    <section class="write-toolbar" aria-label="File operations">
      <button
        class="button button-primary toolbar-button"
        type="button"
        onClick={onCreateFile}
      >
        <FilePlus2 size={18} aria-hidden="true" />
        <span class="toolbar-label">New file</span>
      </button>
      <button
        class="button button-secondary toolbar-button"
        type="button"
        onClick={onCreateFolder}
      >
        <FolderPlus size={18} aria-hidden="true" />
        <span class="toolbar-label">New folder</span>
      </button>
      <button
        class="button button-secondary toolbar-button"
        type="button"
        onClick={() => input.current?.click()}
      >
        <Upload size={18} aria-hidden="true" />
        <span class="toolbar-label">Upload files</span>
      </button>
      <input
        ref={input}
        class="sr-only"
        type="file"
        multiple
        aria-label="Choose files to upload"
        onChange={(event) => choose(event.currentTarget.files)}
      />
    </section>
  );
}

export function EntryActionButtons({
  entry,
  path,
  copyPath,
  writable,
  onOperation,
}: {
  entry: DirectoryEntry;
  path: string;
  copyPath: string;
  writable: boolean;
  onOperation: (operation: EntryOperation) => void;
}) {
  return (
    <div
      class="entry-actions"
      role="group"
      aria-label={`Actions for ${entry.name}`}
    >
      <div class="entry-actions-inline">
        <CopyPathButton
          value={copyPath}
          label={`Copy full path for ${entry.name}`}
          className="entry-action"
          size={18}
        />
        {writable && (
          <>
            <button
              class="entry-action tooltip-action"
              type="button"
              aria-label={`Rename ${entry.name}`}
              data-tooltip="Rename"
              onClick={() => onOperation({ kind: "rename", entry, path })}
            >
              <Pencil size={18} aria-hidden="true" />
            </button>
            <button
              class="entry-action tooltip-action"
              type="button"
              aria-label={`Move ${entry.name}`}
              data-tooltip="Move to…"
              onClick={() => onOperation({ kind: "move", entry, path })}
            >
              <FolderInput size={18} aria-hidden="true" />
            </button>
            <button
              class="entry-action entry-action-danger tooltip-action"
              type="button"
              aria-label={`Delete ${entry.name}`}
              data-tooltip="Delete"
              onClick={() => onOperation({ kind: "delete", entry, path })}
            >
              <Trash2 size={18} aria-hidden="true" />
            </button>
          </>
        )}
      </div>
      <EntryActionMenu
        entry={entry}
        path={path}
        copyPath={copyPath}
        writable={writable}
        onOperation={onOperation}
      />
    </div>
  );
}

/**
 * On phones the row's actions fold into one "⋯" button so each row stays a
 * single line. Wider screens show the icon buttons instead (see styles.css).
 */
function EntryActionMenu({
  entry,
  path,
  copyPath,
  writable,
  onOperation,
}: {
  entry: DirectoryEntry;
  path: string;
  copyPath: string;
  writable: boolean;
  onOperation: (operation: EntryOperation) => void;
}) {
  // The list is fixed-positioned from the trigger, because the folder panel
  // clips overflow; it opens upward when the row is near the bottom.
  const [open, setOpen] = useState<JSX.CSSProperties>();
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const isOpen = open !== undefined;

  useEffect(() => {
    if (!isOpen) return;
    root.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    const closeOutside = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(undefined);
    };
    // A fixed list would drift from its row while the page scrolls.
    const closeOnScroll = () => setOpen(undefined);
    document.addEventListener("pointerdown", closeOutside);
    window.addEventListener("scroll", closeOnScroll, { passive: true });
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      window.removeEventListener("scroll", closeOnScroll);
    };
  }, [isOpen]);

  const close = () => {
    setOpen(undefined);
    trigger.current?.focus();
  };

  const choose = (operation: EntryOperation) => {
    setOpen(undefined);
    onOperation(operation);
  };

  const handleKeys = (event: JSX.TargetedKeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(
      event.currentTarget.querySelectorAll<HTMLElement>('[role="menuitem"]'),
    );
    const index = items.indexOf(document.activeElement as HTMLElement);
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      items[(index + 1) % items.length]?.focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      items[(index - 1 + items.length) % items.length]?.focus();
    } else if (event.key === "Home") {
      event.preventDefault();
      items[0]?.focus();
    } else if (event.key === "End") {
      event.preventDefault();
      items.at(-1)?.focus();
    } else if (event.key === "Tab") {
      setOpen(undefined);
    }
  };

  return (
    <div class="entry-menu" ref={root}>
      <button
        ref={trigger}
        class="entry-action"
        type="button"
        aria-label={`More actions for ${entry.name}`}
        aria-haspopup="menu"
        aria-expanded={isOpen}
        onClick={(event) => {
          if (isOpen) {
            setOpen(undefined);
            return;
          }
          const rect = event.currentTarget.getBoundingClientRect();
          const right = `${window.innerWidth - rect.right}px`;
          setOpen(
            rect.bottom + 240 > window.innerHeight
              ? { bottom: `${window.innerHeight - rect.top + 4}px`, right }
              : { top: `${rect.bottom + 4}px`, right },
          );
        }}
      >
        <Ellipsis size={18} aria-hidden="true" />
      </button>
      {open && (
        <div
          class="entry-menu-list"
          style={open}
          role="menu"
          aria-label={`Actions for ${entry.name}`}
          onKeyDown={handleKeys}
        >
          <CopyPathButton
            value={copyPath}
            label={`Copy full path for ${entry.name}`}
            className="entry-menu-item"
            size={17}
            text="Copy full path"
            role="menuitem"
          />
          {writable && (
            <>
              <button
                class="entry-menu-item"
                type="button"
                role="menuitem"
                onClick={() => choose({ kind: "rename", entry, path })}
              >
                <Pencil size={17} aria-hidden="true" />
                Rename
              </button>
              <button
                class="entry-menu-item"
                type="button"
                role="menuitem"
                onClick={() => choose({ kind: "move", entry, path })}
              >
                <FolderInput size={17} aria-hidden="true" />
                Move to…
              </button>
              <button
                class="entry-menu-item entry-action-danger"
                type="button"
                role="menuitem"
                onClick={() => choose({ kind: "delete", entry, path })}
              >
                <Trash2 size={17} aria-hidden="true" />
                Move to Trash
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

interface OperationDialogProps {
  api: ApiClient;
  csrfToken: string;
  operation: EntryOperation;
  directory: string;
  shareId: string;
  /** Labels the move picker's root; falls back to a generic label. */
  shareName?: string;
  userId: string;
  onClose: () => void;
  onChanged: (operation: EntryOperation, destinationPath?: string) => void;
  onSessionExpired: () => void;
  onSessionRefreshed: (session: Session) => void;
}

export function OperationDialog(props: OperationDialogProps) {
  if (props.operation.kind === "edit") return <EditorDialog {...props} />;
  if (props.operation.kind === "move") return <MoveDialog {...props} />;
  // Deletes move the item to Trash without a dialog.
  if (props.operation.kind === "delete") return null;
  return <SimpleOperationDialog {...props} />;
}

type ValidatorState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; etag: string }
  | { status: "error"; message: string; retryable: boolean };

/**
 * Captures an entry's validator when a dialog opens, so the If-Match sent on
 * submit protects the version the person actually reviewed. A kind that no
 * longer matches the entry shown blocks the operation, because the
 * confirmation offered depends on it.
 */
function useEntryValidator(
  api: ApiClient,
  shareId: string,
  target: { path: string; entry: DirectoryEntry } | undefined,
  onSessionExpired: () => void,
): [ValidatorState, () => void] {
  const [state, setState] = useState<ValidatorState>(
    target ? { status: "loading" } : { status: "idle" },
  );
  const [attempt, setAttempt] = useState(0);
  const path = target?.path;
  const kind = target?.entry.kind;

  useEffect(() => {
    if (path === undefined || kind === undefined) return;
    const controller = new AbortController();
    setState({ status: "loading" });
    api.metadata(shareId, path, controller.signal).then(
      (metadata) => {
        if (controller.signal.aborted) return;
        if (metadata.kind !== kind) {
          setState({
            status: "error",
            message:
              metadata.kind === "directory"
                ? "This item is now a folder. Close this dialog and reload the folder before trying again."
                : "This item is now a file. Close this dialog and reload the folder before trying again.",
            retryable: false,
          });
        } else {
          setState({ status: "ready", etag: metadata.etag });
        }
      },
      (cause: unknown) => {
        if (controller.signal.aborted || isAborted(cause)) return;
        if (isUnauthorized(cause)) {
          onSessionExpired();
          return;
        }
        setState({
          status: "error",
          message:
            cause instanceof ApiError && cause.kind === "not-found"
              ? "The item no longer exists. Reload the folder."
              : "The current version of this item could not be checked.",
          retryable: !(cause instanceof ApiError && cause.kind === "not-found"),
        });
      },
    );
    return () => controller.abort();
  }, [api, attempt, kind, path, shareId]);

  return [state, () => setAttempt((value) => value + 1)];
}

function ValidatorStatus({
  state,
  onRetry,
}: {
  state: ValidatorState;
  onRetry: () => void;
}) {
  if (state.status === "loading")
    return (
      <p class="muted" role="status">
        Checking the current version…
      </p>
    );
  if (state.status !== "error") return null;
  return (
    <div class="field-error" role="alert">
      <p>{state.message}</p>
      {state.retryable && (
        <button class="button button-secondary" type="button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

function SimpleOperationDialog({
  api,
  csrfToken,
  operation,
  directory,
  shareId,
  onClose,
  onChanged,
  onSessionExpired,
}: OperationDialogProps) {
  const initial = operation.kind === "rename" ? operation.entry.name : "";
  const [value, setValue] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();
  const input = useRef<HTMLInputElement>(null);
  const [validator, retryValidator] = useEntryValidator(
    api,
    shareId,
    "entry" in operation ? operation : undefined,
    onSessionExpired,
  );
  const needsValidator = validator.status !== "idle";
  const validatorReady = !needsValidator || validator.status === "ready";
  const title =
    operation.kind === "create-file"
      ? "Create file"
      : operation.kind === "create-folder"
        ? "Create folder"
        : `Rename ${operation.entry.name}`;

  useEffect(() => {
    input.current?.focus();
    return () => controller.current?.abort();
  }, []);

  const close = () => {
    if (!busy) onClose();
  };

  const submit = async (event: JSX.TargetedSubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;

    let destination: string;
    if (
      operation.kind === "create-file" ||
      operation.kind === "create-folder"
    ) {
      if (!isValidPathComponent(value)) {
        setError(
          "Enter one valid name without slashes, dot segments, or trailing spaces.",
        );
        return;
      }
      destination = joinPath(directory, value);
    } else if (operation.kind === "rename") {
      if (!isValidPathComponent(value) || value === operation.entry.name) {
        setError("Enter a different valid file or folder name.");
        return;
      }
      destination = joinPath(parentPath(operation.path), value);
    } else {
      return;
    }
    if (!validatorReady) return;

    setBusy(true);
    setError(undefined);
    const nextController = new AbortController();
    controller.current = nextController;
    try {
      if (operation.kind === "create-file") {
        await api.createFile(
          shareId,
          destination,
          csrfToken,
          nextController.signal,
        );
      } else if (operation.kind === "create-folder") {
        await api.createDirectory(
          shareId,
          destination,
          csrfToken,
          nextController.signal,
        );
      } else if (validator.status !== "ready") {
        return;
      } else {
        // The validator was captured when this dialog opened, so a change
        // made since then is refused by the server instead of overwritten.
        await api.moveEntry(
          shareId,
          operation.path,
          destination,
          validator.etag,
          csrfToken,
          nextController.signal,
        );
      }
      onChanged(
        operation,
        operation.kind === "rename" || operation.kind === "create-file"
          ? destination
          : undefined,
      );
    } catch (cause) {
      if (isUnauthorized(cause)) {
        onSessionExpired();
      } else if (!isAborted(cause)) {
        setError(operationError(cause));
      }
    } finally {
      setBusy(false);
    }
  };

  const fieldLabel =
    operation.kind === "rename"
      ? "New name"
      : operation.kind === "create-file"
        ? "File name"
        : "Folder name";

  return (
    <Modal title={title} onClose={close} busy={busy}>
      <form class="operation-form" onSubmit={submit}>
        {operation.kind === "rename" && (
          <p class="muted">
            Rename this item in its current folder. Existing items are never
            overwritten.
          </p>
        )}
        <label for="operation-value">{fieldLabel}</label>
        <input
          ref={input}
          id="operation-value"
          value={value}
          required
          autocomplete="off"
          onInput={(event) => setValue(event.currentTarget.value)}
          aria-describedby={error ? "operation-error" : undefined}
        />
        <ValidatorStatus state={validator} onRetry={retryValidator} />
        {error && (
          <p id="operation-error" class="field-error" role="alert">
            {error}
          </p>
        )}
        <div class="dialog-actions">
          <button
            class="button button-secondary"
            type="button"
            disabled={busy}
            onClick={close}
          >
            Cancel
          </button>
          <button
            class="button button-primary"
            type="submit"
            disabled={busy || !validatorReady}
          >
            {busy
              ? "Working…"
              : operation.kind === "rename"
                ? "Rename"
                : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function MoveDialog({
  api,
  csrfToken,
  operation,
  directory,
  shareId,
  shareName = "Shared folder",
  onClose,
  onChanged,
  onSessionExpired,
}: OperationDialogProps) {
  if (operation.kind !== "move")
    throw new Error("move dialog requires an entry");
  const [destinationDirectory, setDestinationDirectory] = useState(
    operation.destinationDirectory ?? directory,
  );
  // The dialog opens on the item's own folder, which is never a valid
  // destination. Only a folder the person picked is reported as an error.
  const [picked, setPicked] = useState(
    operation.destinationDirectory !== undefined,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();

  const [validator, retryValidator] = useEntryValidator(
    api,
    shareId,
    operation,
    onSessionExpired,
  );

  useEffect(() => () => controller.current?.abort(), []);

  const destination = joinPath(destinationDirectory, operation.entry.name);
  const invalid =
    destination === operation.path ||
    (operation.entry.kind === "directory" &&
      (destinationDirectory === operation.path ||
        destinationDirectory.startsWith(`${operation.path}/`)));

  const submit = async (event: JSX.TargetedSubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || invalid || validator.status !== "ready") return;
    setBusy(true);
    setError(undefined);
    const nextController = new AbortController();
    controller.current = nextController;
    try {
      // The validator was captured when this dialog opened.
      await api.moveEntry(
        shareId,
        operation.path,
        destination,
        validator.etag,
        csrfToken,
        nextController.signal,
      );
      onChanged(operation, destination);
    } catch (cause) {
      if (isUnauthorized(cause)) onSessionExpired();
      else if (!isAborted(cause)) setError(operationError(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={`Move ${operation.entry.name}`} onClose={onClose} busy={busy}>
      <form class="operation-form" onSubmit={submit}>
        <p class="muted">
          Choose a destination in this shared folder. Existing items are never
          overwritten.
        </p>
        <FolderPicker
          api={api}
          share={{ id: shareId, name: shareName, access: "read-write" }}
          selected={destinationDirectory}
          onSelect={(path) => {
            setDestinationDirectory(path);
            setPicked(true);
          }}
          onSessionExpired={onSessionExpired}
        />
        {!invalid ? (
          <p class="move-destination">
            Destination: <strong>{destination || operation.entry.name}</strong>
          </p>
        ) : picked ? (
          <p class="field-error">
            Choose a different folder outside this item.
          </p>
        ) : (
          <p class="muted">Select a destination folder to continue.</p>
        )}
        <ValidatorStatus state={validator} onRetry={retryValidator} />
        {error && (
          <p class="field-error" role="alert">
            {error}
          </p>
        )}
        <div class="dialog-actions">
          <button
            class="button button-secondary"
            type="button"
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            class="button button-primary"
            type="submit"
            disabled={busy || invalid || validator.status !== "ready"}
          >
            {busy ? "Moving…" : "Move here"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditorDialog({
  api,
  csrfToken,
  operation,
  shareId,
  userId,
  onClose,
  onChanged,
  onSessionExpired,
  onSessionRefreshed,
}: OperationDialogProps) {
  if (operation.kind !== "edit") throw new Error("editor requires a file");
  const [text, setText] = useState("");
  const [initialText, setInitialText] = useState("");
  const [metadata, setMetadata] = useState<EntryMetadata>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();
  const editor = useRef<HTMLTextAreaElement>(null);
  const dirty = text !== initialText;

  const load = () => {
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setLoading(true);
    setError(undefined);
    setConflict(false);
    void (async () => {
      try {
        // Metadata is deliberately captured before content. A change between these
        // reads leaves a stale validator and therefore cannot be silently saved.
        const nextMetadata = await api.metadata(
          shareId,
          operation.path,
          nextController.signal,
        );
        const document = await api.text(
          shareId,
          operation.path,
          nextController.signal,
        );
        setMetadata(nextMetadata);
        setText(document.text);
        setInitialText(document.text);
        requestAnimationFrame(() => editor.current?.focus());
      } catch (cause) {
        if (isUnauthorized(cause)) onSessionExpired();
        else if (!isAborted(cause)) setError(operationError(cause));
      } finally {
        setLoading(false);
      }
    })();
  };

  useEffect(() => {
    load();
    return () => controller.current?.abort();
  }, [operation.path, shareId]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  const save = async () => {
    if (!metadata || saving || !dirty) return;
    const nextController = new AbortController();
    controller.current = nextController;
    setSaving(true);
    setError(undefined);
    setConflict(false);
    try {
      const write = (token: string) =>
        api.saveText(
          shareId,
          operation.path,
          text,
          metadata.etag,
          token,
          nextController.signal,
        );
      try {
        await write(csrfToken);
      } catch (cause) {
        if (!(cause instanceof ApiError && cause.kind === "forbidden"))
          throw cause;
        const refreshed = await api.session(nextController.signal);
        if (refreshed.user.id !== userId) {
          setError(
            "A different account is signed in. Return to your original account, then retry save. Your edits are still here.",
          );
          return;
        }
        if (
          !refreshed.shares.some(
            (share) => share.id === shareId && share.access === "read-write",
          )
        ) {
          setError(
            "Write access is unavailable for this folder. Your edits are still here to copy or retry after access is restored.",
          );
          return;
        }
        onSessionRefreshed(refreshed);
        await write(refreshed.csrfToken);
      }
      setInitialText(text);
      onChanged(operation);
    } catch (cause) {
      if (isUnauthorized(cause))
        setError(
          "Your sign-in needs refreshing. Sign in again in another tab, then retry save here. Your edits are still here.",
        );
      else if (cause instanceof ApiError && cause.kind === "conflict")
        setConflict(true);
      else if (cause instanceof ApiError && cause.kind === "forbidden")
        setError(
          "Save was denied with the current access. Your edits are still here. Retry save or contact an administrator.",
        );
      else if (!isAborted(cause)) setError(operationError(cause));
    } finally {
      setSaving(false);
    }
  };

  const close = () => {
    if (saving) return;
    if (!dirty || window.confirm("Discard your unsaved changes?")) onClose();
  };

  const reloadLatest = () => {
    if (
      !dirty ||
      window.confirm("Discard your unsaved edits and reload the file?")
    )
      load();
  };

  return (
    <Modal
      title={`Edit ${operation.entry.name}`}
      onClose={close}
      busy={saving}
      wide
    >
      {loading ? (
        <p role="status">Loading text…</p>
      ) : !metadata ? (
        <div role="alert" class="field-error">
          <p>{error ?? "The file could not be loaded."}</p>
          <button class="button button-secondary" type="button" onClick={load}>
            Try again
          </button>
        </div>
      ) : (
        <div class="editor-form">
          {error && (
            <div role="alert" class="notice notice-warning">
              {error}
            </div>
          )}
          {conflict && (
            <div class="notice notice-warning" role="alert">
              <p>
                This file changed after you opened it. Your edits were not
                saved.
              </p>
              <button
                class="button button-secondary"
                type="button"
                onClick={reloadLatest}
              >
                Reload latest version
              </button>
            </div>
          )}
          <label for="text-editor">UTF-8 text content</label>
          <textarea
            ref={editor}
            id="text-editor"
            value={text}
            disabled={saving}
            spellcheck={false}
            onInput={(event) => setText(event.currentTarget.value)}
          />
          <p class="editor-status" aria-live="polite">
            {saving
              ? "Saving…"
              : dirty
                ? "Unsaved changes"
                : "All changes saved"}
          </p>
          <div class="dialog-actions">
            <button
              class="button button-secondary"
              type="button"
              disabled={saving}
              onClick={close}
            >
              Close
            </button>
            <button
              class="button button-primary"
              type="button"
              disabled={!dirty || saving || conflict}
              onClick={save}
            >
              {error ? "Retry save" : "Save"}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

interface UploadJob {
  id: string;
  file: File;
  status:
    "queued" | "uploading" | "succeeded" | "failed" | "cancelled" | "conflict";
  loaded: number;
  total?: number;
  message?: string;
  /** The existing file's validator, captured when the conflict was shown. */
  replaceEtag?: string;
}

export function UploadQueue({
  api,
  csrfToken,
  directory,
  files,
  shareId,
  onClose,
  onChanged,
  onSessionExpired,
}: {
  api: ApiClient;
  csrfToken: string;
  directory: string;
  files: File[];
  shareId: string;
  onClose: () => void;
  onChanged: () => void;
  onSessionExpired: () => void;
}) {
  const [jobs, setJobs] = useState<UploadJob[]>(() =>
    files.map((file, index) => ({
      id: `${index}:${file.name}`,
      file,
      status: isValidPathComponent(file.name) ? "queued" : "failed",
      loaded: 0,
      message: isValidPathComponent(file.name)
        ? undefined
        : "The filename is not valid for this server.",
    })),
  );
  const controllers = useRef(new Map<string, AbortController>());
  const started = useRef(false);

  const update = (id: string, change: Partial<UploadJob>) =>
    setJobs((current) =>
      current.map((job) => (job.id === id ? { ...job, ...change } : job)),
    );

  const run = async (job: UploadJob, replace = false) => {
    if (controllers.current.has(job.id)) return;
    // Replacement only ever uses the validator captured when the conflict
    // was shown, so a version the person never saw is not overwritten.
    const etag = replace ? job.replaceEtag : undefined;
    if (replace && !etag) return;
    const controller = new AbortController();
    controllers.current.set(job.id, controller);
    update(job.id, {
      status: "uploading",
      loaded: 0,
      message: undefined,
      replaceEtag: undefined,
    });
    try {
      const result = await api.uploadFile(
        shareId,
        directory,
        job.file,
        csrfToken,
        {
          replace,
          etag,
          signal: controller.signal,
          onProgress: (loaded, total) => update(job.id, { loaded, total }),
        },
      );
      const outcome = result.outcomes[0]?.outcome;
      if (outcome === "created" || outcome === "replaced") {
        update(job.id, {
          status: "succeeded",
          loaded: job.file.size,
          total: job.file.size,
          message: outcome === "replaced" ? "Replaced" : "Uploaded",
        });
        onChanged();
      } else if (outcome === "conflict") {
        update(job.id, await describeConflict(job, controller.signal));
      } else if (outcome === "quota_exceeded") {
        update(job.id, {
          status: "failed",
          message: "The shared folder quota was exceeded.",
        });
      } else if (outcome && shareStateMessages[outcome]) {
        update(job.id, {
          status: "failed",
          message: shareStateMessages[outcome],
        });
      } else {
        update(job.id, { status: "failed", message: "The upload failed." });
      }
    } catch (cause) {
      if (isUnauthorized(cause)) {
        controllers.current.forEach((item) => item.abort());
        onSessionExpired();
      } else if (isAborted(cause)) {
        update(job.id, { status: "cancelled", message: "Cancelled" });
      } else {
        update(job.id, { status: "failed", message: uploadError(cause) });
      }
    } finally {
      controllers.current.delete(job.id);
    }
  };

  const describeConflict = async (
    job: UploadJob,
    signal: AbortSignal,
  ): Promise<Partial<UploadJob>> => {
    try {
      const existing = await api.metadata(
        shareId,
        joinPath(directory, job.file.name),
        signal,
      );
      if (existing.kind !== "file") {
        return {
          status: "failed",
          message: "A folder with this name already exists.",
        };
      }
      return {
        status: "conflict",
        message: "A file with this name already exists.",
        replaceEtag: existing.etag,
      };
    } catch (cause) {
      if (isUnauthorized(cause) || isAborted(cause)) throw cause;
      return {
        status: "conflict",
        message:
          "A file with this name already exists, but its current version could not be checked. Retry to check again.",
      };
    }
  };

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const queue = jobs.filter((job) => job.status === "queued");
    let next = 0;
    const worker = async () => {
      while (next < queue.length) {
        const job = queue[next++];
        if (job) await run(job);
      }
    };
    // The server allows each user three concurrent uploads (src/mutations.rs).
    for (let index = 0; index < Math.min(3, queue.length); index += 1) {
      void worker();
    }
    return () =>
      controllers.current.forEach((controller) => controller.abort());
  }, []);

  const active = jobs.some(
    (job) => job.status === "queued" || job.status === "uploading",
  );
  const complete = jobs.filter((job) => job.status === "succeeded").length;

  return (
    <Modal title="Uploads" onClose={onClose} busy={false} wide>
      <p class="sr-only" role="status" aria-live="polite">
        {active
          ? `${complete} of ${jobs.length} uploads complete`
          : `Uploads finished: ${complete} succeeded`}
      </p>
      <ul class="upload-list">
        {jobs.map((job) => (
          <li key={job.id}>
            <div class="upload-job-heading">
              <span class="upload-name">{job.file.name}</span>
              <span>{uploadStatus(job.status)}</span>
            </div>
            {job.status === "uploading" && (
              <progress
                value={job.loaded}
                max={job.total ?? (job.file.size || 1)}
                aria-label={`Upload progress for ${job.file.name}`}
              />
            )}
            {job.message && <p class="upload-message">{job.message}</p>}
            <div class="upload-job-actions">
              {job.status === "uploading" && (
                <button
                  class="entry-action"
                  type="button"
                  onClick={() => controllers.current.get(job.id)?.abort()}
                >
                  Cancel
                </button>
              )}
              {(job.status === "failed" ||
                job.status === "cancelled" ||
                (job.status === "conflict" && !job.replaceEtag)) &&
                isValidPathComponent(job.file.name) && (
                  <button
                    class="entry-action"
                    type="button"
                    onClick={() => void run(job)}
                  >
                    Retry
                  </button>
                )}
              {job.status === "conflict" && job.replaceEtag && (
                <button
                  class="entry-action entry-action-danger"
                  type="button"
                  onClick={() => void run(job, true)}
                >
                  Replace existing file
                </button>
              )}
            </div>
          </li>
        ))}
      </ul>
      <div class="dialog-actions">
        <button class="button button-secondary" type="button" onClick={onClose}>
          {active ? "Close and cancel uploads" : "Close"}
        </button>
        {active && (
          <button
            class="button button-danger"
            type="button"
            onClick={() =>
              controllers.current.forEach((controller) => controller.abort())
            }
          >
            Cancel all
          </button>
        )}
      </div>
    </Modal>
  );
}

export function Modal({
  title,
  children,
  onClose,
  busy,
  wide = false,
  className,
}: {
  title: string;
  children: preact.ComponentChildren;
  onClose: () => void;
  busy: boolean;
  wide?: boolean;
  /** An extra class on the panel, for a dialog with its own layout. */
  className?: string;
}) {
  const titleId = `dialog-${title.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}`;
  const panel = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  const busyRef = useRef(busy);
  closeRef.current = onClose;
  busyRef.current = busy;

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const focusTimer = window.setTimeout(() => {
      if (!panel.current?.contains(document.activeElement)) {
        panel.current
          ?.querySelector<HTMLElement>(
            "button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), [href]",
          )
          ?.focus();
      }
    }, 0);
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) closeRef.current();
      if (event.key !== "Tab" || !panel.current) return;
      const focusable = Array.from(
        panel.current.querySelectorAll<HTMLElement>(
          "button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), [href]",
        ),
      );
      if (focusable.length === 0) return;
      const first = focusable[0]!;
      const last = focusable.at(-1)!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", keydown);
    return () => {
      window.clearTimeout(focusTimer);
      document.removeEventListener("keydown", keydown);
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, []);

  return (
    <div
      class="modal-backdrop"
      role="presentation"
      onMouseDown={(event) =>
        !busy && event.target === event.currentTarget && onClose()
      }
    >
      <div
        ref={panel}
        class={`modal-panel${wide ? " modal-panel-wide" : ""}${className ? ` ${className}` : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        {/* A <header> here would add a second banner landmark. */}
        <div class="modal-header">
          <h2 id={titleId}>{title}</h2>
          <button
            class="modal-close"
            type="button"
            aria-label={`Close ${title}`}
            disabled={busy}
            onClick={onClose}
          >
            <X size={20} aria-hidden="true" />
          </button>
        </div>
        <div class="modal-content">{children}</div>
      </div>
    </div>
  );
}

function joinPath(parent: string, child: string): string {
  return parent ? `${parent}/${child}` : child;
}

function parentPath(path: string): string {
  const separator = path.lastIndexOf("/");
  return separator < 0 ? "" : path.slice(0, separator);
}

/**
 * Messages for server error codes and upload outcomes that name a state of
 * the shared folder or path depth rather than a failure of this request.
 */
export const shareStateMessages: Readonly<Record<string, string>> = {
  path_too_deep: "Folders can be nested at most 64 levels deep.",
  share_too_large_to_measure:
    "The shared folder has too many items to check its quota. Ask an administrator.",
  share_too_deep_to_measure:
    "The shared folder has folders nested too deeply to check its quota. Ask an administrator.",
};

function shareStateMessage(cause: ApiError): string | undefined {
  return cause.code ? shareStateMessages[cause.code] : undefined;
}

function operationError(cause: unknown): string {
  if (cause instanceof ApiError) {
    const stateMessage = shareStateMessage(cause);
    if (stateMessage) return stateMessage;
    if (cause.kind === "forbidden")
      return "Your write access changed. Reload the page or contact an administrator.";
    if (cause.kind === "conflict")
      return "The item changed or the destination already exists. Reload the folder and try again.";
    if (cause.kind === "not-found")
      return "The item no longer exists. Reload the folder.";
    if (cause.status === 413)
      return "The content is larger than the server allows.";
    if (cause.status === 415) return "Only valid UTF-8 text can be edited.";
  }
  return "The operation failed. Check your connection and try again.";
}

function uploadError(cause: unknown): string {
  if (cause instanceof ApiError) {
    const stateMessage = shareStateMessage(cause);
    if (stateMessage) return stateMessage;
    if (cause.kind === "forbidden") return "Your write access changed.";
    if (cause.kind === "conflict" || cause.status === 412)
      return "The existing file changed after it was checked. Retry to review it again.";
    if (cause.status === 413)
      return "This file is larger than the server allows.";
    if (cause.status === 429 || cause.status === 503)
      return "The server is busy. Retry shortly.";
  }
  return "The upload failed. Check your connection and retry.";
}

function uploadStatus(status: UploadJob["status"]): string {
  return status === "queued"
    ? "Queued"
    : status === "uploading"
      ? "Uploading"
      : status === "succeeded"
        ? "Succeeded"
        : status === "cancelled"
          ? "Cancelled"
          : status === "conflict"
            ? "Needs attention"
            : "Failed";
}

function isUnauthorized(cause: unknown): boolean {
  return cause instanceof ApiError && cause.kind === "unauthorized";
}

function isAborted(cause: unknown): boolean {
  return cause instanceof ApiError && cause.kind === "aborted";
}

import { type JSX } from "preact";
import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "preact/hooks";
import {
  Download,
  Archive,
  ArchiveRestore,
  Ellipsis,
  FilePlus2,
  FolderDown,
  FolderInput,
  FolderPlus,
  Pencil,
  Trash2,
  Upload,
  X,
} from "lucide-preact";

import {
  ApiError,
  type ArchiveFormat,
  type ApiClient,
  type DirectoryEntry,
  type EntryMetadata,
  type Session,
  type TextSaveResult,
} from "./api";
import { CopyPathButton } from "./copy-path-button";
import { isValidPathComponent } from "./virtual-path";
import { FolderPicker } from "./tree";
import { useToast } from "./toast";

export type EntryOperation =
  | { kind: "create-file" }
  | { kind: "create-folder" }
  | {
      kind: "rename" | "delete" | "edit" | "move" | "compress" | "extract";
      entry: DirectoryEntry;
      path: string;
      destinationDirectory?: string;
      sources?: string[];
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

/**
 * A row's download: the file itself, or a folder as a ZIP. A folder's
 * archive is checked with the server first (`onArchive`), so a refusal is
 * shown in the app; modified clicks keep the browser's own link behavior.
 */
interface EntryDownload {
  href: string;
  onArchive?: () => void;
}

function downloadClick(
  download: EntryDownload,
  event: JSX.TargetedMouseEvent<HTMLAnchorElement>,
  after?: () => void,
) {
  const modified =
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey;
  if (download.onArchive && !modified) {
    event.preventDefault();
    download.onArchive();
  }
  after?.();
}

function downloadLabel(entry: DirectoryEntry): string {
  return entry.kind === "directory"
    ? `Download ${entry.name} as ZIP`
    : `Download ${entry.name}`;
}

export function EntryActionButtons({
  entry,
  path,
  copyPath,
  download,
  writable,
  onOperation,
}: {
  entry: DirectoryEntry;
  path: string;
  copyPath: string;
  download: EntryDownload;
  writable: boolean;
  onOperation: (operation: EntryOperation) => void;
}) {
  const Icon = entry.kind === "directory" ? FolderDown : Download;
  return (
    <div
      class="entry-actions"
      role="group"
      aria-label={`Actions for ${entry.name}`}
    >
      <div class="entry-actions-inline">
        <a
          class="entry-action tooltip-action"
          href={download.href}
          aria-label={downloadLabel(entry)}
          data-tooltip={
            entry.kind === "directory" ? "Download as ZIP" : "Download"
          }
          onClick={(event) => downloadClick(download, event)}
        >
          <Icon size={18} aria-hidden="true" />
        </a>
        <CopyPathButton
          value={copyPath}
          label={`Copy full path for ${entry.name}`}
          className="entry-action entry-action-secondary"
          size={18}
        />
        {writable && (
          <>
            <button
              class="entry-action entry-action-secondary tooltip-action"
              type="button"
              aria-label={`Compress ${entry.name}`}
              data-tooltip="Compress…"
              onClick={() => onOperation({ kind: "compress", entry, path })}
            >
              <Archive size={18} aria-hidden="true" />
            </button>
            {entry.kind === "file" && archiveFormat(entry.name) && (
              <button
                class="entry-action entry-action-secondary tooltip-action"
                type="button"
                aria-label={`Extract ${entry.name}`}
                data-tooltip="Extract…"
                onClick={() => onOperation({ kind: "extract", entry, path })}
              >
                <ArchiveRestore size={18} aria-hidden="true" />
              </button>
            )}
            <button
              class="entry-action entry-action-secondary tooltip-action"
              type="button"
              aria-label={`Rename ${entry.name}`}
              data-tooltip="Rename"
              onClick={() => onOperation({ kind: "rename", entry, path })}
            >
              <Pencil size={18} aria-hidden="true" />
            </button>
            <button
              class="entry-action entry-action-secondary tooltip-action"
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
        download={download}
        writable={writable}
        onOperation={onOperation}
      />
    </div>
  );
}

/**
 * On phones the row's actions fold into one "⋯" button so each row stays a
 * single line. Wider screens show the icon buttons instead, and a list too
 * narrow for all of them keeps Download and Delete beside this menu, which
 * still holds every action (see styles.css).
 */
function EntryActionMenu({
  entry,
  path,
  copyPath,
  download,
  writable,
  onOperation,
}: {
  entry: DirectoryEntry;
  path: string;
  copyPath: string;
  download: EntryDownload;
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
          const count =
            2 +
            (writable
              ? 4 + (entry.kind === "file" && archiveFormat(entry.name) ? 1 : 0)
              : 0);
          const rem =
            Number.parseFloat(
              getComputedStyle(document.documentElement).fontSize,
            ) || 16;
          const height = count * 2.75 * rem + 12;
          setOpen({
            top: `${Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - height - 8))}px`,
            right,
          });
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
          <a
            class="entry-menu-item"
            role="menuitem"
            href={download.href}
            aria-label={downloadLabel(entry)}
            onClick={(event) =>
              downloadClick(download, event, () => setOpen(undefined))
            }
          >
            {entry.kind === "directory" ? (
              <FolderDown size={17} aria-hidden="true" />
            ) : (
              <Download size={17} aria-hidden="true" />
            )}
            {entry.kind === "directory" ? "Download as ZIP" : "Download"}
          </a>
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
                onClick={() => choose({ kind: "compress", entry, path })}
              >
                <Archive size={17} aria-hidden="true" /> Compress…
              </button>
              {entry.kind === "file" && archiveFormat(entry.name) && (
                <button
                  class="entry-menu-item"
                  type="button"
                  role="menuitem"
                  onClick={() => choose({ kind: "extract", entry, path })}
                >
                  <ArchiveRestore size={17} aria-hidden="true" /> Extract…
                </button>
              )}
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
  /** The account's autosave choice, which the editor starts from. */
  autosave?: boolean;
  /** The account's line wrapping choice, which the editor starts from. */
  wrapLines?: boolean;
  onClose: () => void;
  onChanged: (operation: EntryOperation, destinationPath?: string) => void;
  onSessionExpired: () => void;
  onSessionRefreshed: (session: Session) => void;
}

/** How long the editor waits after the last edit before autosaving. */
export const autosaveDelayMs = 2_000;

/** Failed autosaves retried before autosave pauses and asks for a retry. */
export const autosaveRetries = 4;

/** The longest wait between two autosave retries. */
export const autosaveRetryMaxMs = 30_000;

export function OperationDialog(props: OperationDialogProps) {
  if (props.operation.kind === "compress" || props.operation.kind === "extract")
    return <ArchiveDialog {...props} />;
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

/** Lines as the textarea shows them; a trailing newline starts an empty one. */
function countLines(text: string): number {
  let lines = 1;
  for (
    let index = text.indexOf("\n");
    index !== -1;
    index = text.indexOf("\n", index + 1)
  )
    lines += 1;
  return lines;
}

/** The zero-based line that holds `offset`. */
function lineAt(text: string, offset: number): number {
  let line = 0;
  for (
    let index = text.indexOf("\n");
    index !== -1 && index < offset;
    index = text.indexOf("\n", index + 1)
  )
    line += 1;
  return line;
}

/**
 * The indentation the file already uses: a tab when most indented lines
 * start with one, otherwise its narrowest run of spaces, two by default.
 */
export function detectIndent(text: string): string {
  let tabs = 0;
  let spaced = 0;
  let narrowest = Infinity;
  for (const line of text.split("\n")) {
    if (line.startsWith("\t")) tabs += 1;
    else {
      const spaces = /^ +(?=\S)/.exec(line)?.[0].length;
      if (spaces === undefined) continue;
      spaced += 1;
      narrowest = Math.min(narrowest, spaces);
    }
  }
  if (tabs > spaced) return "\t";
  return " ".repeat(narrowest >= 2 && narrowest <= 8 ? narrowest : 2);
}

export interface IndentEdit {
  start: number;
  end: number;
  replacement: string;
  selectionStart: number;
  selectionEnd: number;
}

/**
 * What Tab or Shift+Tab does to `text` with the given selection. Tab inside
 * one line inserts `unit`; Tab across lines and Shift+Tab work on whole lines.
 */
export function indentEdit(
  text: string,
  start: number,
  end: number,
  unit: string,
  outdent: boolean,
): IndentEdit {
  const selected = text.slice(start, end);
  if (!outdent && !selected.includes("\n")) {
    const caret = start + unit.length;
    return {
      start,
      end,
      replacement: unit,
      selectionStart: caret,
      selectionEnd: caret,
    };
  }
  const first = text.lastIndexOf("\n", start - 1) + 1;
  // A selection that ends at the start of a line leaves that line alone.
  const lastEnd = end > start && text[end - 1] === "\n" ? end - 1 : end;
  const lineEnd = text.indexOf("\n", lastEnd);
  const last = lineEnd === -1 ? text.length : lineEnd;
  const lines = text.slice(first, last).split("\n");
  const changes = lines.map((line) => {
    if (!outdent) return line === "" ? 0 : unit.length;
    if (line.startsWith(unit)) return -unit.length;
    if (line.startsWith("\t")) return -1;
    return -Math.min(/^ */.exec(line)![0].length, unit.length);
  });
  const replacement = lines
    .map((line, index) =>
      changes[index]! > 0 ? unit + line : line.slice(-changes[index]!),
    )
    .join("\n");
  const total = changes.reduce((sum, change) => sum + change, 0);
  return {
    start: first,
    end: last,
    replacement,
    selectionStart: Math.max(first, start + changes[0]!),
    selectionEnd: Math.max(first, end + total),
  };
}

/**
 * Replaces part of a textarea's value through the browser's editing
 * commands, so undo still works, falling back to a plain replacement.
 */
function replaceText(textarea: HTMLTextAreaElement, edit: IndentEdit): void {
  textarea.setSelectionRange(edit.start, edit.end);
  const inserted =
    typeof document.execCommand === "function" &&
    document.execCommand("insertText", false, edit.replacement);
  if (!inserted) {
    textarea.setRangeText(edit.replacement, edit.start, edit.end);
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  }
  textarea.setSelectionRange(edit.selectionStart, edit.selectionEnd);
}

/** Whether a failed save may succeed if tried again unchanged. */
function isTransient(cause: unknown): boolean {
  return (
    cause instanceof ApiError && (cause.kind === "network" || cause.retryable)
  );
}

function EditorDialog({
  api,
  csrfToken,
  operation,
  shareId,
  userId,
  autosave: autosaveDefault = false,
  wrapLines: wrapDefault = false,
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
  // Autosave and Save leave the text editable; a save that closes the
  // editor locks it, so nothing typed meanwhile is lost.
  const [saving, setSaving] = useState<"auto" | "manual" | "closing">();
  const showToast = useToast();
  const [conflict, setConflict] = useState(false);
  const [error, setError] = useState<string>();
  // Starts from the account setting; turning it off here lasts only until
  // the editor closes.
  const [autosave, setAutosave] = useState(autosaveDefault);
  // Like autosave, the account setting is only where the editor starts.
  const [wrap, setWrap] = useState(wrapDefault);
  // Autosaves that failed in a row on errors worth retrying.
  const [failedAutosaves, setFailedAutosaves] = useState(0);
  const [caretLine, setCaretLine] = useState(0);
  // Each line's rendered height while wrapping; one row each otherwise.
  const [lineHeights, setLineHeights] = useState<number[]>();
  // Closing with edits autosave will not save asks what to do with them.
  const [closePrompt, setClosePrompt] = useState(false);
  const controller = useRef<AbortController>();
  const editor = useRef<HTMLTextAreaElement>(null);
  const gutter = useRef<HTMLPreElement>(null);
  const measure = useRef<HTMLDivElement>(null);
  const currentLine = useRef<HTMLDivElement>(null);
  const firstToggle = useRef<HTMLInputElement>(null);
  const saveAndCloseButton = useRef<HTMLButtonElement>(null);
  const indentUnit = useRef("  ");
  const savingNow = useRef(false);
  const savedOnce = useRef(false);
  const dirty = text !== initialText;
  // A failed save keeps failing until the user acts, so autosave waits.
  const autosavePaused = error !== undefined || conflict;
  const lineCount = countLines(text);
  // Rebuilt only when the count changes, not on every keystroke.
  const lineNumbers = useMemo(
    () => Array.from({ length: lineCount }, (_, line) => line + 1).join("\n"),
    [lineCount],
  );

  const followCaret = () => {
    const textarea = editor.current;
    if (textarea) setCaretLine(lineAt(textarea.value, textarea.selectionStart));
  };

  /** Moves the current-line band to the caret's line at the scroll offset. */
  const placeCurrentLine = () => {
    const textarea = editor.current;
    const band = currentLine.current;
    if (!textarea || !band) return;
    const style = getComputedStyle(textarea);
    const row = parseFloat(style.lineHeight) || 21;
    const top =
      parseFloat(style.paddingTop) +
      (lineHeights
        ? lineHeights
            .slice(0, caretLine)
            .reduce((sum, height) => sum + height, 0)
        : caretLine * row) -
      textarea.scrollTop;
    band.style.top = `${top}px`;
    band.style.height = `${lineHeights?.[caretLine] ?? row}px`;
  };

  useEffect(() => {
    // Arrow keys and clicks move the caret without an input event.
    const changed = () => {
      if (document.activeElement === editor.current) followCaret();
    };
    document.addEventListener("selectionchange", changed);
    return () => document.removeEventListener("selectionchange", changed);
  }, []);

  // A wrapped line is as tall as the rows it takes, so the gutter copies
  // each height from a hidden copy of the text laid out at the same width.
  useLayoutEffect(() => {
    const textarea = editor.current;
    const copy = measure.current;
    if (!wrap || !textarea || !copy) {
      setLineHeights(undefined);
      return;
    }
    const layout = () => {
      const style = getComputedStyle(textarea);
      copy.style.width = `${
        textarea.clientWidth -
        parseFloat(style.paddingLeft) -
        parseFloat(style.paddingRight)
      }px`;
      copy.replaceChildren(
        ...textarea.value.split("\n").map((line) => {
          const row = document.createElement("div");
          // An empty line still takes one row.
          row.textContent = line || " ";
          return row;
        }),
      );
      const heights = Array.from(
        copy.children,
        (row) => (row as HTMLElement).offsetHeight,
      );
      copy.replaceChildren();
      setLineHeights(heights);
    };
    layout();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(layout);
    observer.observe(textarea);
    return () => observer.disconnect();
  }, [wrap, text, loading]);

  useLayoutEffect(placeCurrentLine);

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
        indentUnit.current = detectIndent(document.text);
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

  /** Saves `snapshot` and reports whether it was saved. */
  const persist = async (
    snapshot: string,
    mode: "auto" | "manual" | "closing",
  ): Promise<boolean> => {
    if (!metadata || savingNow.current) return false;
    savingNow.current = true;
    const nextController = new AbortController();
    controller.current = nextController;
    setSaving(mode);
    setError(undefined);
    setConflict(false);
    try {
      const write = (token: string) =>
        api.saveText(
          shareId,
          operation.path,
          snapshot,
          metadata.etag,
          token,
          nextController.signal,
        );
      let saved: TextSaveResult;
      try {
        saved = await write(csrfToken);
      } catch (cause) {
        if (!(cause instanceof ApiError && cause.kind === "forbidden"))
          throw cause;
        const refreshed = await api.session(nextController.signal);
        if (refreshed.user.id !== userId) {
          setError(
            "A different account is signed in. Return to your original account, then retry save. Your edits are still here.",
          );
          return false;
        }
        if (
          !refreshed.shares.some(
            (share) => share.id === shareId && share.access === "read-write",
          )
        ) {
          setError(
            "Write access is unavailable for this folder. Your edits are still here to copy or retry after access is restored.",
          );
          return false;
        }
        onSessionRefreshed(refreshed);
        saved = await write(refreshed.csrfToken);
      }
      setMetadata({ ...metadata, etag: saved.etag });
      // Edits typed during an autosave stay unsaved and start the next one.
      setInitialText(snapshot);
      savedOnce.current = true;
      setFailedAutosaves(0);
      return true;
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
      else if (
        mode === "auto" &&
        isTransient(cause) &&
        failedAutosaves < autosaveRetries
      )
        // Autosave tries again on its own, waiting longer each time.
        setFailedAutosaves(failedAutosaves + 1);
      else if (!isAborted(cause)) {
        setFailedAutosaves(0);
        setError(operationError(cause));
      }
      return false;
    } finally {
      savingNow.current = false;
      setSaving(undefined);
    }
  };

  useEffect(() => {
    if (!autosave || !dirty || saving || autosavePaused || !metadata) return;
    const timer = window.setTimeout(
      () => void persist(text, "auto"),
      Math.min(autosaveDelayMs * 2 ** failedAutosaves, autosaveRetryMaxMs),
    );
    return () => window.clearTimeout(timer);
  }, [
    autosave,
    text,
    initialText,
    saving,
    autosavePaused,
    metadata,
    failedAutosaves,
  ]);

  const indent = (event: JSX.TargetedKeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Escape") {
      // Tab indents here, so Escape is the keyboard's way out of the text;
      // a second Escape closes the editor.
      event.preventDefault();
      event.stopPropagation();
      firstToggle.current?.focus();
      return;
    }
    if (
      event.key !== "Tab" ||
      event.altKey ||
      event.ctrlKey ||
      event.metaKey ||
      event.isComposing
    )
      return;
    event.preventDefault();
    event.stopPropagation();
    const textarea = event.currentTarget;
    replaceText(
      textarea,
      indentEdit(
        textarea.value,
        textarea.selectionStart,
        textarea.selectionEnd,
        indentUnit.current,
        event.shiftKey,
      ),
    );
    followCaret();
  };

  /** Saves and keeps editing; the listing refreshes when the editor closes. */
  const save = async () => {
    if (!dirty || saving) return;
    if (!(await persist(text, "manual"))) return;
    showToast(`Saved ${operation.entry.name}.`);
    // The Save button is disabled until the next edit, so typing resumes.
    editor.current?.focus();
  };

  const close = async () => {
    if (saving) return;
    // Escape or the close button while asking means "not yet".
    if (closePrompt) return keepEditing();
    if (dirty && autosave && !autosavePaused) {
      // Closing is the end of the edit, so autosave saves what is pending.
      if (await persist(text, "closing")) onChanged(operation);
      return;
    }
    if (dirty) setClosePrompt(true);
    else discard();
  };

  const keepEditing = () => {
    setClosePrompt(false);
    editor.current?.focus();
  };

  const discard = () => {
    if (savedOnce.current) onChanged(operation);
    else onClose();
  };

  const saveAndClose = async () => {
    // A failed save shows its error with the usual buttons.
    setClosePrompt(false);
    if (await persist(text, "closing")) onChanged(operation);
  };

  useEffect(() => {
    if (closePrompt) saveAndCloseButton.current?.focus();
  }, [closePrompt]);

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
      onClose={() => void close()}
      busy={saving === "closing"}
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
          <div
            class={wrap ? "editor-surface editor-wrapping" : "editor-surface"}
          >
            <div
              ref={currentLine}
              class="editor-current-line"
              aria-hidden="true"
            />
            <pre ref={gutter} class="editor-gutter" aria-hidden="true">
              {lineHeights
                ? lineHeights.map((height, line) => (
                    <div key={line} style={{ height: `${height}px` }}>
                      {line + 1}
                    </div>
                  ))
                : lineNumbers}
            </pre>
            <textarea
              ref={editor}
              id="text-editor"
              value={text}
              disabled={saving === "closing"}
              spellcheck={false}
              wrap={wrap ? "soft" : "off"}
              aria-describedby="text-editor-keys"
              onInput={(event) => {
                setText(event.currentTarget.value);
                followCaret();
              }}
              onKeyDown={indent}
              onFocus={followCaret}
              onScroll={(event) => {
                if (gutter.current)
                  gutter.current.scrollTop = event.currentTarget.scrollTop;
                placeCurrentLine();
              }}
            />
            <div ref={measure} class="editor-measure" aria-hidden="true" />
          </div>
          <p id="text-editor-keys" class="sr-only">
            Tab indents and Shift+Tab outdents. Press Escape to leave the text.
          </p>
          <div class="editor-footer">
            <p class="editor-status" aria-live="polite">
              {saving
                ? "Saving…"
                : !dirty
                  ? "All changes saved"
                  : autosave && failedAutosaves > 0
                    ? "Could not save. Retrying…"
                    : autosave && autosavePaused
                      ? "Unsaved changes. Autosave is paused."
                      : "Unsaved changes"}
              {autosave && error !== undefined && dirty && !saving && (
                <>
                  {" "}
                  <button
                    class="text-button"
                    type="button"
                    onClick={() => void persist(text, "auto")}
                  >
                    Retry now
                  </button>
                </>
              )}
            </p>
            <div class="editor-toggles">
              <label class="settings-toggle">
                <input
                  ref={firstToggle}
                  type="checkbox"
                  checked={wrap}
                  onChange={(event) => setWrap(event.currentTarget.checked)}
                />
                Wrap lines
              </label>
              <label class="settings-toggle">
                <input
                  type="checkbox"
                  checked={autosave}
                  onChange={(event) => setAutosave(event.currentTarget.checked)}
                />
                Autosave
              </label>
            </div>
          </div>
          {closePrompt ? (
            <div
              class="editor-close-prompt"
              role="group"
              aria-labelledby="editor-close-question"
            >
              <p id="editor-close-question">
                Save your changes before closing?
              </p>
              <div class="dialog-actions">
                <button
                  class="button button-secondary"
                  type="button"
                  onClick={keepEditing}
                >
                  Cancel
                </button>
                <button
                  class="button button-secondary"
                  type="button"
                  onClick={discard}
                >
                  Discard
                </button>
                <button
                  ref={saveAndCloseButton}
                  class="button button-primary"
                  type="button"
                  disabled={conflict}
                  onClick={() => void saveAndClose()}
                >
                  Save and close
                </button>
              </div>
            </div>
          ) : (
            <div class="dialog-actions">
              <button
                class="button button-secondary"
                type="button"
                disabled={saving === "closing"}
                onClick={() => void close()}
              >
                Close
              </button>
              <button
                class="button button-primary"
                type="button"
                disabled={!dirty || saving !== undefined || conflict}
                onClick={() => void save()}
              >
                {error ? "Retry save" : "Save"}
              </button>
            </div>
          )}
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

const archiveFormats: {
  format: ArchiveFormat;
  suffix: string;
}[] = [
  { format: "zip", suffix: ".zip" },
  { format: "tar-gz", suffix: ".tar.gz" },
  { format: "tar-zst", suffix: ".tar.zst" },
  { format: "tar", suffix: ".tar" },
  { format: "gz", suffix: ".gz" },
];

export function archiveFormat(name: string): ArchiveFormat | undefined {
  const lower = name.toLowerCase();
  if (lower.endsWith(".tgz")) return "tar-gz";
  return archiveFormats.find(({ suffix }) => lower.endsWith(suffix))?.format;
}

function ArchiveDialog({
  api,
  csrfToken,
  operation,
  shareId,
  onClose,
  onChanged,
  onSessionExpired,
}: OperationDialogProps) {
  const extracting = operation.kind === "extract";
  const entry = "entry" in operation ? operation.entry : undefined;
  const source = "path" in operation ? operation.path : "";
  const sources =
    "sources" in operation && operation.sources ? operation.sources : [source];
  const detected = archiveFormat(entry?.name ?? "");
  const format = extracting ? (detected ?? "zip") : "zip";
  const base = sources.length > 1 ? "Archive" : (entry?.name ?? "Archive");
  const extractedName =
    base.replace(/\.(?:tar\.gz|tar\.zst|tgz|zip|tar|gz)$/i, "") || "Archive";
  const [name, setName] = useState(extracting ? extractedName : `${base}.zip`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    input.current?.focus();
    return () => controller.current?.abort();
  }, []);

  const submit = async (event: JSX.TargetedSubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    if (!isValidPathComponent(name)) {
      setError("Enter one valid name for the destination.");
      return;
    }
    const destination = joinPath(parentPath(source), name);
    const current = new AbortController();
    controller.current = current;
    setBusy(true);
    setError(undefined);
    try {
      const result = await api.localArchive(
        shareId,
        extracting ? "extract" : "compress",
        sources,
        destination,
        format,
        csrfToken,
        current.signal,
      );
      if (!current.signal.aborted) onChanged(operation, result.path);
    } catch (cause) {
      if (current.signal.aborted || isAborted(cause)) return;
      if (isUnauthorized(cause)) onSessionExpired();
      else if (cause instanceof ApiError && cause.code === "invalid_request")
        setError(
          "The operation could not finish. The archive may be damaged, encrypted, unsupported, contain unsafe or duplicate entries, or exceed the processing time limit.",
        );
      else if (cause instanceof ApiError && cause.code === "too_large")
        setError(
          "The operation exceeds the archive size, entry, metadata, or available share quota limit.",
        );
      else setError(operationError(cause));
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  };
  const cancel = () => {
    controller.current?.abort();
    onClose();
  };
  return (
    <Modal
      title={extracting ? "Extract archive" : "Compress"}
      onClose={cancel}
      busy={false}
    >
      <form class="operation-form" onSubmit={submit}>
        <p class="muted archive-description">
          {extracting
            ? "Extract into a new folder beside this archive. If the name is taken, -2, -3, and so on are added. Existing items are never overwritten."
            : "Create a ZIP archive beside the selected items. The originals are kept."}
        </p>
        <label for="archive-name">
          {extracting ? "Folder name" : "Archive name"}
        </label>
        <input
          ref={input}
          id="archive-name"
          value={name}
          required
          disabled={busy}
          autocomplete="off"
          onInput={(event) => setName(event.currentTarget.value)}
        />
        {busy && (
          <p role="status">
            {extracting ? "Extracting…" : "Compressing…"} You can cancel this
            operation.
          </p>
        )}
        {error && (
          <p class="field-error" role="alert">
            {error}
          </p>
        )}
        <div class="dialog-actions">
          <button
            class="button button-secondary"
            type="button"
            onClick={cancel}
          >
            Cancel
          </button>
          <button class="button button-primary" type="submit" disabled={busy}>
            {extracting ? "Extract" : "Compress"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

import { type JSX } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { FolderInput, Pencil, Trash2, Upload } from "lucide-preact";

import {
  ApiError,
  type ApiClient,
  type DirectoryEntry,
  type EntryMetadata,
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
  onUpload,
}: {
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
        class="button button-secondary upload-picker"
        type="button"
        onClick={() => input.current?.click()}
      >
        <Upload size={17} aria-hidden="true" />
        Upload files
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
        </>
      )}
      <CopyPathButton
        value={copyPath}
        label={`Copy full path for ${entry.name}`}
        className="entry-action"
        size={18}
      />
      {writable && (
        <button
          class="entry-action entry-action-danger tooltip-action"
          type="button"
          aria-label={`Delete ${entry.name}`}
          data-tooltip="Delete"
          onClick={() => onOperation({ kind: "delete", entry, path })}
        >
          <Trash2 size={18} aria-hidden="true" />
        </button>
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
  onClose: () => void;
  onChanged: (operation: EntryOperation, destinationPath?: string) => void;
  onSessionExpired: () => void;
}

export function OperationDialog(props: OperationDialogProps) {
  if (props.operation.kind === "edit") return <EditorDialog {...props} />;
  if (props.operation.kind === "move") return <MoveDialog {...props} />;
  return <SimpleOperationDialog {...props} />;
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
  const destructive = operation.kind === "delete";
  const deletesFile = destructive && operation.entry.kind === "file";
  const deletesFolder = destructive && operation.entry.kind === "directory";
  const initial = operation.kind === "rename" ? operation.entry.name : "";
  const [value, setValue] = useState(initial);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();
  const input = useRef<HTMLInputElement>(null);
  const title =
    operation.kind === "create-file"
      ? "Create file"
      : operation.kind === "create-folder"
        ? "Create folder"
        : operation.kind === "rename"
          ? `Rename ${operation.entry.name}`
          : operation.entry.kind === "directory"
            ? `Delete folder ${operation.entry.name}`
            : `Delete file ${operation.entry.name}`;

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

    let destination = value;
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
    } else if (deletesFolder && value !== operation.entry.name) {
      setError(`Type ${operation.entry.name} exactly to confirm deletion.`);
      return;
    } else if (deletesFile && !confirmed) {
      setError(`Confirm permanent deletion of ${operation.entry.name}.`);
      return;
    }

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
      } else {
        const metadata = await api.metadata(
          shareId,
          operation.path,
          nextController.signal,
        );
        if (operation.kind === "rename") {
          await api.moveEntry(
            shareId,
            operation.path,
            destination,
            metadata.etag,
            csrfToken,
            nextController.signal,
          );
        } else {
          await api.deleteEntry(
            shareId,
            operation.path,
            metadata.etag,
            csrfToken,
            nextController.signal,
          );
        }
      }
      onChanged(
        operation,
        operation.kind === "rename" ? destination : undefined,
      );
    } catch (cause) {
      if (isUnauthorized(cause)) {
        onSessionExpired();
      } else if (!isAborted(cause)) {
        setError(operationError(cause, operation.kind));
      }
    } finally {
      setBusy(false);
    }
  };

  const fieldLabel = deletesFolder
    ? `Type ${operation.entry.name} to confirm`
    : operation.kind === "rename"
      ? "New name"
      : operation.kind === "create-file"
        ? "File name"
        : "Folder name";

  return (
    <Modal title={title} onClose={close} busy={busy}>
      <form class="operation-form" onSubmit={submit}>
        {destructive && (
          <p class="danger-copy">
            This permanently deletes only this item. Non-empty folders are never
            deleted.
          </p>
        )}
        {operation.kind === "rename" && (
          <p class="muted">
            Rename this item in its current folder. Existing items are never
            overwritten.
          </p>
        )}
        {deletesFile ? (
          <label class="confirmation-check" for="operation-confirm-delete">
            <input
              ref={input}
              id="operation-confirm-delete"
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.currentTarget.checked)}
              aria-describedby={error ? "operation-error" : undefined}
            />
            <span>
              I understand that {operation.entry.name} will be permanently
              deleted
            </span>
          </label>
        ) : (
          <>
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
          </>
        )}
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
            class={`button ${destructive ? "button-danger" : "button-primary"}`}
            type="submit"
            disabled={
              busy ||
              (deletesFile && !confirmed) ||
              (deletesFolder && value !== operation.entry.name)
            }
          >
            {busy ? "Working…" : destructive ? "Delete" : "Confirm"}
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
  onClose,
  onChanged,
  onSessionExpired,
}: OperationDialogProps) {
  if (operation.kind !== "move")
    throw new Error("move dialog requires an entry");
  const [destinationDirectory, setDestinationDirectory] = useState(
    operation.destinationDirectory ?? directory,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();

  useEffect(() => () => controller.current?.abort(), []);

  const destination = joinPath(destinationDirectory, operation.entry.name);
  const invalid =
    destination === operation.path ||
    (operation.entry.kind === "directory" &&
      destinationDirectory.startsWith(`${operation.path}/`));

  const submit = async (event: JSX.TargetedSubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || invalid) return;
    setBusy(true);
    setError(undefined);
    const nextController = new AbortController();
    controller.current = nextController;
    try {
      const metadata = await api.metadata(
        shareId,
        operation.path,
        nextController.signal,
      );
      await api.moveEntry(
        shareId,
        operation.path,
        destination,
        metadata.etag,
        csrfToken,
        nextController.signal,
      );
      onChanged(operation, destination);
    } catch (cause) {
      if (isUnauthorized(cause)) onSessionExpired();
      else if (!isAborted(cause)) setError(operationError(cause, "rename"));
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
          share={{ id: shareId, name: "Shared folder", access: "read-write" }}
          selected={destinationDirectory}
          onSelect={setDestinationDirectory}
          onSessionExpired={onSessionExpired}
        />
        <p class="move-destination">
          Destination: <strong>{destination || operation.entry.name}</strong>
        </p>
        {invalid && (
          <p class="field-error">
            Choose a different folder outside this item.
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
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            class="button button-primary"
            type="submit"
            disabled={busy || invalid}
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
  onClose,
  onChanged,
  onSessionExpired,
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
        else if (!isAborted(cause)) setError(operationError(cause, "edit"));
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
      await api.saveText(
        shareId,
        operation.path,
        text,
        metadata.etag,
        csrfToken,
        nextController.signal,
      );
      setInitialText(text);
      onChanged(operation);
    } catch (cause) {
      if (isUnauthorized(cause)) onSessionExpired();
      else if (cause instanceof ApiError && cause.kind === "conflict")
        setConflict(true);
      else if (!isAborted(cause)) setError(operationError(cause, "edit"));
    } finally {
      setSaving(false);
    }
  };

  const close = () => {
    if (saving) return;
    if (!dirty || window.confirm("Discard your unsaved changes?")) onClose();
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
      ) : error ? (
        <div role="alert" class="field-error">
          <p>{error}</p>
          <button class="button button-secondary" type="button" onClick={load}>
            Try again
          </button>
        </div>
      ) : (
        <div class="editor-form">
          {conflict && (
            <div class="notice notice-warning" role="alert">
              <p>
                This file changed after you opened it. Your edits were not
                saved.
              </p>
              <button
                class="button button-secondary"
                type="button"
                onClick={load}
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
            disabled={saving || conflict}
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
              Save
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
    const controller = new AbortController();
    controllers.current.set(job.id, controller);
    update(job.id, { status: "uploading", loaded: 0, message: undefined });
    try {
      let etag: string | undefined;
      if (replace) {
        etag = (
          await api.metadata(
            shareId,
            joinPath(directory, job.file.name),
            controller.signal,
          )
        ).etag;
      }
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
        update(job.id, {
          status: "conflict",
          message: "A file with this name already exists.",
        });
      } else if (outcome === "quota_exceeded") {
        update(job.id, {
          status: "failed",
          message: "The shared folder quota was exceeded.",
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
              {(job.status === "failed" || job.status === "cancelled") &&
                isValidPathComponent(job.file.name) && (
                  <button
                    class="entry-action"
                    type="button"
                    onClick={() => void run(job)}
                  >
                    Retry
                  </button>
                )}
              {job.status === "conflict" && (
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
}: {
  title: string;
  children: preact.ComponentChildren;
  onClose: () => void;
  busy: boolean;
  wide?: boolean;
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
        class={`modal-panel${wide ? " modal-panel-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header class="modal-header">
          <h2 id={titleId}>{title}</h2>
          <button
            class="modal-close"
            type="button"
            aria-label={`Close ${title}`}
            disabled={busy}
            onClick={onClose}
          >
            ×
          </button>
        </header>
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

function operationError(
  cause: unknown,
  operation: EntryOperation["kind"],
): string {
  if (cause instanceof ApiError) {
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
  return operation === "delete"
    ? "The item could not be deleted. A folder must be empty."
    : "The operation failed. Check your connection and try again.";
}

function uploadError(cause: unknown): string {
  if (cause instanceof ApiError) {
    if (cause.kind === "forbidden") return "Your write access changed.";
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

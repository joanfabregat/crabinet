import type { ThemePreference } from "./theme";
import { isValidPathComponent, isValidVirtualPath } from "./virtual-path";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";

export type AccessMode = "read" | "read-write";

export interface User {
  id: string;
  username: string;
  displayName: string;
  pictureUrl?: string;
}

export interface Share {
  id: string;
  name: string;
  access: AccessMode;
}

export interface Session {
  user: User;
  shares: Share[];
  defaultFolder?: DefaultFolder | null;
  /** Display settings saved on the server, so they follow the account. */
  preferences: UserPreferences;
  /** An opaque CSRF value held in memory only. This is not the session ID. */
  csrfToken: string;
  /** The running server release, e.g. "0.3.0". */
  version?: string;
}

export interface DefaultFolder {
  shareId: string;
  path: string;
}

export interface UserPreferences {
  showHiddenFiles: boolean;
  theme: ThemePreference;
}

export const defaultUserPreferences: UserPreferences = {
  showHiddenFiles: false,
  theme: "system",
};

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthMethods {
  passwordEnabled: boolean;
  oidcEnabled: boolean;
  passkeyEnabled?: boolean;
}

export interface Passkey {
  id: string;
  name: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface PasskeyChallenge<T> {
  flowId: string;
  options: { publicKey: T };
}

export interface DirectoryEntry {
  name: string;
  kind: "directory" | "file";
  size?: number;
  modifiedAtMs?: number;
}

export interface DirectoryPage {
  shareId: string;
  path: string;
  entries: DirectoryEntry[];
  nextCursor?: string;
}

export interface EntryMetadata {
  shareId: string;
  path: string;
  name: string;
  kind: "directory" | "file";
  size?: number;
  modifiedAtMs?: number;
  accessedAtMs?: number;
  createdAtMs?: number;
  etag: string;
}

export interface TextDocument {
  shareId: string;
  path: string;
  text: string;
  size: number;
  mimeType: string;
  etag: string;
}

export interface MutationResult {
  shareId: string;
  path: string;
  outcome: "success";
}

export interface TrashItem {
  id: string;
  originalPath: string;
  kind: "directory" | "file";
  deletedAt: string;
  deletedBy: string;
  expiresAt: string;
}

export interface TrashPage {
  shareId: string;
  items: TrashItem[];
  /** Days an item stays in Trash; older servers leave it out. */
  retentionDays?: number;
  /** Opaque position of the next page; omitted on the last page. */
  nextCursor?: string;
}

/** Items per Trash page; the server accepts at most 200. */
export const trashPageSize = 100;

/** The result of one Empty Trash request for a share. */
export interface EmptyTrashResult {
  shareId: string;
  /** Items this request deleted permanently. */
  purged: number;
  /** Items that could not be deleted and remain in Trash. */
  failed: number;
  /** The request ran out of time; ask again to continue. */
  moreRemaining: boolean;
}

export interface TrashResult extends MutationResult {
  trashId: string;
}

export type UploadOutcomeKind =
  | "created"
  | "replaced"
  | "conflict"
  | "quota_exceeded"
  | "share_too_large_to_measure"
  | "share_too_deep_to_measure"
  | "error";

const uploadOutcomeKinds: ReadonlySet<unknown> = new Set<UploadOutcomeKind>([
  "created",
  "replaced",
  "conflict",
  "quota_exceeded",
  "share_too_large_to_measure",
  "share_too_deep_to_measure",
  "error",
]);

export interface UploadOutcome {
  path: string;
  outcome: UploadOutcomeKind;
}

export interface UploadResult {
  shareId: string;
  outcomes: UploadOutcome[];
}

export interface UploadOptions {
  replace?: boolean;
  etag?: string;
  signal?: AbortSignal;
  onProgress?: (loaded: number, total?: number) => void;
}

export type PreviewKind =
  | "text"
  | "code"
  | "markdown_source"
  | "html_source"
  | "image"
  | "pdf"
  | "audio"
  | "video"
  /** A camera RAW file, shown only through its server-rendered thumbnail. */
  | "raw"
  /**
   * An SVG document within the server's render limit, recognized from its
   * content: its source (a head above the preview limit), plus an image view
   * of the whole file from `svgPreviewUrl`.
   */
  | "svg";

export type PreviewMimeType =
  | "image/png"
  | "image/jpeg"
  | "image/gif"
  | "image/webp"
  | "image/avif"
  | "application/pdf"
  | "audio/mp4"
  | "audio/ogg"
  | "audio/wav"
  | "audio/flac"
  | "audio/mpeg"
  | "video/mp4"
  | "video/webm"
  | "video/ogg";

export interface PreviewDocument {
  kind: PreviewKind;
  source: string;
  language?: string;
  /** Derived by the server from the file's signature, never its name. */
  mimeType?: PreviewMimeType;
  width?: number;
  height?: number;
  /** The whole file's size, also when `source` is only its head. */
  size: number;
  /**
   * A text-like file above the server's preview limit: `source` is only its
   * head, described by `shownBytes` and `shownLines`.
   */
  truncated: boolean;
  shownBytes?: number;
  shownLines?: number;
  /** The open route serves this file inline in a new tab. */
  openable?: boolean;
  /**
   * The rendered-HTML route renders the whole file, also when `source` is
   * only its head. Only `html_source` documents within the server's render
   * limit are renderable.
   */
  renderable?: boolean;
  /** The thumbnail route can render this file (see `thumbnailUrl`). */
  thumbnailable?: boolean;
}

/** The only long-edge sizes the thumbnail route accepts. */
export type ThumbnailSize = 256 | 1600;

export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "not-found"
  | "conflict"
  | "rate-limited"
  | "invalid-request"
  | "invalid-response"
  | "network"
  | "aborted"
  | "server";

export interface ApiErrorOptions {
  status?: number;
  code?: string;
  requestId?: string;
  retryable?: boolean;
  cause?: unknown;
}

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status?: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly retryable: boolean;

  constructor(
    kind: ApiErrorKind,
    message: string,
    options: ApiErrorOptions = {},
  ) {
    super(message, { cause: options.cause });
    this.name = "ApiError";
    this.kind = kind;
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId;
    this.retryable = options.retryable ?? false;
  }
}

export interface ApiClient {
  session(signal?: AbortSignal): Promise<Session>;
  authMethods(signal?: AbortSignal): Promise<AuthMethods>;
  login(credentials: LoginCredentials, signal?: AbortSignal): Promise<Session>;
  logout(csrfToken: string, signal?: AbortSignal): Promise<void>;
  passkeys(signal?: AbortSignal): Promise<Passkey[]>;
  startPasskeyRegistration(
    name: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<PasskeyChallenge<PublicKeyCredentialCreationOptionsJSON>>;
  finishPasskeyRegistration(
    flowId: string,
    credential: RegistrationResponseJSON,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<Passkey>;
  startPasskeyLogin(
    username?: string,
  ): Promise<PasskeyChallenge<PublicKeyCredentialRequestOptionsJSON>>;
  finishPasskeyLogin(
    flowId: string,
    credential: AuthenticationResponseJSON,
  ): Promise<Session>;
  renamePasskey(id: string, name: string, csrfToken: string): Promise<Passkey>;
  removePasskey(id: string, csrfToken: string): Promise<void>;
  updateDefaultFolder(
    folder: DefaultFolder | null,
    csrfToken: string,
  ): Promise<DefaultFolder | null>;
  /** Saves only the given settings and returns every saved display setting. */
  updatePreferences(
    update: Partial<UserPreferences>,
    csrfToken: string,
  ): Promise<UserPreferences>;
  directory(
    shareId: string,
    path: string,
    cursor?: string,
    signal?: AbortSignal,
    showHidden?: boolean,
  ): Promise<DirectoryPage>;
  preview(
    shareId: string,
    path: string,
    signal?: AbortSignal,
  ): Promise<PreviewDocument>;
  metadata(
    shareId: string,
    path: string,
    signal?: AbortSignal,
  ): Promise<EntryMetadata>;
  /**
   * Starts an archive of a folder, a file, or a selection of one folder's
   * entries (see {@link archiveUrl}) and cancels it as soon as the server
   * admits it, so a refusal can be shown in the app before the browser
   * downloads the same URL. Rejects with the server's error otherwise.
   */
  checkArchive(
    shareId: string,
    paths: string | readonly string[],
    signal?: AbortSignal,
  ): Promise<void>;
  text(
    shareId: string,
    path: string,
    signal?: AbortSignal,
  ): Promise<TextDocument>;
  createDirectory(
    shareId: string,
    path: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<MutationResult>;
  createFile(
    shareId: string,
    path: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<MutationResult>;
  saveText(
    shareId: string,
    path: string,
    text: string,
    etag: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<MutationResult>;
  moveEntry(
    shareId: string,
    source: string,
    destination: string,
    etag: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<MutationResult>;
  deleteEntry(
    shareId: string,
    path: string,
    etag: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<TrashResult>;
  /** One page of a share's Trash, newest first; pass `nextCursor` for more. */
  trash(
    shareId: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<TrashPage>;
  restoreTrash(
    shareId: string,
    id: string,
    destination: string | undefined,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<void>;
  purgeTrash(
    shareId: string,
    id: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<void>;
  /** Permanently deletes everything in one share's Trash, not just a page. */
  emptyTrash(
    shareId: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<EmptyTrashResult>;
  uploadFile(
    shareId: string,
    directory: string,
    file: File,
    csrfToken: string,
    options?: UploadOptions,
  ): Promise<UploadResult>;
}

interface ApiProblem {
  code?: string;
  message?: string;
  requestId?: string;
}

export interface ApiClientOptions {
  fetch?: typeof globalThis.fetch;
  xhrFactory?: () => XMLHttpRequest;
  retryDelayMs?: number;
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const fetchImplementation =
    options.fetch ?? globalThis.fetch.bind(globalThis);
  const retryDelayMs = options.retryDelayMs ?? 200;
  const xhrFactory = options.xhrFactory ?? (() => new XMLHttpRequest());

  const request = async <T>(
    path: string,
    init: RequestInit = {},
    retrySafe = false,
  ): Promise<T> => {
    const attempts = retrySafe ? 2 : 1;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        const response = await fetchImplementation(path, {
          ...init,
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            ...init.headers,
          },
        });

        if (!response.ok) {
          const error = await responseError(response);
          if (attempt < attempts && isAutomaticallyRetryable(error.status)) {
            await abortableDelay(retryDelayMs, init.signal);
            continue;
          }
          throw error;
        }

        if (response.status === 204) return undefined as T;
        try {
          return (await response.json()) as T;
        } catch (cause) {
          throw new ApiError(
            "invalid-response",
            "The server returned invalid JSON",
            {
              status: response.status,
              cause,
            },
          );
        }
      } catch (cause) {
        if (isAbortFailure(cause) || init.signal?.aborted) {
          throw new ApiError("aborted", "The request was cancelled", { cause });
        }
        if (cause instanceof ApiError) throw cause;
        if (attempt < attempts) {
          await abortableDelay(retryDelayMs, init.signal);
          continue;
        }
        throw new ApiError("network", "The server could not be reached", {
          retryable: true,
          cause,
        });
      }
    }

    throw new ApiError("network", "The server could not be reached", {
      retryable: true,
    });
  };

  return {
    session: async (signal) =>
      parseSession(await request<unknown>("/api/v1/session", { signal }, true)),
    authMethods: (signal) =>
      request<AuthMethods>("/api/v1/auth/methods", { signal }, true),
    login: async (credentials, signal) =>
      parseSession(
        await request<unknown>("/api/v1/auth/login", {
          method: "POST",
          signal,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(credentials),
        }),
      ),
    logout: (csrfToken, signal) =>
      request<void>("/api/v1/auth/logout", {
        method: "POST",
        signal,
        headers: { "X-CSRF-Token": csrfToken },
      }),
    passkeys: async (signal) =>
      parsePasskeyList(
        await request<unknown>("/api/v1/auth/passkeys", { signal }, true),
      ),
    startPasskeyRegistration: async (name, csrfToken, signal) =>
      parsePasskeyChallenge(
        await request<unknown>("/api/v1/auth/passkeys/register/start", {
          method: "POST",
          signal,
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          body: JSON.stringify({ name }),
        }),
        isCreationOptions,
      ) as PasskeyChallenge<PublicKeyCredentialCreationOptionsJSON>,
    finishPasskeyRegistration: async (flowId, credential, csrfToken, signal) =>
      parsePasskey(
        await request<unknown>("/api/v1/auth/passkeys/register/finish", {
          method: "POST",
          signal,
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          body: JSON.stringify({ flowId, credential }),
        }),
      ),
    startPasskeyLogin: async (username) =>
      parsePasskeyChallenge(
        await request<unknown>("/api/v1/auth/passkeys/login/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(username ? { username } : {}),
        }),
        isRequestOptions,
      ) as PasskeyChallenge<PublicKeyCredentialRequestOptionsJSON>,
    finishPasskeyLogin: async (flowId, credential) =>
      parseSession(
        await request<unknown>("/api/v1/auth/passkeys/login/finish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ flowId, credential }),
        }),
      ),
    renamePasskey: async (id, name, csrfToken) => {
      const passkey = parsePasskey(
        await request<unknown>(
          `/api/v1/auth/passkeys/${encodeURIComponent(id)}`,
          {
            method: "PATCH",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrfToken,
            },
            body: JSON.stringify({ name }),
          },
        ),
      );
      if (passkey.id !== id) throw invalidResponse();
      return passkey;
    },
    removePasskey: (id, csrfToken) =>
      request(`/api/v1/auth/passkeys/${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": csrfToken },
      }),
    updateDefaultFolder: async (folder, csrfToken) => {
      if (folder && !isValidVirtualPath(folder.path)) {
        throw new ApiError("invalid-request", "The virtual path is invalid");
      }
      const result = await request<unknown>("/api/v1/preferences", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify({ defaultFolder: folder }),
      });
      if (
        !isRecord(result) ||
        !("defaultFolder" in result) ||
        !isOptionalDefaultFolder(result.defaultFolder)
      ) {
        throw invalidResponse();
      }
      return result.defaultFolder as DefaultFolder | null;
    },
    updatePreferences: async (update, csrfToken) => {
      const result = await request<unknown>("/api/v1/preferences/display", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify(update),
      });
      if (!isUserPreferences(result)) throw invalidResponse();
      return { showHiddenFiles: result.showHiddenFiles, theme: result.theme };
    },
    directory: async (shareId, path, cursor, signal, showHidden = true) => {
      if (!isValidVirtualPath(path)) {
        throw new ApiError("invalid-request", "The virtual path is invalid");
      }
      const query = new URLSearchParams({ path, limit: "100" });
      if (cursor) query.set("cursor", cursor);
      if (!showHidden) query.set("showHidden", "false");
      return parseDirectoryPage(
        await request<unknown>(
          `/api/v1/shares/${encodeURIComponent(shareId)}/directory?${query.toString()}`,
          { signal },
          true,
        ),
        shareId,
        path,
      );
    },
    preview: async (shareId, path, signal) => {
      const url = previewApiUrl(shareId, path);
      return parsePreviewDocument(
        await request<unknown>(url, { signal }, true),
      );
    },
    checkArchive: async (shareId, paths, signal) => {
      const url = archiveUrl(shareId, paths);
      const controller = new AbortController();
      const cancel = () => controller.abort();
      signal?.addEventListener("abort", cancel, { once: true });
      try {
        const response = await fetchImplementation(url, {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) throw await responseError(response);
      } catch (cause) {
        if (cause instanceof ApiError) throw cause;
        if (isAbortFailure(cause) || signal?.aborted) {
          throw new ApiError("aborted", "The request was cancelled", { cause });
        }
        throw new ApiError("network", "The server could not be reached", {
          retryable: true,
          cause,
        });
      } finally {
        signal?.removeEventListener("abort", cancel);
        // Stops an admitted archive's body; the browser downloads it anew.
        controller.abort();
      }
    },
    metadata: async (shareId, path, signal) =>
      parseMetadata(
        await request<unknown>(
          fileApiUrl(shareId, path, "metadata"),
          {
            signal,
          },
          true,
        ),
        shareId,
        path,
      ),
    text: async (shareId, path, signal) =>
      parseTextDocument(
        await request<unknown>(
          fileApiUrl(shareId, path, "text"),
          { signal },
          true,
        ),
        shareId,
        path,
      ),
    createDirectory: async (shareId, path, csrfToken, signal) =>
      parseMutationResult(
        await request<unknown>(shareApiUrl(shareId, "directories"), {
          method: "POST",
          signal,
          headers: mutationJsonHeaders(csrfToken),
          body: JSON.stringify({ path }),
        }),
        shareId,
        path,
      ),
    createFile: async (shareId, path, csrfToken, signal) =>
      parseMutationResult(
        await request<unknown>(shareApiUrl(shareId, "files"), {
          method: "POST",
          signal,
          headers: mutationJsonHeaders(csrfToken),
          body: JSON.stringify({ path }),
        }),
        shareId,
        path,
      ),
    saveText: async (shareId, path, text, etag, csrfToken, signal) =>
      parseMutationResult(
        await request<unknown>(fileApiUrl(shareId, path, "text"), {
          method: "PUT",
          signal,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-CSRF-Token": csrfToken,
            "If-Match": etag,
          },
          body: text,
        }),
        shareId,
        path,
      ),
    moveEntry: async (shareId, source, destination, etag, csrfToken, signal) =>
      parseMutationResult(
        await request<unknown>(shareApiUrl(shareId, "move"), {
          method: "POST",
          signal,
          headers: {
            ...mutationJsonHeaders(csrfToken),
            "If-Match": etag,
          },
          body: JSON.stringify({ source, destination }),
        }),
        shareId,
        destination,
      ),
    deleteEntry: async (shareId, path, etag, csrfToken, signal) =>
      parseTrashResult(
        await request<unknown>(fileApiUrl(shareId, path, "entry"), {
          method: "DELETE",
          signal,
          headers: {
            "X-CSRF-Token": csrfToken,
            "If-Match": etag,
          },
        }),
        shareId,
        path,
      ),
    trash: async (shareId, cursor, signal) => {
      const query = new URLSearchParams({ limit: String(trashPageSize) });
      if (cursor) query.set("cursor", cursor);
      return parseTrashPage(
        await request<unknown>(
          `${shareApiUrl(shareId, "trash")}?${query.toString()}`,
          { signal },
          true,
        ),
        shareId,
      );
    },
    restoreTrash: async (shareId, id, destination, csrfToken, signal) => {
      if (destination !== undefined && !isValidVirtualPath(destination))
        throw new ApiError(
          "invalid-request",
          "The restore destination is invalid",
        );
      await request<unknown>(
        `${shareApiUrl(shareId, "trash")}/${encodeURIComponent(id)}/restore`,
        {
          method: "POST",
          signal,
          headers: mutationJsonHeaders(csrfToken),
          body: JSON.stringify(
            destination === undefined ? {} : { destination },
          ),
        },
      );
    },
    purgeTrash: async (shareId, id, csrfToken, signal) => {
      await request<unknown>(
        `${shareApiUrl(shareId, "trash")}/${encodeURIComponent(id)}`,
        { method: "DELETE", signal, headers: { "X-CSRF-Token": csrfToken } },
      );
    },
    emptyTrash: async (shareId, csrfToken, signal) =>
      parseEmptyTrashResult(
        await request<unknown>(`${shareApiUrl(shareId, "trash")}/empty`, {
          method: "POST",
          signal,
          headers: { "X-CSRF-Token": csrfToken },
        }),
        shareId,
      ),
    uploadFile: (shareId, directory, file, csrfToken, uploadOptions = {}) =>
      uploadWithXhr(
        xhrFactory,
        shareId,
        directory,
        file,
        csrfToken,
        uploadOptions,
      ),
  };
}

function mutationJsonHeaders(csrfToken: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  };
}

function shareApiUrl(shareId: string, action: string): string {
  return `/api/v1/shares/${encodeURIComponent(shareId)}/${action}`;
}

function uploadWithXhr(
  factory: () => XMLHttpRequest,
  shareId: string,
  directory: string,
  file: File,
  csrfToken: string,
  options: UploadOptions,
): Promise<UploadResult> {
  if (!isValidVirtualPath(directory) || !isValidPathComponent(file.name)) {
    return Promise.reject(
      new ApiError("invalid-request", "The upload destination is invalid"),
    );
  }
  if (options.replace && !options.etag) {
    return Promise.reject(
      new ApiError(
        "invalid-request",
        "A validator is required to replace a file",
      ),
    );
  }
  if (options.signal?.aborted) {
    return Promise.reject(new ApiError("aborted", "The request was cancelled"));
  }

  return new Promise((resolve, reject) => {
    const xhr = factory();
    const query = new URLSearchParams({ path: directory });
    if (options.replace) query.set("replace", "true");
    xhr.open("POST", `${shareApiUrl(shareId, "uploads")}?${query}`, true);
    xhr.responseType = "json";
    xhr.withCredentials = true;
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("X-CSRF-Token", csrfToken);
    if (options.etag) xhr.setRequestHeader("If-Match", options.etag);

    const abort = () => xhr.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    const finish = () => options.signal?.removeEventListener("abort", abort);
    xhr.upload.addEventListener("progress", (event) =>
      options.onProgress?.(
        event.loaded,
        event.lengthComputable ? event.total : undefined,
      ),
    );
    xhr.addEventListener("load", () => {
      finish();
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(parseUploadResult(xhr.response, shareId));
        } catch (cause) {
          reject(cause);
        }
      } else {
        reject(xhrResponseError(xhr));
      }
    });
    xhr.addEventListener("error", () => {
      finish();
      reject(
        new ApiError("network", "The server could not be reached", {
          retryable: true,
        }),
      );
    });
    xhr.addEventListener("abort", () => {
      finish();
      reject(new ApiError("aborted", "The request was cancelled"));
    });

    const form = new FormData();
    form.append("file", file, file.name);
    xhr.send(form);
  });
}

const previewLanguages = new Set([
  "c",
  "cpp",
  "css",
  "go",
  "html",
  "java",
  "javascript",
  "json",
  "jsx",
  "kotlin",
  "lua",
  "markdown",
  "php",
  "python",
  "ruby",
  "rust",
  "shell",
  "sql",
  "swift",
  "toml",
  "tsx",
  "typescript",
  "xml",
  "yaml",
]);

const previewKinds = new Set<PreviewKind>([
  "text",
  "code",
  "markdown_source",
  "html_source",
  "image",
  "pdf",
  "audio",
  "video",
  "raw",
  "svg",
]);

/**
 * Kinds that carry no source text: they stream from the open route, or, for
 * RAW, are shown only through the thumbnail route.
 */
const streamedPreviewKinds = new Set<PreviewKind>([
  "image",
  "pdf",
  "audio",
  "video",
  "raw",
]);

export function isStreamedPreviewKind(kind: PreviewKind): boolean {
  return streamedPreviewKinds.has(kind);
}

const maxPreviewBytes = 16 * 1024 * 1024;
/** The server returns at most this head of a file above its preview limit. */
const maxHeadBytes = 64 * 1024;
const maxHeadLines = 1000;

/** Lines in `text`, counting a final line without a line feed. */
export function countLines(text: string): number {
  let lines = 0;
  for (let index = text.indexOf("\n"); index !== -1;) {
    lines += 1;
    index = text.indexOf("\n", index + 1);
  }
  return text === "" || text.endsWith("\n") ? lines : lines + 1;
}

/**
 * A whole document carries no head fields; a head is a text-like source no
 * longer than the server's head bounds, shorter than the file, and exactly
 * as long as its `shownBytes` and `shownLines` say.
 */
function previewHeadIsValid(
  value: Record<string, unknown>,
  streamed: boolean,
): boolean {
  if (value.truncated !== true) {
    return value.shownBytes === undefined && value.shownLines === undefined;
  }
  const { shownBytes, shownLines } = value;
  return (
    !streamed &&
    typeof value.source === "string" &&
    typeof value.size === "number" &&
    typeof shownBytes === "number" &&
    Number.isSafeInteger(shownBytes) &&
    shownBytes >= 0 &&
    shownBytes <= maxHeadBytes &&
    shownBytes < value.size &&
    new TextEncoder().encode(value.source).byteLength === shownBytes &&
    typeof shownLines === "number" &&
    Number.isSafeInteger(shownLines) &&
    shownLines >= 0 &&
    shownLines <= maxHeadLines &&
    countLines(value.source) === shownLines
  );
}

function parsePreviewDocument(value: unknown): PreviewDocument {
  if (!isRecord(value)) throw invalidResponse();
  const language = value.language === null ? undefined : value.language;
  const streamed =
    typeof value.kind === "string" &&
    streamedPreviewKinds.has(value.kind as PreviewKind);
  if (
    typeof value.kind !== "string" ||
    !previewKinds.has(value.kind as PreviewKind) ||
    typeof value.source !== "string" ||
    hasInvalidText(value.source) ||
    typeof value.size !== "number" ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0 ||
    typeof value.truncated !== "boolean" ||
    // Only whole buffered text is bound by the preview limit; streamed kinds
    // are metadata about a file of any size, and a head describes a larger
    // file.
    (!streamed && !value.truncated && value.size > maxPreviewBytes) ||
    (!streamed &&
      !value.truncated &&
      new TextEncoder().encode(value.source).byteLength !== value.size) ||
    !previewHeadIsValid(value, streamed) ||
    (value.openable !== undefined && typeof value.openable !== "boolean") ||
    (value.renderable !== undefined && typeof value.renderable !== "boolean") ||
    // Only HTML renders.
    (value.renderable === true && value.kind !== "html_source") ||
    (value.thumbnailable !== undefined &&
      typeof value.thumbnailable !== "boolean") ||
    // Thumbnails exist only for images and RAW files, and a RAW file is
    // never opened inline and always comes with its thumbnail.
    (value.thumbnailable === true &&
      value.kind !== "image" &&
      value.kind !== "raw") ||
    (value.kind === "raw" &&
      (value.thumbnailable !== true ||
        value.openable === true ||
        value.source !== "")) ||
    (language !== undefined &&
      (typeof language !== "string" || !previewLanguages.has(language))) ||
    !previewLanguageMatchesKind(
      value.kind as PreviewKind,
      language as string | undefined,
    ) ||
    !previewMediaMetadataIsValid(value)
  ) {
    throw invalidResponse();
  }
  return {
    kind: value.kind as PreviewKind,
    source: value.source as string,
    size: value.size as number,
    truncated: value.truncated as boolean,
    ...(typeof value.shownBytes === "number"
      ? { shownBytes: value.shownBytes }
      : {}),
    ...(typeof value.shownLines === "number"
      ? { shownLines: value.shownLines }
      : {}),
    ...(typeof value.openable === "boolean"
      ? { openable: value.openable }
      : {}),
    ...(typeof value.renderable === "boolean"
      ? { renderable: value.renderable }
      : {}),
    ...(typeof value.thumbnailable === "boolean"
      ? { thumbnailable: value.thumbnailable }
      : {}),
    ...(typeof language === "string" ? { language } : {}),
    ...(typeof value.mimeType === "string"
      ? { mimeType: value.mimeType as PreviewMimeType }
      : {}),
    ...(typeof value.width === "number" ? { width: value.width } : {}),
    ...(typeof value.height === "number" ? { height: value.height } : {}),
  };
}

function previewLanguageMatchesKind(
  kind: PreviewKind,
  language: string | undefined,
): boolean {
  if (kind === "html_source") return language === "html";
  if (kind === "markdown_source") return language === "markdown";
  if (kind === "svg") return language === "xml";
  if (kind === "text") return language === undefined;
  if (streamedPreviewKinds.has(kind)) return language === undefined;
  return language !== "html" && language !== "markdown";
}

/** The exact media types the server derives from each kind's signatures. */
const previewMimeTypes: Record<string, ReadonlySet<string>> = {
  image: new Set([
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
  ]),
  pdf: new Set(["application/pdf"]),
  audio: new Set([
    "audio/mp4",
    "audio/ogg",
    "audio/wav",
    "audio/flac",
    "audio/mpeg",
  ]),
  video: new Set(["video/mp4", "video/webm", "video/ogg"]),
};

function previewMediaMetadataIsValid(value: Record<string, unknown>): boolean {
  const mimeTypes = previewMimeTypes[value.kind as string];
  if (mimeTypes === undefined) {
    return (
      value.mimeType === undefined &&
      value.width === undefined &&
      value.height === undefined
    );
  }
  const isImage = value.kind === "image";
  const validDimension = (dimension: unknown) =>
    dimension === undefined ||
    (isImage &&
      typeof dimension === "number" &&
      Number.isSafeInteger(dimension) &&
      dimension > 0);
  return (
    value.source === "" &&
    typeof value.mimeType === "string" &&
    mimeTypes.has(value.mimeType) &&
    validDimension(value.width) &&
    validDimension(value.height)
  );
}

function hasInvalidText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (
      (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) ||
      (code >= 0x7f && code <= 0x9f) ||
      code === 0xfffe ||
      code === 0xffff
    ) {
      return true;
    }
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function previewApiUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "preview");
}

export function htmlPreviewUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "preview/html");
}

export function renderedHtmlPreviewUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "preview/html/rendered");
}

export function imagePreviewUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "preview/image");
}

/**
 * A whole SVG document as `image/svg+xml` under the sandboxed preview CSP,
 * for an `<img>` only.
 */
export function svgPreviewUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "preview/svg");
}

export function directoryEventsUrl(shareId: string, path: string): string {
  if (!isValidVirtualPath(path)) {
    throw new ApiError("invalid-request", "The virtual path is invalid");
  }
  const query = new URLSearchParams({ path });
  return `/api/v1/shares/${encodeURIComponent(shareId)}/events?${query.toString()}`;
}

export function downloadUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "download");
}

/** The most entries one archive request may select (server-enforced too). */
export const maxArchivePaths = 1_000;

/**
 * A ZIP archive. One path names a folder (the empty path is the share root)
 * or a single file; several paths name entries of one folder, each at the
 * archive's top level.
 */
export function archiveUrl(
  shareId: string,
  paths: string | readonly string[],
): string {
  const list = typeof paths === "string" ? [paths] : paths;
  const base = `/api/v1/shares/${encodeURIComponent(shareId)}/archive`;
  if (list.length === 1 && list[0] === "") return base;
  if (list.length === 0 || !list.every(isValidVirtualPath)) {
    throw new ApiError("invalid-request", "The virtual path is invalid");
  }
  const query = new URLSearchParams();
  for (const path of list) query.append("path", path);
  return `${base}?${query.toString()}`;
}

/**
 * The inline view of a file whose signature the server allowlists: images,
 * PDF, audio, video, SVG as a sandboxed image, and text served as
 * `text/plain`.
 */
export function openUrl(shareId: string, path: string): string {
  return fileApiUrl(shareId, path, "open");
}

/**
 * A server-rendered JPEG or PNG no larger than `size` on its long edge, with
 * EXIF orientation applied and no metadata.
 */
export function thumbnailUrl(
  shareId: string,
  path: string,
  size: ThumbnailSize,
): string {
  return `${fileApiUrl(shareId, path, "thumbnail")}&size=${size}`;
}

/**
 * Requests a thumbnail URL that an `<img>` failed to load and reports why:
 * resolves when it now succeeds, and otherwise rejects with the `ApiError`
 * the server answered (`413` too large, `415` unsupported, `429` busy). The
 * page's image policy admits only same-origin URLs, so the image itself is
 * loaded by the element, never through a blob.
 */
export async function thumbnailStatus(
  url: string,
  signal?: AbortSignal,
  fetchImplementation: typeof globalThis.fetch = globalThis.fetch.bind(
    globalThis,
  ),
): Promise<void> {
  let response: Response;
  try {
    response = await fetchImplementation(url, {
      credentials: "same-origin",
      headers: { Accept: "image/jpeg, image/png, application/json" },
      signal,
    });
  } catch (cause) {
    if (isAbortFailure(cause) || signal?.aborted) {
      throw new ApiError("aborted", "The request was cancelled", { cause });
    }
    throw new ApiError("network", "The server could not be reached", {
      retryable: true,
      cause,
    });
  }
  if (!response.ok) throw await responseError(response);
  await response.body?.cancel();
}

function fileApiUrl(shareId: string, path: string, action: string): string {
  if (!isValidVirtualPath(path)) {
    throw new ApiError("invalid-request", "The virtual path is invalid");
  }
  const query = new URLSearchParams({ path });
  return `/api/v1/shares/${encodeURIComponent(shareId)}/${action}?${query.toString()}`;
}

function parseSession(value: unknown): Session {
  if (
    !isRecord(value) ||
    !isRecord(value.user) ||
    typeof value.user.id !== "string" ||
    typeof value.user.username !== "string" ||
    typeof value.user.displayName !== "string" ||
    (value.user.pictureUrl !== undefined &&
      typeof value.user.pictureUrl !== "string") ||
    typeof value.csrfToken !== "string" ||
    (value.version !== undefined && typeof value.version !== "string") ||
    !Array.isArray(value.shares) ||
    !value.shares.every(isShare) ||
    !isOptionalDefaultFolder(value.defaultFolder) ||
    !isUserPreferences(value.preferences)
  ) {
    throw invalidResponse();
  }
  const { pictureUrl, ...user } = value.user as unknown as User;
  const session = { ...value, user } as unknown as Session;
  session.preferences = {
    showHiddenFiles: value.preferences.showHiddenFiles,
    theme: value.preferences.theme,
  };
  // Only avatar hosts allowed by the page CSP are rendered; anything else
  // falls back to no picture rather than attempting a blocked request.
  if (pictureUrl !== undefined && isAllowedPictureUrl(pictureUrl)) {
    session.user.pictureUrl = pictureUrl;
  }
  return session;
}

const pictureHosts = new Set(["lh3.googleusercontent.com", "www.gravatar.com"]);

function isAllowedPictureUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.port === "" &&
      url.username === "" &&
      url.password === "" &&
      pictureHosts.has(url.hostname)
    );
  } catch {
    return false;
  }
}

function parsePasskey(value: unknown): Passkey {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    value.id.length === 0 ||
    typeof value.name !== "string" ||
    !isTimestampSeconds(value.createdAt) ||
    (value.lastUsedAt !== null && !isTimestampSeconds(value.lastUsedAt))
  ) {
    throw invalidResponse();
  }
  return {
    id: value.id,
    name: value.name,
    createdAt: value.createdAt as number,
    lastUsedAt: value.lastUsedAt as number | null,
  };
}

function parsePasskeyList(value: unknown): Passkey[] {
  if (!isRecord(value) || !Array.isArray(value.passkeys)) {
    throw invalidResponse();
  }
  return value.passkeys.map(parsePasskey);
}

function isTimestampSeconds(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function parsePasskeyChallenge(
  value: unknown,
  isOptions: (publicKey: Record<string, unknown>) => boolean,
): PasskeyChallenge<unknown> {
  if (
    !isRecord(value) ||
    typeof value.flowId !== "string" ||
    value.flowId.length === 0 ||
    !isRecord(value.options) ||
    !isRecord(value.options.publicKey) ||
    !isOptions(value.options.publicKey)
  ) {
    throw invalidResponse();
  }
  return {
    flowId: value.flowId,
    options: { publicKey: value.options.publicKey },
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isOptionalCredentialList(value: unknown): boolean {
  return (
    value === undefined ||
    (Array.isArray(value) &&
      value.every(
        (credential) =>
          isRecord(credential) &&
          isNonEmptyString(credential.id) &&
          credential.type === "public-key",
      ))
  );
}

function isRequestOptions(publicKey: Record<string, unknown>): boolean {
  return (
    isNonEmptyString(publicKey.challenge) &&
    isOptionalCredentialList(publicKey.allowCredentials) &&
    (publicKey.rpId === undefined || typeof publicKey.rpId === "string")
  );
}

function isCreationOptions(publicKey: Record<string, unknown>): boolean {
  const { rp, user, pubKeyCredParams } = publicKey;
  return (
    isNonEmptyString(publicKey.challenge) &&
    isRecord(rp) &&
    typeof rp.name === "string" &&
    (rp.id === undefined || typeof rp.id === "string") &&
    isRecord(user) &&
    isNonEmptyString(user.id) &&
    typeof user.name === "string" &&
    typeof user.displayName === "string" &&
    Array.isArray(pubKeyCredParams) &&
    pubKeyCredParams.length > 0 &&
    pubKeyCredParams.every(
      (parameter) =>
        isRecord(parameter) &&
        parameter.type === "public-key" &&
        typeof parameter.alg === "number" &&
        Number.isSafeInteger(parameter.alg),
    ) &&
    isOptionalCredentialList(publicKey.excludeCredentials)
  );
}

/** The API error code sent when an action needs a recent sign-in. */
export const reauthenticationRequiredCode = "reauthentication_required";

/** Raised when a CSRF refresh finds a different account signed in. */
export const accountChangedCode = "account_changed";

/**
 * Runs a CSRF-protected mutation, recovering once from a stale token.
 *
 * Another tab can rotate the session (and with it the CSRF token). A plain
 * `403 forbidden` is then retried once with the token from a fresh session,
 * but only when that session still belongs to the same user. Other 403s,
 * such as a required re-authentication, are never retried.
 */
export async function withCsrfRetry<T>(
  api: Pick<ApiClient, "session">,
  csrfToken: string,
  userId: string,
  onSessionRefreshed: (session: Session) => void,
  mutate: (csrfToken: string) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  try {
    return await mutate(csrfToken);
  } catch (cause) {
    if (
      !(cause instanceof ApiError) ||
      cause.kind !== "forbidden" ||
      (cause.code !== undefined && cause.code !== "forbidden")
    ) {
      throw cause;
    }
    const refreshed = await api.session(signal);
    if (refreshed.user.id !== userId) {
      throw new ApiError("forbidden", "A different account is signed in", {
        status: 403,
        code: accountChangedCode,
      });
    }
    onSessionRefreshed(refreshed);
    return await mutate(refreshed.csrfToken);
  }
}

function isUserPreferences(value: unknown): value is UserPreferences {
  return (
    isRecord(value) &&
    typeof value.showHiddenFiles === "boolean" &&
    (value.theme === "system" ||
      value.theme === "light" ||
      value.theme === "dark")
  );
}

function isOptionalDefaultFolder(value: unknown): boolean {
  return (
    value === undefined ||
    value === null ||
    (isRecord(value) &&
      typeof value.shareId === "string" &&
      typeof value.path === "string" &&
      isValidVirtualPath(value.path))
  );
}

function parseDirectoryPage(
  value: unknown,
  expectedShareId: string,
  expectedPath: string,
): DirectoryPage {
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    value.path !== expectedPath ||
    !isValidVirtualPath(value.path) ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isDirectoryEntry) ||
    (value.nextCursor !== undefined && typeof value.nextCursor !== "string")
  ) {
    throw invalidResponse();
  }
  return value as unknown as DirectoryPage;
}

function parseMetadata(
  value: unknown,
  expectedShareId: string,
  expectedPath: string,
): EntryMetadata {
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    value.path !== expectedPath ||
    !isValidVirtualPath(value.path) ||
    !isValidPathComponent(value.name) ||
    (value.kind !== "directory" && value.kind !== "file") ||
    typeof value.etag !== "string" ||
    value.etag.length === 0 ||
    (value.size !== undefined &&
      (typeof value.size !== "number" ||
        !Number.isSafeInteger(value.size) ||
        value.size < 0)) ||
    !isOptionalTimestamp(value.modifiedAtMs) ||
    !isOptionalTimestamp(value.accessedAtMs) ||
    !isOptionalTimestamp(value.createdAtMs)
  ) {
    throw invalidResponse();
  }
  return value as unknown as EntryMetadata;
}

function isOptionalTimestamp(value: unknown): boolean {
  return (
    value === undefined ||
    (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
  );
}

function parseTextDocument(
  value: unknown,
  expectedShareId: string,
  expectedPath: string,
): TextDocument {
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    value.path !== expectedPath ||
    typeof value.text !== "string" ||
    typeof value.size !== "number" ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0 ||
    typeof value.mimeType !== "string" ||
    typeof value.etag !== "string" ||
    new TextEncoder().encode(value.text).byteLength !== value.size
  ) {
    throw invalidResponse();
  }
  return value as unknown as TextDocument;
}

function parseMutationResult(
  value: unknown,
  expectedShareId: string,
  expectedPath: string,
): MutationResult {
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    value.path !== expectedPath ||
    value.outcome !== "success"
  ) {
    throw invalidResponse();
  }
  return value as unknown as MutationResult;
}

function parseTrashResult(
  value: unknown,
  expectedShareId: string,
  expectedPath: string,
): TrashResult {
  parseMutationResult(value, expectedShareId, expectedPath);
  if (!isRecord(value) || typeof value.trashId !== "string" || !value.trashId)
    throw invalidResponse();
  return value as unknown as TrashResult;
}

function parseEmptyTrashResult(
  value: unknown,
  expectedShareId: string,
): EmptyTrashResult {
  const isCount = (count: unknown) =>
    Number.isInteger(count) && (count as number) >= 0;
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    value.outcome !== "success" ||
    !isCount(value.purged) ||
    !isCount(value.failed) ||
    typeof value.moreRemaining !== "boolean"
  )
    throw invalidResponse();
  return value as unknown as EmptyTrashResult;
}

function parseTrashPage(value: unknown, expectedShareId: string): TrashPage {
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    !Array.isArray(value.items) ||
    !value.items.every(
      (item) =>
        isRecord(item) &&
        typeof item.id === "string" &&
        typeof item.originalPath === "string" &&
        isValidVirtualPath(item.originalPath) &&
        (item.kind === "file" || item.kind === "directory") &&
        typeof item.deletedAt === "string" &&
        typeof item.deletedBy === "string" &&
        typeof item.expiresAt === "string",
    ) ||
    (value.retentionDays !== undefined &&
      !(
        Number.isInteger(value.retentionDays) &&
        (value.retentionDays as number) > 0
      )) ||
    (value.nextCursor !== undefined &&
      (typeof value.nextCursor !== "string" || value.nextCursor.length === 0))
  )
    throw invalidResponse();
  return value as unknown as TrashPage;
}

function parseUploadResult(
  value: unknown,
  expectedShareId: string,
): UploadResult {
  if (
    !isRecord(value) ||
    value.shareId !== expectedShareId ||
    !Array.isArray(value.outcomes) ||
    !value.outcomes.every(
      (outcome) =>
        isRecord(outcome) &&
        isValidVirtualPath(outcome.path) &&
        uploadOutcomeKinds.has(outcome.outcome),
    )
  ) {
    throw invalidResponse();
  }
  return value as unknown as UploadResult;
}

function isShare(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.name === "string" &&
    (value.access === "read" || value.access === "read-write")
  );
}

function isDirectoryEntry(value: unknown): boolean {
  return (
    isRecord(value) &&
    isValidPathComponent(value.name) &&
    (value.kind === "directory" || value.kind === "file") &&
    (value.size === undefined ||
      (typeof value.size === "number" &&
        Number.isFinite(value.size) &&
        value.size >= 0)) &&
    isOptionalTimestamp(value.modifiedAtMs)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalidResponse(): ApiError {
  return new ApiError(
    "invalid-response",
    "The server returned an unexpected response",
  );
}

async function responseError(response: Response): Promise<ApiError> {
  let problem: ApiProblem = {};
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("json")) {
    try {
      const value: unknown = await response.json();
      problem = extractProblem(value);
    } catch {
      // The status code is sufficient; never expose an untrusted response body.
    }
  }

  const status = response.status;
  const kind: ApiErrorKind =
    status === 401
      ? "unauthorized"
      : status === 403
        ? "forbidden"
        : status === 404
          ? "not-found"
          : status === 409
            ? "conflict"
            : status === 429
              ? "rate-limited"
              : "server";
  const retryable =
    status === 429 || status === 502 || status === 503 || status === 504;

  return new ApiError(
    kind,
    problem.message ?? `Request failed with status ${status}`,
    {
      status,
      code: problem.code,
      requestId:
        problem.requestId ?? response.headers.get("x-request-id") ?? undefined,
      retryable,
    },
  );
}

function xhrResponseError(xhr: XMLHttpRequest): ApiError {
  const status = xhr.status;
  const kind: ApiErrorKind =
    status === 401
      ? "unauthorized"
      : status === 403
        ? "forbidden"
        : status === 404
          ? "not-found"
          : status === 409
            ? "conflict"
            : status === 429
              ? "rate-limited"
              : "server";
  const problem = extractProblem(xhr.response);
  return new ApiError(
    kind,
    problem.message ?? `Request failed with status ${status}`,
    {
      status,
      code: problem.code,
      requestId:
        problem.requestId ?? xhr.getResponseHeader("x-request-id") ?? undefined,
      retryable:
        status === 429 || status === 502 || status === 503 || status === 504,
    },
  );
}

function extractProblem(value: unknown): ApiProblem {
  if (!isRecord(value)) return {};
  const candidate = isRecord(value.error) ? value.error : value;
  return {
    code: typeof candidate.code === "string" ? candidate.code : undefined,
    message:
      typeof candidate.message === "string" ? candidate.message : undefined,
    requestId:
      typeof candidate.requestId === "string" ? candidate.requestId : undefined,
  };
}

function isAbortFailure(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function isAutomaticallyRetryable(status: number | undefined): boolean {
  return status === 502 || status === 503 || status === 504;
}

function abortableDelay(
  milliseconds: number,
  signal?: AbortSignal | null,
): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(new ApiError("aborted", "The request was cancelled"));
  }

  return new Promise((resolve, reject) => {
    const finish = () => {
      signal?.removeEventListener("abort", abort);
      resolve();
    };
    const abort = () => {
      window.clearTimeout(timer);
      reject(new ApiError("aborted", "The request was cancelled"));
    };
    const timer = window.setTimeout(finish, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

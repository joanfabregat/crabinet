import { isValidPathComponent, isValidVirtualPath } from "./virtual-path";

export type AccessMode = "read" | "read-write";

export interface User {
  id: string;
  username: string;
  displayName: string;
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
  /** An opaque CSRF value held in memory only. This is not the session ID. */
  csrfToken: string;
}

export interface DefaultFolder {
  shareId: string;
  path: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthMethods {
  passwordEnabled: boolean;
  oidcEnabled: boolean;
}

export interface DirectoryEntry {
  name: string;
  kind: "directory" | "file";
  size?: number;
  modifiedAt?: string;
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

export type UploadOutcomeKind =
  "created" | "replaced" | "conflict" | "quota_exceeded" | "error";

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
  "text" | "code" | "markdown_source" | "html_source" | "image";

export interface PreviewDocument {
  kind: PreviewKind;
  source: string;
  language?: string;
  mimeType?:
    "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/avif";
  width?: number;
  height?: number;
  size: number;
  truncated: boolean;
}

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
  updateDefaultFolder(
    folder: DefaultFolder | null,
    csrfToken: string,
  ): Promise<DefaultFolder | null>;
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
  ): Promise<MutationResult>;
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
      parseMutationResult(
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
]);

const maxPreviewBytes = 16 * 1024 * 1024;

function parsePreviewDocument(value: unknown): PreviewDocument {
  if (!isRecord(value)) throw invalidResponse();
  const language = value.language === null ? undefined : value.language;
  if (
    typeof value.kind !== "string" ||
    !previewKinds.has(value.kind as PreviewKind) ||
    typeof value.source !== "string" ||
    hasInvalidText(value.source) ||
    typeof value.size !== "number" ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0 ||
    value.size > maxPreviewBytes ||
    ((value.kind as PreviewKind) !== "image" &&
      new TextEncoder().encode(value.source).byteLength !== value.size) ||
    typeof value.truncated !== "boolean" ||
    (language !== undefined &&
      (typeof language !== "string" || !previewLanguages.has(language))) ||
    !previewLanguageMatchesKind(
      value.kind as PreviewKind,
      language as string | undefined,
    ) ||
    !previewImageMetadataIsValid(value)
  ) {
    throw invalidResponse();
  }
  return {
    kind: value.kind as PreviewKind,
    source: value.source as string,
    size: value.size as number,
    truncated: value.truncated as boolean,
    ...(typeof language === "string" ? { language } : {}),
    ...(typeof value.mimeType === "string"
      ? { mimeType: value.mimeType as PreviewDocument["mimeType"] }
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
  if (kind === "text") return language === undefined;
  if (kind === "image") return language === undefined;
  return language !== "html" && language !== "markdown";
}

const imageMimeTypes = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/avif",
]);

function previewImageMetadataIsValid(value: Record<string, unknown>): boolean {
  const isImage = value.kind === "image";
  if (!isImage) {
    return (
      value.mimeType === undefined &&
      value.width === undefined &&
      value.height === undefined
    );
  }
  const validDimension = (dimension: unknown) =>
    dimension === undefined ||
    (typeof dimension === "number" &&
      Number.isSafeInteger(dimension) &&
      dimension > 0);
  return (
    value.source === "" &&
    typeof value.mimeType === "string" &&
    imageMimeTypes.has(value.mimeType) &&
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
    typeof value.csrfToken !== "string" ||
    !Array.isArray(value.shares) ||
    !value.shares.every(isShare) ||
    !isOptionalDefaultFolder(value.defaultFolder)
  ) {
    throw invalidResponse();
  }
  return value as unknown as Session;
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
        (outcome.outcome === "created" ||
          outcome.outcome === "replaced" ||
          outcome.outcome === "conflict" ||
          outcome.outcome === "quota_exceeded" ||
          outcome.outcome === "error"),
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
    (value.modifiedAt === undefined || typeof value.modifiedAt === "string")
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

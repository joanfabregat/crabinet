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
  /** An opaque CSRF value held in memory only. This is not the session ID. */
  csrfToken: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
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

export type PreviewKind = "text" | "code" | "markdown_source" | "html_source";

export interface PreviewDocument {
  kind: PreviewKind;
  source: string;
  language?: string;
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
  login(credentials: LoginCredentials, signal?: AbortSignal): Promise<Session>;
  logout(csrfToken: string, signal?: AbortSignal): Promise<void>;
  directory(
    shareId: string,
    path: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<DirectoryPage>;
  preview(
    shareId: string,
    path: string,
    signal?: AbortSignal,
  ): Promise<PreviewDocument>;
}

interface ApiProblem {
  code?: string;
  message?: string;
  requestId?: string;
}

export interface ApiClientOptions {
  fetch?: typeof globalThis.fetch;
  retryDelayMs?: number;
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const fetchImplementation =
    options.fetch ?? globalThis.fetch.bind(globalThis);
  const retryDelayMs = options.retryDelayMs ?? 200;

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
    directory: async (shareId, path, cursor, signal) => {
      if (!isValidVirtualPath(path)) {
        throw new ApiError("invalid-request", "The virtual path is invalid");
      }
      const query = new URLSearchParams({ path, limit: "100" });
      if (cursor) query.set("cursor", cursor);
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
  };
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
    new TextEncoder().encode(value.source).byteLength !== value.size ||
    typeof value.truncated !== "boolean" ||
    (language !== undefined &&
      (typeof language !== "string" || !previewLanguages.has(language))) ||
    !previewLanguageMatchesKind(
      value.kind as PreviewKind,
      language as string | undefined,
    )
  ) {
    throw invalidResponse();
  }
  return {
    kind: value.kind as PreviewKind,
    source: value.source as string,
    size: value.size as number,
    truncated: value.truncated as boolean,
    ...(typeof language === "string" ? { language } : {}),
  };
}

function previewLanguageMatchesKind(
  kind: PreviewKind,
  language: string | undefined,
): boolean {
  if (kind === "html_source") return language === "html";
  if (kind === "markdown_source") return language === "markdown";
  if (kind === "text") return language === undefined;
  return language !== "html" && language !== "markdown";
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
    !value.shares.every(isShare)
  ) {
    throw invalidResponse();
  }
  return value as unknown as Session;
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
      if (isRecord(value)) {
        problem = {
          code: typeof value.code === "string" ? value.code : undefined,
          message:
            typeof value.message === "string" ? value.message : undefined,
          requestId:
            typeof value.requestId === "string" ? value.requestId : undefined,
        };
      }
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

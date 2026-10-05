import type { RefObject } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";

import { ApiError, type ApiClient } from "./api";

/** A folder's size as the Size column shows it. */
export type FolderSizeState =
  | { status: "known"; size: number; complete: boolean }
  /** The size could not be computed; the cell stays empty, as for a file. */
  | { status: "unavailable" };

/**
 * Size requests one listing keeps in flight. The server admits four walks per
 * user at once; two leave room for another tab.
 */
export const folderSizeConcurrency = 2;

/** Attempts for a request refused as busy, spaced by `busyRetryMs`. */
const busyAttempts = 3;
const busyRetryMs = 1_000;

/**
 * The attribute that marks a folder's Size cell, holding the folder name;
 * the listing sets it as `data-folder-size`.
 */
export const folderSizeAttribute = "data-folder-size";

interface Run {
  readonly controller: AbortController;
  /** Folders currently on screen, in the order they appeared. */
  readonly visible: Set<string>;
  /** Folders asked for since the listing was last (re)loaded. */
  readonly requested: Set<string>;
  readonly inFlight: Set<string>;
  readonly attempts: Map<string, number>;
  folders: ReadonlySet<string>;
  stopped: boolean;
}

/**
 * Fetches the sizes of the folders in one listing, in the background and only
 * for folder rows whose Size cell is on screen, so the listing itself never
 * waits for a walk. Cells are found inside `container` by
 * {@link folderSizeAttribute}; a cell that is not displayed (for example a
 * hidden column) never intersects and is never fetched. Without
 * `IntersectionObserver`, every listed folder counts as on screen.
 *
 * At most {@link folderSizeConcurrency} requests run at once. A size, once
 * known, stays on screen while the listing reloads (`revision` changes); the
 * reload asks again for the folders on screen, and the server answers from
 * its cache unless a change invalidated the size. Changing share or folder
 * cancels the requests in flight and starts over.
 */
export function useFolderSizes({
  api,
  shareId,
  path,
  folders,
  enabled,
  revision,
  container,
  onSessionExpired,
}: {
  api: ApiClient;
  shareId: string;
  path: string;
  /** Names of the folders in the listing, in listing order. */
  folders: readonly string[];
  enabled: boolean;
  revision: number;
  container: RefObject<HTMLElement>;
  onSessionExpired: () => void;
}): ReadonlyMap<string, FolderSizeState> {
  const [sizes, setSizes] = useState<ReadonlyMap<string, FolderSizeState>>(
    () => new Map(),
  );
  const run = useRef<Run>();
  const latest = useRef({ api, onSessionExpired });
  latest.current = { api, onSessionExpired };
  const folderKey = folders.join("/");

  const pump = (current: Run) => {
    while (!current.stopped && current.inFlight.size < folderSizeConcurrency) {
      const next = [...current.visible].find(
        (name) =>
          current.folders.has(name) &&
          !current.requested.has(name) &&
          !current.inFlight.has(name),
      );
      if (next === undefined) return;
      fetchSize(current, next);
    }
  };

  const fetchSize = (current: Run, name: string) => {
    current.requested.add(name);
    current.inFlight.add(name);
    const folderPath = path ? `${path}/${name}` : name;
    latest.current.api
      .folderSize(shareId, folderPath, current.controller.signal)
      .then(
        (result) => {
          if (current.stopped) return;
          current.attempts.delete(name);
          setSizes((previous) =>
            new Map(previous).set(name, {
              status: "known",
              size: result.size,
              complete: result.complete,
            }),
          );
        },
        (cause: unknown) => {
          if (current.stopped) return;
          const error = cause instanceof ApiError ? cause : undefined;
          if (error?.kind === "aborted") return;
          if (error?.kind === "unauthorized") {
            current.stopped = true;
            latest.current.onSessionExpired();
            return;
          }
          if (error?.code === "feature_disabled") {
            // Switched off since the session loaded: stop asking.
            current.stopped = true;
          }
          const attempt = (current.attempts.get(name) ?? 0) + 1;
          if (
            !current.stopped &&
            error?.kind === "rate-limited" &&
            attempt < busyAttempts
          ) {
            current.attempts.set(name, attempt);
            window.setTimeout(() => {
              current.requested.delete(name);
              pump(current);
            }, busyRetryMs * attempt);
            return;
          }
          current.attempts.delete(name);
          setSizes((previous) => {
            // A size from before a reload stays rather than disappearing.
            if (previous.get(name)?.status === "known") return previous;
            return new Map(previous).set(name, { status: "unavailable" });
          });
        },
      )
      .finally(() => {
        current.inFlight.delete(name);
        pump(current);
      });
  };

  // A new location starts over.
  useEffect(() => {
    setSizes(new Map());
    if (!enabled) return;
    const current: Run = {
      controller: new AbortController(),
      visible: new Set(),
      requested: new Set(),
      inFlight: new Set(),
      attempts: new Map(),
      folders: new Set(),
      stopped: false,
    };
    run.current = current;
    return () => {
      current.stopped = true;
      current.controller.abort();
      if (run.current === current) run.current = undefined;
    };
  }, [enabled, path, shareId]);

  // A reload asks again for the folders on screen.
  const lastRevision = useRef(revision);
  useEffect(() => {
    if (lastRevision.current === revision) return;
    lastRevision.current = revision;
    const current = run.current;
    if (!current) return;
    current.requested.clear();
    pump(current);
  }, [revision]);

  // Watches the Size cells of the listed folders. `folderKey` stands for
  // `folders`, whose array is new on every render.
  useEffect(() => {
    const current = run.current;
    if (!current) return;
    current.folders = new Set(folders);
    const cells =
      container.current?.querySelectorAll<HTMLElement>(
        `[${folderSizeAttribute}]`,
      ) ?? [];
    if (typeof IntersectionObserver === "undefined") {
      for (const name of folders) current.visible.add(name);
      pump(current);
      return;
    }
    const observer = new IntersectionObserver((changes) => {
      for (const change of changes) {
        const name = change.target.getAttribute(folderSizeAttribute);
        if (name === null) continue;
        if (change.isIntersecting) current.visible.add(name);
        else current.visible.delete(name);
      }
      pump(current);
    });
    for (const cell of cells) observer.observe(cell);
    return () => observer.disconnect();
  }, [folderKey, enabled, path, shareId]);

  return sizes;
}

/**
 * A folder's Size cell: a spinner until the size arrives, then the size, or
 * a lower bound ("≥ 14.0 GB") when the server stopped counting early.
 */
export function FolderSizeValue({
  state,
  format,
}: {
  state: FolderSizeState | undefined;
  format: (size: number) => string;
}) {
  if (state === undefined) {
    return (
      <span
        class="size-spinner"
        role="img"
        aria-label="Calculating size"
        data-testid="folder-size-spinner"
      />
    );
  }
  if (state.status === "unavailable") return null;
  if (state.complete) return <>{format(state.size)}</>;
  return (
    <>
      <span aria-hidden="true">≥ </span>
      <span class="sr-only">At least </span>
      {format(state.size)}
    </>
  );
}

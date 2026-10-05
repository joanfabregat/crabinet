import { render, screen, waitFor } from "@testing-library/preact";
import { useRef } from "preact/hooks";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, type ApiClient, type FolderSize } from "./api";
import {
  FolderSizeValue,
  folderSizeConcurrency,
  useFolderSizes,
} from "./folder-sizes";

interface Pending {
  path: string;
  resolve: (size: number, complete?: boolean) => void;
  reject: (error: ApiError) => void;
}

/** A `folderSize` whose answers the test releases one by one. */
function deferredSizes() {
  const pending: Pending[] = [];
  const folderSize = vi.fn(
    (shareId: string, path: string) =>
      new Promise<FolderSize>((resolve, reject) => {
        pending.push({
          path,
          resolve: (size, complete = true) =>
            resolve({ shareId, path, size, complete }),
          reject,
        });
      }),
  );
  return { folderSize, pending };
}

function Harness({
  folderSize,
  folders,
  enabled = true,
  revision = 0,
}: {
  folderSize: ApiClient["folderSize"];
  folders: string[];
  enabled?: boolean;
  revision?: number;
}) {
  const container = useRef<HTMLDivElement>(null);
  const sizes = useFolderSizes({
    api: { folderSize } as unknown as ApiClient,
    shareId: "docs",
    path: "base",
    folders,
    enabled,
    revision,
    container,
    onSessionExpired: () => undefined,
  });
  return (
    <div ref={container}>
      {folders.map((name) => (
        <span key={name} data-folder-size={name} data-testid={name}>
          <FolderSizeValue
            state={sizes.get(name)}
            format={(size) => `${size} B`}
          />
        </span>
      ))}
    </div>
  );
}

const original = globalThis.IntersectionObserver;

afterEach(() => {
  globalThis.IntersectionObserver = original;
});

/** Replaces IntersectionObserver with one the test drives by hand. */
function controlledObserver() {
  const observed: Element[] = [];
  let notify: IntersectionObserverCallback = () => undefined;
  class FakeObserver {
    constructor(callback: IntersectionObserverCallback) {
      notify = callback;
    }
    observe(element: Element) {
      observed.push(element);
    }
    disconnect() {
      observed.length = 0;
    }
    unobserve() {}
    takeRecords() {
      return [];
    }
  }
  globalThis.IntersectionObserver =
    FakeObserver as unknown as typeof IntersectionObserver;
  return {
    observed,
    show(...names: string[]) {
      notify(
        observed
          .filter((element) =>
            names.includes(element.getAttribute("data-folder-size") ?? ""),
          )
          .map(
            (target) =>
              ({ target, isIntersecting: true }) as IntersectionObserverEntry,
          ),
        {} as IntersectionObserver,
      );
    },
  };
}

describe("folder sizes", () => {
  it("shows a spinner until each size arrives, two requests at a time", async () => {
    const { folderSize, pending } = deferredSizes();
    render(<Harness folderSize={folderSize} folders={["a", "b", "c"]} />);

    expect(
      screen.getAllByRole("img", { name: "Calculating size" }),
    ).toHaveLength(3);
    await waitFor(() =>
      expect(folderSize).toHaveBeenCalledTimes(folderSizeConcurrency),
    );
    expect(pending.map((request) => request.path)).toEqual([
      "base/a",
      "base/b",
    ]);

    pending[0]!.resolve(1_500);
    expect(await screen.findByText("1500 B")).toBeVisible();
    expect(
      screen.getAllByRole("img", { name: "Calculating size" }),
    ).toHaveLength(2);
    await waitFor(() => expect(folderSize).toHaveBeenCalledTimes(3));
    expect(pending[2]!.path).toBe("base/c");
  });

  it("shows a size the server stopped counting as a lower bound", async () => {
    const { folderSize, pending } = deferredSizes();
    render(<Harness folderSize={folderSize} folders={["big"]} />);
    await waitFor(() => expect(pending).toHaveLength(1));
    pending[0]!.resolve(14_000, false);

    const cell = screen.getByTestId("big");
    await waitFor(() => expect(cell).toHaveTextContent("≥ At least 14000 B"));
    expect(cell.querySelector('[aria-hidden="true"]')).toHaveTextContent("≥");
    expect(cell.querySelector(".sr-only")).toHaveTextContent("At least");
  });

  it("leaves the cell empty when a size is unavailable", async () => {
    const { folderSize, pending } = deferredSizes();
    render(<Harness folderSize={folderSize} folders={["gone"]} />);
    await waitFor(() => expect(pending).toHaveLength(1));
    pending[0]!.reject(new ApiError("not-found", "Resource not found"));

    await waitFor(() =>
      expect(
        screen.queryByRole("img", { name: "Calculating size" }),
      ).toBeNull(),
    );
    expect(screen.getByTestId("gone")).toHaveTextContent("");
  });

  it("asks only for folders whose Size cell is on screen", async () => {
    const observer = controlledObserver();
    const { folderSize, pending } = deferredSizes();
    render(<Harness folderSize={folderSize} folders={["a", "b", "c"]} />);
    await waitFor(() => expect(observer.observed).toHaveLength(3));
    expect(folderSize).not.toHaveBeenCalled();

    observer.show("c");
    await waitFor(() => expect(pending).toHaveLength(1));
    expect(pending[0]!.path).toBe("base/c");
  });

  it("keeps a known size on screen while a reload asks again", async () => {
    const { folderSize, pending } = deferredSizes();
    const { rerender } = render(
      <Harness folderSize={folderSize} folders={["a"]} />,
    );
    await waitFor(() => expect(pending).toHaveLength(1));
    pending[0]!.resolve(10);
    expect(await screen.findByText("10 B")).toBeVisible();

    rerender(<Harness folderSize={folderSize} folders={["a"]} revision={1} />);
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(screen.getByText("10 B")).toBeVisible();
    expect(screen.queryByRole("img", { name: "Calculating size" })).toBeNull();
    pending[1]!.resolve(12);
    expect(await screen.findByText("12 B")).toBeVisible();
  });

  it("retries a busy refusal, then gives up", async () => {
    vi.useFakeTimers();
    try {
      const folderSize = vi
        .fn<ApiClient["folderSize"]>()
        .mockRejectedValue(new ApiError("rate-limited", "busy"));
      render(<Harness folderSize={folderSize} folders={["a"]} />);
      await vi.waitFor(() => expect(folderSize).toHaveBeenCalledTimes(1));
      await vi.advanceTimersByTimeAsync(10_000);
      expect(folderSize).toHaveBeenCalledTimes(3);
      expect(
        screen.queryByRole("img", { name: "Calculating size" }),
      ).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("asks for nothing when disabled", () => {
    const { folderSize } = deferredSizes();
    render(<Harness folderSize={folderSize} folders={["a"]} enabled={false} />);
    expect(folderSize).not.toHaveBeenCalled();
  });
});

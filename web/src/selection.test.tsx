import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { ApiError, type DirectoryEntry } from "./api";
import {
  archiveErrorMessage,
  bulkTrashMessage,
  emptySelection,
  moveEntriesToTrash,
  pruneSelection,
  toggleAll,
  toggleSelection,
  useEntrySelection,
  type SelectionState,
} from "./selection";

const order = ["a", "b", "c", "d", "e"];

function names(state: SelectionState): string[] {
  return [...state.names].sort();
}

describe("selection state", () => {
  it("toggles one entry and makes it the anchor", () => {
    const one = toggleSelection(emptySelection, order, "b", false);
    expect(names(one)).toEqual(["b"]);
    expect(one.anchor).toBe("b");
    const none = toggleSelection(one, order, "b", false);
    expect(names(none)).toEqual([]);
    expect(none.anchor).toBe("b");
  });

  it("selects a range forward and backward from the anchor", () => {
    const anchored = toggleSelection(emptySelection, order, "b", false);
    const forward = toggleSelection(anchored, order, "d", true);
    expect(names(forward)).toEqual(["b", "c", "d"]);
    expect(forward.anchor).toBe("d");

    const backward = toggleSelection(
      toggleSelection(emptySelection, order, "d", false),
      order,
      "a",
      true,
    );
    expect(names(backward)).toEqual(["a", "b", "c", "d"]);
  });

  it("deselects a range when the clicked entry was selected", () => {
    const all = toggleAll(emptySelection, order);
    const anchored = toggleSelection(all, order, "b", false);
    const cleared = toggleSelection(anchored, order, "d", true);
    expect(names(cleared)).toEqual(["a", "e"]);
  });

  it("toggles one entry when the anchor is gone or there is none", () => {
    expect(names(toggleSelection(emptySelection, order, "c", true))).toEqual([
      "c",
    ]);
    const stale = { names: new Set<string>(), anchor: "gone" };
    expect(names(toggleSelection(stale, order, "c", true))).toEqual(["c"]);
  });

  it("selects all, and clears when all are selected", () => {
    const all = toggleAll(
      toggleSelection(emptySelection, order, "a", false),
      order,
    );
    expect(names(all)).toEqual(order);
    expect(names(toggleAll(all, order))).toEqual([]);
    expect(names(toggleAll(emptySelection, []))).toEqual([]);
  });

  it("prunes entries that left the listing and keeps unchanged state", () => {
    const state = toggleSelection(
      toggleSelection(emptySelection, order, "a", false),
      order,
      "c",
      false,
    );
    expect(pruneSelection(state, order)).toBe(state);
    const pruned = pruneSelection(state, ["a", "b"]);
    expect(names(pruned)).toEqual(["a"]);
    expect(pruned.anchor).toBeUndefined();
  });
});

function Harness({
  entries,
  location,
}: {
  entries: string[];
  location: string;
}) {
  const { selection, toggle, toggleAll, clear } = useEntrySelection(
    entries,
    location,
  );
  return (
    <div>
      <output>{[...selection.names].sort().join(",") || "none"}</output>
      {entries.map((name) => (
        <button
          key={name}
          type="button"
          onClick={(event) => toggle(name, event.shiftKey)}
        >
          {name}
        </button>
      ))}
      <button type="button" onClick={toggleAll}>
        all
      </button>
      <button type="button" onClick={clear}>
        clear
      </button>
    </div>
  );
}

describe("useEntrySelection", () => {
  it("clears on a new location and drops entries that disappear", () => {
    const { rerender } = render(<Harness entries={order} location="one" />);
    fireEvent.click(screen.getByRole("button", { name: "b" }));
    fireEvent.click(screen.getByRole("button", { name: "d" }), {
      shiftKey: true,
    });
    expect(screen.getByRole("status")).toHaveTextContent("b,c,d");

    // A refresh without "c": it is dropped, and does not come back.
    rerender(<Harness entries={["a", "b", "d", "e"]} location="one" />);
    expect(screen.getByRole("status")).toHaveTextContent("b,d");
    rerender(<Harness entries={order} location="one" />);
    expect(screen.getByRole("status")).toHaveTextContent("b,d");

    rerender(<Harness entries={order} location="two" />);
    expect(screen.getByRole("status")).toHaveTextContent("none");
    rerender(<Harness entries={order} location="one" />);
    expect(screen.getByRole("status")).toHaveTextContent("none");

    fireEvent.click(screen.getByRole("button", { name: "all" }));
    expect(screen.getByRole("status")).toHaveTextContent("a,b,c,d,e");
    fireEvent.click(screen.getByRole("button", { name: "clear" }));
    expect(screen.getByRole("status")).toHaveTextContent("none");
  });
});

describe("bulk moves to Trash", () => {
  const items: Array<{ entry: DirectoryEntry; path: string }> = [
    { entry: { name: "a.txt", kind: "file", size: 1 }, path: "a.txt" },
    { entry: { name: "b.txt", kind: "file", size: 1 }, path: "b.txt" },
    { entry: { name: "c", kind: "directory" }, path: "c" },
  ];

  it("moves each entry in turn and reports partial failures", async () => {
    const moveOne = vi.fn(async (entry: DirectoryEntry) => {
      if (entry.name === "b.txt")
        throw new ApiError("conflict", "changed", { status: 409 });
      return `trash-${entry.name}`;
    });
    const progress = vi.fn();
    const outcome = await moveEntriesToTrash(items, moveOne, progress);
    expect(moveOne).toHaveBeenCalledTimes(3);
    expect(outcome.moved.map((moved) => moved.id)).toEqual([
      "trash-a.txt",
      "trash-c",
    ]);
    expect(outcome.failed.map((failed) => failed.path)).toEqual(["b.txt"]);
    expect(outcome.sessionExpired).toBe(false);
    expect(progress.mock.calls).toEqual([[1], [2], [3]]);
    expect(bulkTrashMessage(outcome, 3)).toBe(
      "Moved 2 of 3 items to Trash. 1 could not be moved.",
    );
  });

  it("stops when the session expires", async () => {
    const moveOne = vi
      .fn()
      .mockResolvedValueOnce("trash-1")
      .mockRejectedValueOnce(new ApiError("unauthorized", "expired"));
    const outcome = await moveEntriesToTrash(items, moveOne);
    expect(moveOne).toHaveBeenCalledTimes(2);
    expect(outcome.moved).toHaveLength(1);
    expect(outcome.failed).toHaveLength(0);
    expect(outcome.sessionExpired).toBe(true);
  });

  it("words complete and failed outcomes", () => {
    expect(
      bulkTrashMessage({ moved: [], failed: [], sessionExpired: false }, 0),
    ).toBe("Moved 0 items to Trash.");
    const one = { id: "t", ...items[0]! };
    expect(
      bulkTrashMessage({ moved: [one], failed: [], sessionExpired: false }, 1),
    ).toBe("Moved 1 item to Trash.");
    expect(
      bulkTrashMessage(
        { moved: [], failed: [items[0]!, items[1]!], sessionExpired: false },
        2,
      ),
    ).toBe("Could not move 2 items to Trash.");
  });
});

describe("archive error messages", () => {
  it("names the folder, or the selection", () => {
    const tooLarge = new ApiError("server", "limit", {
      status: 413,
      code: "too_large",
    });
    expect(archiveErrorMessage(tooLarge, "photos")).toBe(
      "photos is too large or has too many items to download as one ZIP.",
    );
    expect(archiveErrorMessage(tooLarge, undefined)).toBe(
      "The selection is too large or has too many items to download as one ZIP.",
    );
    expect(
      archiveErrorMessage(new ApiError("not-found", "gone"), undefined),
    ).toBe("Some selected items are no longer available.");
    expect(archiveErrorMessage(new Error("network"), undefined)).toBe(
      "Could not download the selection as a ZIP.",
    );
  });
});

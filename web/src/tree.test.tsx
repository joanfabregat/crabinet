import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { type ApiClient, type Share } from "./api";
import type { BrowserNavigation } from "./navigation";
import { ShareTree } from "./tree";

const shares: Share[] = [
  { id: "reference", name: "Reference library", access: "read" },
  { id: "work", name: "Working files", access: "read-write" },
];

const navigation: BrowserNavigation = {
  current: () => ({ shareId: "work", path: "" }),
  go: vi.fn(),
  subscribe: () => () => undefined,
};

function renderTree(activeView?: "trash") {
  const api = {
    directory: vi.fn(async (shareId: string, path: string) => ({
      shareId,
      path,
      entries: [],
    })),
  } as unknown as ApiClient;
  return render(
    <ShareTree
      api={api}
      shares={shares}
      revision={0}
      showHidden={false}
      activeShareId="work"
      activePath=""
      activeView={activeView}
      navigation={navigation}
      onMove={vi.fn()}
      onSessionExpired={vi.fn()}
    />,
  );
}

describe("ShareTree", () => {
  it("marks only read-only shares with a lock", () => {
    renderTree();

    const locks = screen.getAllByRole("img", { name: "Read only" });
    expect(locks).toHaveLength(1);
    expect(locks[0]!.querySelector(".lucide-lock")).not.toBeNull();
    expect(locks[0]!.closest(".tree-row")).toHaveTextContent(
      "Reference library",
    );
    expect(screen.queryByText("RW")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Read and write")).not.toBeInTheDocument();
  });

  it("offers one Trash link for every share, current while viewing Trash", () => {
    const view = renderTree();

    const trash = screen.getByRole("link", { name: "Trash" });
    expect(trash).toHaveAttribute("href", "/trash");
    expect(trash).not.toHaveAttribute("aria-current");
    expect(screen.queryByRole("list", { name: "Trash shares" })).toBeNull();

    view.unmount();
    renderTree("trash");
    expect(screen.getByRole("link", { name: "Trash" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("opens Trash from the current share", () => {
    renderTree();

    fireEvent.click(screen.getByRole("link", { name: "Trash" }));
    expect(navigation.go).toHaveBeenCalledWith({
      shareId: "work",
      path: "",
      view: "trash",
    });
  });
});

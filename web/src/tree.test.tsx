import { render, screen, within } from "@testing-library/preact";
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

  it("keeps the Trash group collapsed while browsing", () => {
    renderTree();

    expect(screen.getByRole("button", { name: "Trash" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });

  it("expands the Trash group while viewing a trash", () => {
    renderTree("trash");

    expect(screen.getByRole("button", { name: "Trash" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    const trashShares = screen.getByRole("list", { name: "Trash shares" });
    expect(
      within(trashShares).getByRole("link", { name: "Working files" }),
    ).toHaveAttribute("aria-current", "page");
  });

  it("expands the Trash group when navigating into a trash", () => {
    const view = renderTree();

    view.rerender(
      <ShareTree
        api={{} as ApiClient}
        shares={shares}
        revision={0}
        showHidden={false}
        activeShareId="work"
        activePath=""
        activeView="trash"
        navigation={navigation}
        onMove={vi.fn()}
        onSessionExpired={vi.fn()}
      />,
    );

    expect(screen.getByRole("button", { name: "Trash" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });
});

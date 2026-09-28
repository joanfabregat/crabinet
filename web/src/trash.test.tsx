import { fireEvent, render, screen, within } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiClient, Share, TrashItem } from "./api";
import { TrashView } from "./trash";

const now = new Date("2026-09-27T12:00:00Z");

const writable: Share = {
  id: "work",
  name: "Working files",
  access: "read-write",
};

function item(overrides: Partial<TrashItem> = {}): TrashItem {
  return {
    id: "deleted-1",
    originalPath: "projects/notes.txt",
    kind: "file",
    deletedAt: "2026-09-27T11:57:00Z",
    deletedBy: "writer",
    expiresAt: "2026-10-27T11:57:00Z",
    ...overrides,
  };
}

function renderTrash(
  trash: ApiClient["trash"],
  share: Share = writable,
): ReturnType<typeof vi.fn> {
  const api = {
    trash: vi.fn(trash),
    restoreTrash: vi.fn(async () => undefined),
    purgeTrash: vi.fn(async () => undefined),
  };
  render(
    <TrashView
      api={api as unknown as ApiClient}
      share={share}
      csrfToken="csrf"
      userId="u-1"
      onSessionExpired={vi.fn()}
      onSessionRefreshed={vi.fn()}
      onChanged={vi.fn()}
    />,
  );
  return api.trash;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(now);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("TrashView", () => {
  it("summarizes each item on one line with relative times and absolute tooltips", async () => {
    renderTrash(async (shareId) => ({
      shareId,
      items: [
        item(),
        item({
          id: "deleted-2",
          originalPath: "root.txt",
          deletedAt: "2026-09-25T12:00:00Z",
          deletedBy: "reader",
          expiresAt: "2026-09-28T12:00:00Z",
        }),
      ],
    }));

    const entries = await screen.findAllByRole("listitem");
    expect(entries).toHaveLength(2);
    const [nested, root] = entries.map(
      (entry) => entry.querySelector(".trash-details .entry-meta") as Element,
    ) as [Element, Element];
    expect(entries[0]?.querySelectorAll(".entry-meta")).toHaveLength(1);
    expect(nested).toHaveTextContent(
      "From projects · Deleted 3 minutes ago by writer · Expires in 30 days",
    );
    expect(root).toHaveTextContent(
      "From Working files · Deleted 2 days ago by reader · Expires tomorrow",
    );

    const absolute = new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
    const [deleted, expires] = Array.from(nested.querySelectorAll("time"));
    expect(deleted).toHaveAttribute("dateTime", "2026-09-27T11:57:00Z");
    expect(deleted).toHaveAttribute(
      "title",
      absolute.format(new Date("2026-09-27T11:57:00Z")),
    );
    expect(expires).toHaveAttribute("dateTime", "2026-10-27T11:57:00Z");
    expect(expires).toHaveAttribute(
      "title",
      absolute.format(new Date("2026-10-27T11:57:00Z")),
    );
  });

  it("shows an unparseable timestamp as sent", async () => {
    renderTrash(async (shareId) => ({
      shareId,
      items: [item({ deletedAt: "yesterday-ish" })],
    }));

    const meta = (await screen.findByRole("listitem")).querySelector(
      ".entry-meta",
    );
    expect(meta).toHaveTextContent("Deleted yesterday-ish by writer");
    expect(meta?.querySelectorAll("time")).toHaveLength(1);
  });

  it("labels Empty Trash as a danger button and hides it without write access", async () => {
    renderTrash(async (shareId) => ({ shareId, items: [item()] }));

    const empty = await screen.findByRole("button", { name: "Empty Trash" });
    expect(empty).toHaveTextContent("Empty Trash");
    expect(empty).toHaveClass("button", "button-danger");
    expect(empty).not.toHaveAttribute("aria-label");
    fireEvent.click(empty);
    expect(
      screen.getByRole("dialog", { name: "Empty Working files Trash?" }),
    ).toBeVisible();
  });

  it("omits Empty Trash for read-only shares", async () => {
    renderTrash(async (shareId) => ({ shareId, items: [item()] }), {
      ...writable,
      access: "read",
    });

    await screen.findByRole("listitem");
    expect(screen.queryByRole("button", { name: "Empty Trash" })).toBeNull();
  });

  it("always offers Refresh in the header and reloads the list", async () => {
    let items = [item()];
    const trash = renderTrash(async (shareId) => ({ shareId, items }));

    await screen.findByRole("listitem");
    const heading = screen
      .getByRole("heading", { name: "Trash" })
      .closest(".directory-heading") as HTMLElement;
    const refresh = within(heading).getByRole("button", {
      name: "Refresh Trash",
    });
    expect(refresh).toHaveAttribute("data-tooltip", "Refresh Trash");
    expect(screen.queryByRole("alert")).toBeNull();

    items = [];
    fireEvent.click(refresh);
    expect(await screen.findByText("Trash is empty.")).toBeVisible();
    expect(trash).toHaveBeenCalledTimes(2);
    expect(
      within(heading).getByRole("button", { name: "Refresh Trash" }),
    ).toBeEnabled();
  });

  it("keeps Refresh available after a load error and recovers with it", async () => {
    let fail = true;
    renderTrash(async (shareId) => {
      if (fail) throw new Error("offline");
      return { shareId, items: [item()] };
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load Trash. Try again.",
    );
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Refresh Trash" }));
    expect(await screen.findByText("notes.txt")).toBeVisible();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

import { fireEvent, render, screen, within } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiClient, Share, TrashItem } from "./api";
import { ToastProvider } from "./toast";
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
  shares: Share[] = [writable],
): ReturnType<typeof vi.fn> {
  const api = {
    trash: vi.fn(trash),
    restoreTrash: vi.fn(async () => undefined),
    purgeTrash: vi.fn(async () => undefined),
  };
  render(
    <TrashView
      api={api as unknown as ApiClient}
      shares={shares}
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

  it("lists every share's Trash in one list under a divider per share", async () => {
    const reference: Share = {
      id: "ref",
      name: "Reference",
      access: "read",
    };
    const empty: Share = { id: "empty", name: "Empty", access: "read-write" };
    renderTrash(
      async (shareId) => ({
        shareId,
        items:
          shareId === "work"
            ? [item()]
            : shareId === "ref"
              ? [item({ id: "deleted-9", originalPath: "manual.pdf" })]
              : [],
      }),
      [writable, reference, empty],
    );

    const work = await screen.findByRole("region", { name: /Working files/ });
    expect(within(work).getByText("notes.txt")).toBeVisible();
    expect(
      within(work).getByRole("button", { name: "Restore notes.txt" }),
    ).toBeVisible();
    const ref = screen.getByRole("region", { name: /Reference/ });
    expect(within(ref).getByText("manual.pdf")).toBeVisible();
    // Read-only shares list their items without actions.
    expect(within(ref).queryByRole("button")).toBeNull();
    // A share with an empty Trash gets no divider.
    expect(screen.queryByRole("region", { name: /Empty/ })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Empty Trash" }));
    expect(
      screen.getByRole("dialog", { name: "Empty Trash?" }),
    ).toHaveTextContent("Permanently delete 1 item from Trash?");
  });

  it("states the retention period and counts items after an em dash", async () => {
    renderTrash(async (shareId) => ({
      shareId,
      items: [item()],
      retentionDays: 14,
    }));

    const title = await screen.findByRole("heading", {
      name: /Working files/,
    });
    expect(title).toHaveTextContent("Working files — 1 item");
    expect(title.querySelector(".trash-group-count")).toHaveTextContent(
      "— 1 item",
    );
    expect(
      screen.getByText(/Deleted items remain here for 14 days\./),
    ).toBeVisible();
  });

  it("offers Undo after a restore, moving the item back to Trash", async () => {
    const deleteEntry = vi.fn(async (shareId: string, path: string) => ({
      shareId,
      path,
      outcome: "success",
      trashId: "deleted-2",
    }));
    const metadata = vi.fn(async (shareId: string, path: string) => ({
      shareId,
      path,
      name: "notes.txt",
      kind: "file",
      etag: 'W/"restored"',
    }));
    const api = {
      trash: vi.fn(async (shareId: string) => ({ shareId, items: [item()] })),
      restoreTrash: vi.fn(async () => undefined),
      purgeTrash: vi.fn(async () => undefined),
      metadata,
      deleteEntry,
    };
    render(
      <ToastProvider>
        <TrashView
          api={api as unknown as ApiClient}
          shares={[writable]}
          csrfToken="csrf"
          userId="u-1"
          onSessionExpired={vi.fn()}
          onSessionRefreshed={vi.fn()}
          onChanged={vi.fn()}
        />
      </ToastProvider>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Restore notes.txt" }),
    );
    expect(await screen.findByText("Restored notes.txt.")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(
      await screen.findByText("Moved notes.txt back to Trash."),
    ).toBeVisible();
    expect(metadata).toHaveBeenCalledWith("work", "projects/notes.txt");
    expect(deleteEntry).toHaveBeenCalledWith(
      "work",
      "projects/notes.txt",
      'W/"restored"',
      "csrf",
    );
  });

  it("shows a friendly empty state when no share has deleted items", async () => {
    renderTrash(async (shareId) => ({ shareId, items: [] }));

    const empty = await screen.findByRole("heading", {
      name: "Trash is empty.",
    });
    expect(empty.closest(".trash-empty")).toHaveTextContent(
      "Deleted files and folders appear here",
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
    expect(screen.getByRole("dialog", { name: "Empty Trash?" })).toBeVisible();
  });

  it("omits Empty Trash for read-only shares", async () => {
    renderTrash(
      async (shareId) => ({ shareId, items: [item()] }),
      [{ ...writable, access: "read" }],
    );

    await screen.findByRole("listitem");
    expect(screen.queryByRole("button", { name: "Empty Trash" })).toBeNull();
  });

  it("has no Refresh button in the header", async () => {
    renderTrash(async (shareId) => ({ shareId, items: [item()] }));

    await screen.findByRole("listitem");
    const heading = screen
      .getByRole("heading", { name: "Trash" })
      .closest(".directory-heading") as HTMLElement;
    expect(
      within(heading).queryByRole("button", { name: /refresh/i }),
    ).toBeNull();
  });

  it("recovers from a load error with Try again", async () => {
    let fail = true;
    renderTrash(async (shareId) => {
      if (fail) throw new Error("offline");
      return { shareId, items: [item()] };
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load Trash.",
    );
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("notes.txt")).toBeVisible();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

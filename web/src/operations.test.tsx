import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { type ApiClient, type DirectoryPage } from "./api";
import {
  EntryActionButtons,
  OperationDialog,
  type EntryOperation,
} from "./operations";

const pages: Record<string, DirectoryPage> = {
  "": {
    shareId: "work",
    path: "",
    entries: [
      { name: "projects", kind: "directory" },
      { name: "archive", kind: "directory" },
    ],
  },
  projects: {
    shareId: "work",
    path: "projects",
    entries: [{ name: "notes.txt", kind: "file", size: 5 }],
  },
  archive: { shareId: "work", path: "archive", entries: [] },
};

function fakeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  // Only the calls these dialogs make are provided.
  return {
    directory: vi.fn(async (_shareId: string, path: string) => pages[path]!),
    metadata: vi.fn(async (shareId: string, path: string) => ({
      shareId,
      path,
      name: path.split("/").at(-1)!,
      kind: "file" as const,
      etag: 'W/"test"',
    })),
    createFile: vi.fn(),
    createDirectory: vi.fn(),
    moveEntry: vi.fn(),
    ...overrides,
  } as unknown as ApiClient;
}

function renderDialog(
  operation: EntryOperation,
  extra: { api?: ApiClient; shareName?: string } = {},
) {
  return render(
    <OperationDialog
      api={extra.api ?? fakeApi()}
      csrfToken="csrf"
      operation={operation}
      directory="projects"
      shareId="work"
      shareName={extra.shareName}
      userId="joan"
      onClose={vi.fn()}
      onChanged={vi.fn()}
      onSessionExpired={vi.fn()}
      onSessionRefreshed={vi.fn()}
    />,
  );
}

const moveNotes: EntryOperation = {
  kind: "move",
  entry: { name: "notes.txt", kind: "file" },
  path: "projects/notes.txt",
};

describe("OperationDialog", () => {
  it("labels the create submit button Create", () => {
    renderDialog({ kind: "create-folder" });

    expect(screen.getByRole("button", { name: "Create" })).toBeEnabled();
    expect(
      screen.queryByRole("button", { name: "Confirm" }),
    ).not.toBeInTheDocument();
  });

  it("labels the rename submit button Rename", async () => {
    renderDialog({
      kind: "rename",
      entry: { name: "notes.txt", kind: "file" },
      path: "projects/notes.txt",
    });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Rename" })).toBeEnabled(),
    );
  });

  it("uses an icon close button inside a non-landmark header", () => {
    renderDialog({ kind: "create-file" });

    const close = screen.getByRole("button", { name: "Close Create file" });
    expect(close.querySelector(".lucide-x")).not.toBeNull();
    expect(close).not.toHaveTextContent("×");
    expect(screen.queryByRole("banner")).not.toBeInTheDocument();
  });

  it("opens the move dialog with a neutral hint and a disabled Move button", async () => {
    renderDialog(moveNotes);

    const dialog = screen.getByRole("dialog", { name: "Move notes.txt" });
    expect(
      within(dialog).getByText("Select a destination folder to continue."),
    ).toBeVisible();
    expect(
      within(dialog).queryByText(
        "Choose a different folder outside this item.",
      ),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", { name: "Move here" }),
    ).toBeDisabled();

    fireEvent.click(
      await within(dialog).findByRole("button", { name: "archive" }),
    );
    await waitFor(() =>
      expect(
        within(dialog).getByRole("button", { name: "Move here" }),
      ).toBeEnabled(),
    );
    expect(within(dialog).getByText("archive/notes.txt")).toBeVisible();
  });

  it("reports an error only after the person picks an invalid folder", async () => {
    renderDialog({
      kind: "move",
      entry: { name: "projects", kind: "directory" },
      path: "projects",
    });

    const dialog = screen.getByRole("dialog", { name: "Move projects" });
    fireEvent.click(
      await within(dialog).findByRole("button", { name: "projects" }),
    );
    expect(
      within(dialog).getByText("Choose a different folder outside this item."),
    ).toBeVisible();
    expect(
      within(dialog).getByRole("button", { name: "Move here" }),
    ).toBeDisabled();
  });

  it("names the picker root after the share and marks the selected folder", async () => {
    renderDialog(moveNotes, { shareName: "Working files" });

    const dialog = screen.getByRole("dialog", { name: "Move notes.txt" });
    const root = within(dialog).getByRole("button", { name: "Working files" });
    expect(root).toHaveAttribute("aria-pressed", "false");
    expect(
      await within(dialog).findByRole("button", { name: "projects" }),
    ).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(root);
    expect(root).toHaveAttribute("aria-pressed", "true");
    const picker = within(dialog).getByRole("group", {
      name: "Destination folder",
    });
    expect(picker.querySelector(".lucide-folder-plus")).toBeNull();
    expect(picker.querySelector(".lucide-folder")).not.toBeNull();
  });

  it("falls back to a generic picker root label without a share name", () => {
    renderDialog(moveNotes);

    expect(
      screen.getByRole("button", { name: "Shared folder" }),
    ).toBeInTheDocument();
  });
});

describe("row action menu", () => {
  const entry = { name: "notes.txt", kind: "file" as const, size: 5 };

  it("lists the row's actions and closes with Escape back on its button", async () => {
    const onOperation = vi.fn();
    render(
      <EntryActionButtons
        entry={entry}
        path="projects/notes.txt"
        copyPath="work/projects/notes.txt"
        download={{ href: "/download/notes.txt" }}
        writable
        onOperation={onOperation}
      />,
    );
    const trigger = screen.getByRole("button", {
      name: "More actions for notes.txt",
    });
    expect(trigger).toHaveAttribute("aria-haspopup", "menu");
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    const menu = screen.getByRole("menu", { name: "Actions for notes.txt" });
    const items = within(menu).getAllByRole("menuitem");
    expect(items.map((item) => item.textContent)).toEqual([
      "Download",
      "Copy full path",
      "Rename",
      "Move to…",
      "Move to Trash",
    ]);
    await waitFor(() => expect(items[0]).toHaveFocus());
    fireEvent.keyDown(menu, { key: "ArrowUp" });
    expect(items[4]).toHaveFocus();

    fireEvent.keyDown(menu, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(trigger).toHaveFocus();
    expect(onOperation).not.toHaveBeenCalled();
  });

  it("runs the chosen action and offers only copying on a read-only share", () => {
    const onOperation = vi.fn();
    const { rerender } = render(
      <EntryActionButtons
        entry={entry}
        path="projects/notes.txt"
        copyPath="work/projects/notes.txt"
        download={{ href: "/download/notes.txt" }}
        writable
        onOperation={onOperation}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "More actions for notes.txt" }),
    );
    fireEvent.click(screen.getByRole("menuitem", { name: "Rename" }));
    expect(onOperation).toHaveBeenCalledWith({
      kind: "rename",
      entry,
      path: "projects/notes.txt",
    });
    expect(screen.queryByRole("menu")).toBeNull();

    rerender(
      <EntryActionButtons
        entry={entry}
        path="projects/notes.txt"
        copyPath="work/projects/notes.txt"
        download={{ href: "/download/notes.txt" }}
        writable={false}
        onOperation={onOperation}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "More actions for notes.txt" }),
    );
    expect(
      within(screen.getByRole("menu")).getAllByRole("menuitem"),
    ).toHaveLength(2);
  });
});

describe("row downloads", () => {
  it("downloads a file directly with any grant", () => {
    render(
      <EntryActionButtons
        entry={{ name: "notes.txt", kind: "file", size: 5 }}
        path="projects/notes.txt"
        copyPath="work/projects/notes.txt"
        download={{ href: "/download/notes.txt" }}
        writable={false}
        onOperation={vi.fn()}
      />,
    );
    const link = screen.getByRole("link", { name: "Download notes.txt" });
    expect(link).toHaveAttribute("href", "/download/notes.txt");
    expect(link).toHaveAttribute("data-tooltip", "Download");
    // A plain link: the browser follows it to the attachment.
    expect(fireEvent.click(link)).toBe(true);
    fireEvent.click(
      screen.getByRole("button", { name: "More actions for notes.txt" }),
    );
    expect(
      screen.getByRole("menuitem", { name: "Download notes.txt" }),
    ).toHaveAttribute("href", "/download/notes.txt");
  });

  it("checks a folder's ZIP before downloading it, from the row and the menu", () => {
    const onArchive = vi.fn();
    render(
      <EntryActionButtons
        entry={{ name: "photos", kind: "directory" }}
        path="photos"
        copyPath="work/photos"
        download={{ href: "/archive/photos", onArchive }}
        writable={false}
        onOperation={vi.fn()}
      />,
    );
    const link = screen.getByRole("link", { name: "Download photos as ZIP" });
    expect(link).toHaveAttribute("href", "/archive/photos");
    expect(link).toHaveAttribute("data-tooltip", "Download as ZIP");
    expect(fireEvent.click(link)).toBe(false);
    expect(onArchive).toHaveBeenCalledTimes(1);
    // A modified click keeps the browser's own link behavior.
    expect(fireEvent.click(link, { ctrlKey: true })).toBe(true);
    expect(onArchive).toHaveBeenCalledTimes(1);

    fireEvent.click(
      screen.getByRole("button", { name: "More actions for photos" }),
    );
    const item = screen.getByRole("menuitem", {
      name: "Download photos as ZIP",
    });
    expect(item).toHaveTextContent("Download as ZIP");
    fireEvent.click(item);
    expect(onArchive).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

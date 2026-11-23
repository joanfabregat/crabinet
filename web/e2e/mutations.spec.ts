import { readFile } from "node:fs/promises";

import { expect, test, type Locator, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import {
  chooseFiles,
  csrfToken,
  dropFiles,
  openSignedIn,
  ownsServerState,
} from "./helpers";

test.describe("writable share operations", () => {
  test.beforeEach(({ page }, testInfo) => {
    void page;
    test.skip(
      !ownsServerState(testInfo),
      "mutation state is exercised once per engine, in its desktop project",
    );
  });

  test("changes permissions from the expanded preview with a fresh validator", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await directoryListing(page)
      .getByRole("link", { name: "README.md", exact: true })
      .click();
    await page.getByRole("button", { name: "Expand preview" }).click();
    const edit = page.getByRole("button", {
      name: "Change permissions for README.md",
    });
    await edit.click();
    const dialog = page.getByRole("dialog", {
      name: "Permissions for README.md",
      exact: true,
    });
    const input = dialog.getByLabel("Octal permissions");
    await expect(input).toBeFocused();
    const before = await input.inputValue();
    const mode = before === "0600" ? "0640" : "0600";
    await input.fill(mode);
    await dialog.getByRole("button", { name: "Save permissions" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(
      page.getByText("Permissions updated.", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("dialog", { name: "README.md", exact: true }),
    ).toBeVisible();
    const response = await page.request.get(
      "/api/v1/shares/writable/metadata?path=README.md",
    );
    expect(await response.json()).toMatchObject({ mode });
  });

  test("edits above an expanded preview and returns focus without collapsing it", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await directoryListing(page)
      .getByRole("link", { name: "README.md", exact: true })
      .click();
    await page.getByRole("button", { name: "Expand preview" }).click();
    const preview = page.getByRole("dialog", {
      name: "README.md",
      exact: true,
    });
    const edit = preview.getByRole("button", { name: "Edit README.md" });
    await edit.click();

    const dialog = page.getByRole("dialog", { name: "Edit README.md" });
    const editor = dialog.getByLabel("UTF-8 text content");
    await expect(editor).toBeFocused();
    // A real click catches the editor being covered by the preview/backdrop.
    await editor.click();
    const close = dialog.getByRole("button", { name: "Close", exact: true });
    await close.focus();
    await page.keyboard.press("Tab");
    await expect(
      dialog.getByRole("button", { name: "Close Edit README.md" }),
    ).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(preview).toBeVisible();
    await expect(edit).toBeFocused();
    await expect(page).toHaveURL(/view=full/);
  });

  test("creates, edits, moves, trashes, and restores without crossing shares or overwriting", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");

    await createEntry(page, "New folder", "Folder name", "e2e-folder");
    const folderMetadata = await page.request.get(
      "/api/v1/shares/writable/metadata?path=e2e-folder",
    );
    expect(folderMetadata.ok()).toBe(true);
    expect(await folderMetadata.json()).toMatchObject({ mode: "0700" });
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-folder",
        exact: true,
      }),
    ).toBeVisible();

    await createEntry(page, "New file", "File name", "e2e-note.txt");
    const fileMetadata = await page.request.get(
      "/api/v1/shares/writable/metadata?path=e2e-note.txt",
    );
    expect(fileMetadata.ok()).toBe(true);
    expect(await fileMetadata.json()).toMatchObject({ mode: "0600" });
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-note.txt",
        exact: true,
      }),
    ).toBeVisible();

    await directoryListing(page)
      .getByRole("link", { name: "e2e-note.txt", exact: true })
      .click();
    await page.getByRole("button", { name: "Edit e2e-note.txt" }).click();
    const editor = page.getByLabel("UTF-8 text content");
    await expect(editor).toBeFocused();
    await editor.fill("Production-backed browser edit\n");
    await expect(page.getByText("Unsaved changes")).toBeVisible();
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Saved e2e-note.txt.")).toBeVisible();
    await expect(editor).toBeFocused();
    await page.getByRole("button", { name: "Close", exact: true }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);

    const saved = await readText(page, "writable", "e2e-note.txt");
    expect(saved).toBe("Production-backed browser edit\n");
    const savedMetadata = await page.request.get(
      "/api/v1/shares/writable/metadata?path=e2e-note.txt",
    );
    expect(await savedMetadata.json()).toMatchObject({ mode: "0600" });

    await previewAction(page, "e2e-note.txt", "Move").click();
    const moveDialog = page.getByRole("dialog", { name: "Move e2e-note.txt" });
    await moveDialog
      .getByRole("button", { name: "e2e-folder", exact: true })
      .click();
    await moveDialog.getByRole("button", { name: "Move here" }).click();
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-note.txt",
        exact: true,
      }),
    ).toHaveCount(0);

    await directoryListing(page)
      .getByRole("link", { name: "e2e-folder", exact: true })
      .click();
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-note.txt",
        exact: true,
      }),
    ).toBeVisible();

    await directoryListing(page)
      .getByRole("link", { name: "e2e-note.txt", exact: true })
      .click();
    await previewAction(page, "e2e-note.txt", "Rename").click();
    const renameDialog = page.getByRole("dialog", {
      name: "Rename e2e-note.txt",
    });
    await renameDialog.getByLabel("New name").fill("note-renamed.md");
    await renameDialog
      .getByRole("button", { name: "Rename", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "note-renamed.md" }),
    ).toBeVisible();
    await expect(page.getByRole("tab", { name: "Readable" })).toBeVisible();
    await expect(page).toHaveURL(/e2e-folder(\/|%2F)note-renamed\.md/);

    const originalDestination = await readText(
      page,
      "writable",
      "Projects/example.toml",
    );
    await previewAction(page, "note-renamed.md", "Rename").click();
    const targetNameDialog = page.getByRole("dialog", {
      name: "Rename note-renamed.md",
    });
    await targetNameDialog.getByLabel("New name").fill("example.toml");
    await targetNameDialog
      .getByRole("button", { name: "Rename", exact: true })
      .click();
    await previewAction(page, "example.toml", "Move").click();
    const overwriteDialog = page.getByRole("dialog", {
      name: "Move example.toml",
    });
    await overwriteDialog
      .getByRole("button", { name: "Projects", exact: true })
      .click();
    await overwriteDialog.getByRole("button", { name: "Move here" }).click();
    await expect(overwriteDialog.getByRole("alert")).toContainText(
      "destination already exists",
    );
    expect(await readText(page, "writable", "Projects/example.toml")).toBe(
      originalDestination,
    );
    expect(await readText(page, "writable", "e2e-folder/example.toml")).toBe(
      "Production-backed browser edit\n",
    );
    await overwriteDialog.getByRole("button", { name: "Cancel" }).click();

    await directoryListing(page)
      .getByRole("link", { name: "example.toml", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "example.toml" }),
    ).toBeVisible();
    await previewAction(page, "example.toml", "Delete").click();
    await page
      .getByRole("dialog", { name: "Delete example.toml?" })
      .getByRole("button", { name: "Move to Trash" })
      .click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByText("Moved example.toml to Trash.")).toBeVisible();
    await expect(
      directoryListing(page).getByRole("link", {
        name: "example.toml",
        exact: true,
      }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("heading", { name: "example.toml" }),
    ).toHaveCount(0);
    await expect(page).not.toHaveURL(/preview=|example\.toml/);

    await page.goto("/trash");
    const deletedFile = page.getByRole("listitem").filter({
      has: page.getByText("example.toml", { exact: true }),
      hasText: "From e2e-folder ·",
    });
    await expect(deletedFile).toBeVisible();
    await deletedFile.getByRole("button", { name: "Restore" }).click();
    await expect(deletedFile).toHaveCount(0);

    await page.goto("/writable");
    await entryAction(page, "e2e-folder", "Delete").click();
    await page
      .getByRole("dialog", { name: "Delete e2e-folder?" })
      .getByRole("button", { name: "Move to Trash" })
      .click();
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-folder",
        exact: true,
      }),
    ).toHaveCount(0);

    await page.goto("/trash");
    const deletedFolder = page.getByRole("listitem").filter({
      has: page.getByText("e2e-folder", { exact: true }),
      hasText: "From Working files ·",
    });
    await expect(deletedFolder).toBeVisible();
    // Everything fits on the first page, so there is nothing more to load.
    await expect(page.getByRole("button", { name: /^Load more/ })).toHaveCount(
      0,
    );
    // The Trash API pages with an opaque cursor and rejects an altered one.
    const firstPage = await page.request.get(
      "/api/v1/shares/writable/trash?limit=1",
    );
    expect(firstPage.status()).toBe(200);
    const first = (await firstPage.json()) as {
      items: { id: string }[];
      nextCursor?: string;
    };
    expect(first.items).toHaveLength(1);
    if (first.nextCursor) {
      const next = await page.request.get(
        `/api/v1/shares/writable/trash?limit=1&cursor=${encodeURIComponent(first.nextCursor)}`,
      );
      expect(next.status()).toBe(200);
      const nextItems = ((await next.json()) as { items: { id: string }[] })
        .items;
      expect(nextItems.map((item) => item.id)).not.toContain(
        first.items[0]!.id,
      );
    }
    const forged = await page.request.get(
      "/api/v1/shares/writable/trash?limit=1&cursor=AQ",
    );
    expect(forged.status()).toBe(409);
    await deletedFolder.getByRole("button", { name: "Restore" }).click();
    await expect(deletedFolder).toHaveCount(0);
    await page.goto("/writable");
    await expect(
      directoryListing(page).getByRole("link", {
        name: "Projects",
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-folder",
        exact: true,
      }),
    ).toBeVisible();

    const readOnlyLeak = await page.request.get(
      "/api/v1/shares/read-only/metadata?path=e2e-note.txt",
    );
    expect(readOnlyLeak.status()).toBe(404);
  });

  test("detects a concurrent text edit and preserves the winning version", async ({
    context,
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    const competingPage = await context.newPage();
    await competingPage.goto("/writable");
    await expect(
      competingPage.getByLabel("Shared folders", { exact: true }),
    ).toBeVisible();

    await page.getByRole("link", { name: "README.md", exact: true }).click();
    await page.getByRole("button", { name: "Edit README.md" }).click();
    await expect(page.getByLabel("UTF-8 text content")).toBeFocused();
    await competingPage
      .getByRole("link", { name: "README.md", exact: true })
      .click();
    await competingPage.getByRole("button", { name: "Edit README.md" }).click();
    await expect(competingPage.getByLabel("UTF-8 text content")).toBeFocused();

    const winningText = "Saved by the first browser\n";
    await page.getByLabel("UTF-8 text content").fill(winningText);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Saved README.md.")).toBeVisible();
    await page.getByRole("button", { name: "Close", exact: true }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);

    const losingEditor = competingPage.getByLabel("UTF-8 text content");
    const losingText = "Stale second-browser edit\n";
    await losingEditor.fill(losingText);
    await competingPage.getByRole("button", { name: "Save" }).click();
    const conflict = competingPage.getByRole("alert");
    await expect(conflict).toContainText("changed after you opened it");
    await expect(losingEditor).toBeEnabled();
    await expect(losingEditor).toHaveValue(losingText);
    await expect(
      competingPage.getByRole("button", { name: "Save" }),
    ).toBeDisabled();
    expect(await readText(page, "writable", "README.md")).toBe(winningText);

    competingPage.once("dialog", (dialog) => dialog.accept());
    await conflict
      .getByRole("button", { name: "Reload latest version" })
      .click();
    await expect(losingEditor).toHaveValue(winningText);
    await expect(losingEditor).toBeEnabled();
    await competingPage
      .getByRole("button", { name: "Close", exact: true })
      .click();
  });

  test("refreshes the current directory after an out-of-band filesystem mutation", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await expect(
      page.getByRole("link", { name: "README.md", exact: true }),
    ).toBeVisible();
    await page.waitForTimeout(500);

    const token = await csrfToken(page);
    const origin = new URL(page.url()).origin;
    const created = await page.request.post(
      `${origin}/api/v1/shares/writable/directories`,
      {
        data: { path: "sse-external" },
        headers: { Origin: origin, "X-CSRF-Token": token },
      },
    );
    expect(created.ok()).toBe(true);
    await expect(
      page.getByRole("link", { name: "sse-external", exact: true }),
    ).toBeVisible();

    await entryAction(page, "sse-external", "Delete").click();
    await page
      .getByRole("dialog", { name: "Delete sse-external?" })
      .getByRole("button", { name: "Move to Trash" })
      .click();
    await expect(
      page.getByRole("link", { name: "sse-external", exact: true }),
    ).toHaveCount(0);
  });

  test("wraps a long unbreakable name in the Trash confirmation", async ({
    page,
  }) => {
    const name = "251104_Note_cle_Scientifique_Metaux_2025_FR_long_name.pdf";
    const title = `Delete ${name}?`;
    await openSignedIn(page, "/writable", "writer");
    await createEntry(page, "New file", "File name", name);
    await entryAction(page, name, "Delete").click();

    const dialog = page.getByRole("dialog", { name: title });
    await expect(dialog).toBeVisible();
    expect(
      await dialog.evaluate((panel) => panel.scrollWidth - panel.clientWidth),
    ).toBe(0);
    const panelBox = await dialog.boundingBox();
    const closeBox = await dialog
      .getByRole("button", { name: `Close ${title}` })
      .boundingBox();
    expect(panelBox).not.toBeNull();
    expect(closeBox).not.toBeNull();
    expect(closeBox!.x + closeBox!.width).toBeLessThanOrEqual(
      panelBox!.x + panelBox!.width,
    );

    await dialog.getByRole("button", { name: "Move to Trash" }).click();
    await expect(
      directoryListing(page).getByRole("link", { name, exact: true }),
    ).toHaveCount(0);
  });

  test("deletes permanently without leaving an item in Trash", async ({
    page,
  }) => {
    const name = "permanent-delete.txt";
    await openSignedIn(page, "/writable", "writer");
    await createEntry(page, "New file", "File name", name);
    await entryAction(page, name, "Delete").click();

    const dialog = page.getByRole("dialog", { name: `Delete ${name}?` });
    await expect(
      dialog.getByRole("button", { name: "Move to Trash" }),
    ).toBeFocused();
    await dialog.getByRole("button", { name: "Delete permanently" }).click();
    await expect(page.getByText(`Permanently deleted ${name}.`)).toBeVisible();
    await expect(page.getByRole("button", { name: "Undo" })).toHaveCount(0);
    await expect(
      directoryListing(page).getByRole("link", { name, exact: true }),
    ).toHaveCount(0);

    await page.goto("/trash");
    await expect(page.getByText(name, { exact: true })).toHaveCount(0);
  });

  test("empties a share's whole Trash, beyond the page shown", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    const token = await csrfToken(page);
    // More items than one Trash page holds.
    const created = await page.evaluate(async (csrf) => {
      const share = "/api/v1/shares/writable";
      for (let index = 0; index < 105; index += 1) {
        const path = `empty-trash-${index}.txt`;
        const create = await fetch(`${share}/files`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify({ path }),
        });
        if (!create.ok) return `create ${path}: ${create.status}`;
        const query = `path=${encodeURIComponent(path)}`;
        const metadata = (await (
          await fetch(`${share}/metadata?${query}`)
        ).json()) as { etag: string };
        const trash = await fetch(`${share}/entry?${query}`, {
          method: "DELETE",
          headers: { "X-CSRF-Token": csrf, "If-Match": metadata.etag },
        });
        if (!trash.ok) return `delete ${path}: ${trash.status}`;
      }
      return "ok";
    }, token);
    expect(created).toBe("ok");

    await page.goto("/trash");
    await expect(
      page.getByRole("button", { name: "Load more from Working files" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Empty Trash" }).click();
    const dialog = page.getByRole("dialog", { name: "Empty Trash?" });
    await expect(dialog).toContainText(/Permanently delete all \d+\+ items/);
    await dialog
      .getByRole("button", { name: "Empty Trash", exact: true })
      .click();
    await expect(
      page.getByText(/Permanently deleted \d+ items\./),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Trash is empty." }),
    ).toBeVisible();
    const listing = await page.request.get("/api/v1/shares/writable/trash");
    expect(((await listing.json()) as { items: unknown[] }).items).toEqual([]);

    // Without a CSRF token the server refuses to empty Trash.
    const forged = await page.request.post(
      "/api/v1/shares/writable/trash/empty",
    );
    expect(forged.status()).toBe(403);
  });

  test("uploads by native drop and file picker with partial limits, conflict, and explicit replacement", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await createEntry(page, "New file", "File name", "replace-me.txt");

    await dropFiles(
      page.locator("body"),
      [
        {
          name: "dragged.txt",
          mimeType: "text/plain",
          contents: "native drag and drop\n",
        },
        {
          name: "replace-me.txt",
          mimeType: "text/plain",
          contents: "replacement requires confirmation\n",
        },
        {
          name: "too-large.bin",
          mimeType: "application/octet-stream",
          contents: "x".repeat(1024 * 1024 + 1),
        },
      ],
      async () => {
        const overlay = page.getByTestId("upload-drop-overlay");
        await expect(overlay).toBeVisible();
        await expect(overlay).toHaveCSS("pointer-events", "auto");
        await expect(overlay).toContainText("Drop files to upload");
        await expect(overlay).toContainText("Working files");
      },
    );
    await expect(page.getByTestId("upload-drop-overlay")).toHaveCount(0);

    const uploads = page.getByRole("dialog", { name: "Uploads" });
    const outcomes = [
      { name: "dragged.txt", expected: "Uploaded" },
      { name: "replace-me.txt", expected: "Needs attention" },
      {
        name: "too-large.bin",
        expected: "This file is larger than the server allows.",
      },
    ];
    // The server allows two concurrent uploads per user, so any of the three
    // jobs may need a retry. Wait for all initial requests to release their slots.
    for (const { name } of outcomes) {
      await expect(uploadJob(uploads, name)).toContainText(
        /Uploaded|Needs attention|This file is larger than the server allows\.|The server is busy\. Retry shortly\./,
      );
    }
    for (const { name, expected } of outcomes) {
      const job = uploadJob(uploads, name);
      if (
        await job.getByText("The server is busy. Retry shortly.").isVisible()
      ) {
        await job.getByRole("button", { name: "Retry" }).click();
      }
      await expect(job).toContainText(expected);
    }
    expect(await readText(page, "writable", "replace-me.txt")).toBe("");

    await uploadJob(uploads, "replace-me.txt")
      .getByRole("button", { name: "Replace existing file" })
      .click();
    await expect(uploadJob(uploads, "replace-me.txt")).toContainText(
      "Replaced",
    );
    expect(await readText(page, "writable", "replace-me.txt")).toBe(
      "replacement requires confirmation\n",
    );
    const oversized = await page.request.get(
      "/api/v1/shares/writable/metadata?path=too-large.bin",
    );
    expect(oversized.status()).toBe(404);
    await uploads.getByRole("button", { name: "Done", exact: true }).click();

    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "picked.txt",
        mimeType: "text/plain",
        contents: "keyboard file picker\n",
      },
    ]);
    const pickerUploads = page.getByRole("dialog", { name: "Uploads" });
    await expect(uploadJob(pickerUploads, "picked.txt")).toContainText(
      "Uploaded",
    );
    await pickerUploads
      .getByRole("button", { name: "Done", exact: true })
      .click();
    await expect(
      page.getByRole("link", { name: "dragged.txt", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "picked.txt", exact: true }),
    ).toBeVisible();
    const readOnlyLeak = await page.request.get(
      "/api/v1/shares/read-only/metadata?path=dragged.txt",
    );
    expect(readOnlyLeak.status()).toBe(404);
  });

  test("keeps minimized uploads at their original destination and exposes file actions", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    // Delay sending in the page, so multipart file data stays with the browser
    // rather than being serialized through Playwright's request interceptor.
    await page.evaluate(() => {
      const gate = { holding: true, pending: [] as Array<() => void> };
      (window as unknown as { uploadGate: typeof gate }).uploadGate = gate;
      const send = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function (body) {
        if (gate.holding && body instanceof FormData && body.has("file")) {
          gate.pending.push(() => send.call(this, body));
        } else send.call(this, body);
      };
    });
    let started = 0;
    page.on("request", (request) => {
      if (request.url().includes("/api/v1/shares/writable/uploads?"))
        started += 1;
    });
    await chooseFiles(
      page.getByLabel("Choose files to upload"),
      [0, 1, 2, 3].map((i) => ({
        name: `queue-${i}.txt`,
        mimeType: "text/plain",
        contents: `queued upload ${i}\n`,
      })),
    );
    const uploads = page.getByRole("dialog", { name: "Uploads", exact: true });
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            (window as unknown as { uploadGate: { pending: unknown[] } })
              .uploadGate.pending.length,
        ),
      )
      .toBe(3);
    await uploads.getByRole("button", { name: "Pause queue" }).click();
    await uploads.getByRole("button", { name: "Continue browsing" }).click();
    const mini = page.getByRole("button", { name: /Show uploads:/ });
    await expect(mini).toBeFocused();
    await directoryListing(page)
      .getByRole("link", { name: "Projects", exact: true })
      .click();
    await expect(page).toHaveURL(/\/writable\/Projects$/);
    await page.evaluate(() => {
      const gate = (
        window as unknown as {
          uploadGate: { holding: boolean; pending: Array<() => void> };
        }
      ).uploadGate;
      gate.holding = false;
      gate.pending.splice(0).forEach((send) => send());
    });
    await expect(
      page.getByRole("button", { name: /Show uploads: 3 of 4 complete/ }),
    ).toBeVisible();
    expect(started).toBe(3);
    await mini.click();
    await uploads.getByRole("button", { name: "Resume queue" }).click();
    await expect(
      uploads.getByRole("button", { name: "Done", exact: true }),
    ).toBeVisible();
    await expect.poll(() => started).toBe(4);
    const open = uploads.getByRole("link", {
      name: "Open queue-0.txt",
      exact: true,
    });
    await expect(open).toHaveAttribute("href", "/writable/queue-0.txt");
    await expect(open).toHaveAttribute("rel", "noopener noreferrer");
    const popup = page.waitForEvent("popup");
    await open.click();
    const file = await popup;
    await expect(file.getByLabel("File source")).toContainText(
      "queued upload 0",
    );
    await file.close();
    await page.evaluate(() =>
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (value: string) => {
            (window as unknown as { copiedPath: string }).copiedPath = value;
          },
        },
      }),
    );
    await uploads
      .getByRole("button", { name: "Copy full path for queue-0.txt" })
      .click();
    await expect
      .poll(() =>
        page.evaluate(
          () => (window as unknown as { copiedPath: string }).copiedPath,
        ),
      )
      .toBe("writable/queue-0.txt");
    const audit = await new AxeBuilder({ page }).analyze();
    expect(
      audit.violations.filter(
        ({ impact }) => impact === "critical" || impact === "serious",
      ),
    ).toEqual([]);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(
      uploads.getByRole("button", { name: "Done", exact: true }),
    ).toBeVisible();
    const box = await uploads.boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(390);
    await uploads.getByRole("button", { name: "Clear completed" }).click();
    await expect(uploads).toHaveCount(0);
    expect(await readText(page, "writable", "queue-0.txt")).toBe(
      "queued upload 0\n",
    );
    const wrongFolder = await page.request.get(
      "/api/v1/shares/writable/metadata?path=Projects/queue-0.txt",
    );
    expect(wrongFolder.status()).toBe(404);
  });

  test("wraps long uploaded filenames inside copy-path tooltips", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    const name = `${"longfilename".repeat(16)}.json`;
    await chooseFiles(page.getByLabel("Choose files to upload"), [
      { name, mimeType: "application/json", contents: "{}" },
    ]);
    const uploads = page.getByRole("dialog", { name: "Uploads", exact: true });
    const copy = uploads.getByRole("button", {
      name: `Copy full path for ${name}`,
    });
    await expect(copy).toBeVisible();

    for (const width of [1440, 390, 320]) {
      await page.setViewportSize({ width, height: 844 });
      // Exercise pointer and keyboard tooltips at each viewport size.
      for (const interaction of ["hover", "focus"] as const) {
        if (interaction === "hover") await copy.hover();
        else await copy.focus();
        const tooltip = page.getByRole("tooltip");
        await expect(tooltip).toBeVisible();
        await expect(tooltip).toHaveText(`Copy full path for ${name}`);
        const bounds = await tooltip.evaluate((element) => {
          const box = element.getBoundingClientRect();
          const range = document.createRange();
          range.selectNodeContents(element);
          return {
            left: box.left,
            right: box.right,
            textFits: Array.from(range.getClientRects()).every(
              (line) => line.left >= box.left && line.right <= box.right,
            ),
          };
        });
        expect(bounds.left).toBeGreaterThanOrEqual(8);
        expect(bounds.right).toBeLessThanOrEqual(width - 8);
        expect(bounds.textFits).toBe(true);
        await copy.blur();
        await page.mouse.move(0, 0);
        await expect(tooltip).toHaveCount(0);
      }
    }
  });

  test("shows upload progress, survives a disconnect retry, and cancels explicitly", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    let attempts = 0;
    await page.route("**/api/v1/shares/writable/uploads?**", async (route) => {
      attempts += 1;
      if (attempts === 1) {
        await route.abort("connectionreset");
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 400));
      await route.continue();
    });

    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "retry-after-disconnect.txt",
        mimeType: "text/plain",
        contents: "retry succeeds\n",
      },
    ]);
    const uploads = page.getByRole("dialog", { name: "Uploads" });
    const retryJob = uploadJob(uploads, "retry-after-disconnect.txt");
    await expect(retryJob).toContainText("The upload failed");
    await retryJob.getByRole("button", { name: "Retry" }).click();
    await expect(
      retryJob.getByRole("progressbar", {
        name: "Upload progress for retry-after-disconnect.txt",
      }),
    ).toBeVisible();
    await expect(retryJob).toContainText("Uploaded");
    await uploads.getByRole("button", { name: "Done", exact: true }).click();
    await page.unroute("**/api/v1/shares/writable/uploads?**");

    let releaseUpload!: () => void;
    const holdUpload = new Promise<void>((resolve) => {
      releaseUpload = resolve;
    });
    await page.route("**/api/v1/shares/writable/uploads?**", async (route) => {
      await holdUpload;
      await route.abort("aborted").catch(() => undefined);
    });
    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "cancelled.txt",
        mimeType: "text/plain",
        contents: "must not be committed\n",
      },
    ]);
    const cancelUploads = page.getByRole("dialog", { name: "Uploads" });
    const cancelJob = uploadJob(cancelUploads, "cancelled.txt");
    await expect(cancelJob.getByRole("progressbar")).toBeVisible();
    await cancelJob.getByRole("button", { name: "Cancel" }).click();
    releaseUpload();
    await expect(cancelJob).toContainText("Cancelled");
    await cancelUploads
      .getByRole("button", { name: "Done", exact: true })
      .click();
    const cancelled = await page.request.get(
      "/api/v1/shares/writable/metadata?path=cancelled.txt",
    );
    expect(cancelled.status()).toBe(404);
  });

  test("keeps an upload at its original destination across browser history changes", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await page.getByRole("link", { name: "Projects", exact: true }).click();
    await expect(page).toHaveURL(/\/writable\/Projects$/);
    await expect(
      page.getByRole("link", { name: "example.toml", exact: true }),
    ).toBeVisible();

    let releaseUpload!: () => void;
    const holdUpload = new Promise<void>((resolve) => {
      releaseUpload = resolve;
    });
    await page.route("**/api/v1/shares/writable/uploads?**", async (route) => {
      await holdUpload;
      await route.continue();
    });
    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "keep-on-navigation.txt",
        mimeType: "text/plain",
        contents: "stays at its original destination\n",
      },
    ]);
    await expect(
      page.getByRole("progressbar", {
        name: "Upload progress for keep-on-navigation.txt",
      }),
    ).toBeVisible();

    await page.goBack();
    releaseUpload();
    await expect(page).toHaveURL(/\/writable$/);
    const uploads = page.getByRole("dialog", { name: "Uploads" });
    await expect(
      uploads.getByRole("link", { name: "Open keep-on-navigation.txt" }),
    ).toHaveAttribute("href", "/writable/Projects/keep-on-navigation.txt");
    expect(
      await readText(page, "writable", "Projects/keep-on-navigation.txt"),
    ).toBe("stays at its original destination\n");
  });

  test("selects files with click and Shift-click, downloads them as one ZIP, and moves them to Trash", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "select-a.txt",
        mimeType: "text/plain",
        contents: "first\n".repeat(400),
      },
      { name: "select-b.txt", mimeType: "text/plain", contents: "second\n" },
      { name: "select-c.txt", mimeType: "text/plain", contents: "third\n" },
    ]);
    const uploads = page.getByRole("dialog", { name: "Uploads" });
    await expect(uploadJob(uploads, "select-c.txt")).toContainText("Uploaded");
    await uploads.getByRole("button", { name: "Done", exact: true }).click();

    const listing = directoryListing(page);
    const first = listing.getByRole("checkbox", {
      name: "Select select-a.txt",
    });
    const last = listing.getByRole("checkbox", { name: "Select select-c.txt" });
    const row = listing.getByRole("listitem").filter({
      has: page.getByRole("checkbox", { name: "Select select-a.txt" }),
    });
    // The checkbox takes the icon's place only while the icon itself is
    // hovered, or the checkbox has keyboard focus; hovering the rest of the
    // row or focusing its name leaves the icon.
    await page.mouse.move(0, 0);
    await expect(first).toHaveCSS("opacity", "0");
    const name = row.getByRole("link", { name: "select-a.txt", exact: true });
    await name.hover();
    await expect(first).toHaveCSS("opacity", "0");
    await name.focus();
    await expect(first).toHaveCSS("opacity", "0");
    await expect(row.locator(".entry-icon")).toBeVisible();
    await page.keyboard.press("Shift+Tab");
    await expect(first).toBeFocused();
    await expect(first).toHaveCSS("opacity", "1");
    await expect(row.locator(".entry-icon")).toBeHidden();
    await name.focus();
    await expect(first).toHaveCSS("opacity", "0");
    await row.locator(".entry-select").hover();
    await expect(first).toHaveCSS("opacity", "1");
    await expect(row.locator(".entry-icon")).toBeHidden();
    // The same 1.125rem as the select-all checkbox.
    const box = await first.boundingBox();
    expect(box?.width).toBeLessThanOrEqual(19);
    expect(box?.width).toBeGreaterThanOrEqual(17);

    await first.click();
    await last.click({ modifiers: ["Shift"] });
    await expect(page).toHaveURL(/\/writable$/);
    await expect(
      listing.getByRole("checkbox", { name: "Select select-b.txt" }),
    ).toBeChecked();
    const bar = page.getByRole("toolbar", { name: "Selection actions" });
    await expect(bar).toContainText("3 selected");
    // Selection mode shows every row's checkbox.
    await expect(
      listing.getByRole("checkbox", { name: "Select README.md" }),
    ).toHaveCSS("opacity", "1");
    await last.click();
    await expect(bar).toContainText("2 selected");

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      bar.getByRole("button", { name: "Download as ZIP" }).click(),
    ]);
    expect(download.suggestedFilename()).toBe("writable.zip");
    expect(await download.failure()).toBeNull();
    const archive = await readFile((await download.path())!);
    // The selected files sit at the top level, with no folder around them.
    // Text of at least 1 KiB is deflated; a shorter file is stored.
    expect(zipEntries(archive)).toEqual([
      { name: "select-a.txt", method: 8 },
      { name: "select-b.txt", method: 0 },
    ]);

    await bar.getByRole("button", { name: "Delete" }).click();
    const confirm = page.getByRole("dialog", {
      name: "Delete 2 items?",
    });
    await confirm.getByRole("button", { name: "Move to Trash" }).click();
    await expect(page.getByText("Moved 2 items to Trash.")).toBeVisible();
    await expect(
      listing.getByRole("link", { name: "select-a.txt", exact: true }),
    ).toHaveCount(0);
    await expect(
      listing.getByRole("link", { name: "select-b.txt", exact: true }),
    ).toHaveCount(0);
    await expect(
      listing.getByRole("link", { name: "select-c.txt", exact: true }),
    ).toBeVisible();
    await expect(bar).toHaveCount(0);
  });
});

async function createEntry(
  page: Page,
  button: "New file" | "New folder",
  label: "File name" | "Folder name",
  name: string,
) {
  await page.getByRole("button", { name: button }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel(label).fill(name);
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

function entryAction(page: Page, entry: string, action: string): Locator {
  return page
    .getByLabel(`Actions for ${entry}`)
    .getByRole("button", { name: `${action} ${entry}`, exact: true });
}

function previewAction(page: Page, entry: string, action: string): Locator {
  return page
    .getByRole("complementary", { name: entry })
    .getByRole("button", { name: `${action} ${entry}`, exact: true });
}

function directoryListing(page: Page): Locator {
  return page.locator(".directory-panel");
}

function uploadJob(dialog: Locator, name: string): Locator {
  return dialog.getByRole("listitem").filter({ hasText: name });
}

async function readText(page: Page, shareId: string, path: string) {
  const query = new URLSearchParams({ path });
  const response = await page.request.get(
    `/api/v1/shares/${shareId}/text?${query.toString()}`,
  );
  expect(response.status()).toBe(200);
  const body = (await response.json()) as { text?: unknown };
  expect(typeof body.text).toBe("string");
  return body.text as string;
}

/**
 * The entries in a small ZIP archive's central directory, in order, with
 * their compression methods (0 stored, 8 deflated). The directory is found
 * through the end record, which has no comment.
 */
function zipEntries(archive: Buffer): { name: string; method: number }[] {
  const end = archive.length - 22;
  expect(archive.readUInt32LE(end)).toBe(0x06054b50);
  const count = archive.readUInt16LE(end + 10);
  let at = archive.readUInt32LE(end + 16);
  const entries: { name: string; method: number }[] = [];
  for (let index = 0; index < count; index++) {
    expect(archive.readUInt32LE(at)).toBe(0x02014b50);
    const method = archive.readUInt16LE(at + 10);
    const nameLength = archive.readUInt16LE(at + 28);
    const extraLength = archive.readUInt16LE(at + 30);
    const commentLength = archive.readUInt16LE(at + 32);
    const name = archive.toString("utf8", at + 46, at + 46 + nameLength);
    entries.push({ name, method });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

test("compresses a folder to ZIP and extracts it on the server", async ({
  page,
}, testInfo) => {
  test.skip(
    !ownsServerState(testInfo),
    "mutation coverage runs once per engine",
  );
  await openSignedIn(page, "/writable", "writer");
  await entryAction(page, "Projects", "Compress").click();
  const dialog = page.getByRole("dialog", { name: "Compress", exact: true });
  await expect(dialog.getByRole("combobox")).toHaveCount(0);
  const name = "e2e-local-zip.zip";
  await dialog.getByLabel("Archive name").fill(name);
  await dialog.getByRole("button", { name: "Compress", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await entryAction(page, name, "Extract").click();
  const extracting = page.getByRole("dialog", { name: "Extract archive" });
  await expect(extracting.getByLabel("Folder name")).toHaveValue(
    "e2e-local-zip",
  );
  const destination = "e2e-extracted-zip";
  await extracting.getByLabel("Folder name").fill(destination);
  await extracting
    .getByRole("button", { name: "Extract", exact: true })
    .click();
  await expect(extracting).toHaveCount(0);
  expect(
    await readText(page, "writable", `${destination}/Projects/example.toml`),
  ).toBe(await readText(page, "writable", "Projects/example.toml"));
  await entryAction(page, name, "Extract").click();
  await page
    .getByRole("dialog", { name: "Extract archive" })
    .getByLabel("Folder name")
    .fill(destination);
  await page
    .getByRole("dialog", { name: "Extract archive" })
    .getByRole("button", { name: "Extract", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(
    page.getByText(`Extracted to ${destination}-2.`, { exact: true }),
  ).toBeVisible();
  expect(
    await readText(page, "writable", `${destination}-2/Projects/example.toml`),
  ).toBe(await readText(page, "writable", "Projects/example.toml"));
});

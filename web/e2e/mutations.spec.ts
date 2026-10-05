import { readFile } from "node:fs/promises";

import { expect, test, type Locator, type Page } from "@playwright/test";

import { chooseFiles, csrfToken, dropFiles, openSignedIn } from "./helpers";

test.describe("writable share operations", () => {
  test.beforeEach(({ page }, testInfo) => {
    void page;
    test.skip(
      testInfo.project.name !== "desktop-chromium",
      "mutation state is exercised once against the shared production server",
    );
  });

  test("creates, edits, moves, trashes, and restores without crossing shares or overwriting", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");

    await createEntry(page, "New folder", "Folder name", "e2e-folder");
    await expect(
      directoryListing(page).getByRole("link", {
        name: "e2e-folder",
        exact: true,
      }),
    ).toBeVisible();

    await createEntry(page, "New file", "File name", "e2e-note.txt");
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
    await expect(page.getByRole("dialog")).toHaveCount(0);

    const saved = await readText(page, "writable", "e2e-note.txt");
    expect(saved).toBe("Production-backed browser edit\n");

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
      .getByRole("dialog", { name: "Move example.toml to Trash?" })
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
      .getByRole("dialog", { name: "Move e2e-folder to Trash?" })
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
      .getByRole("dialog", { name: "Move sse-external to Trash?" })
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
    const title = `Move ${name} to Trash?`;
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
      { name: "dragged.txt", expected: "Succeeded" },
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
        /Succeeded|Needs attention|This file is larger than the server allows\.|The server is busy\. Retry shortly\./,
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
    await uploads.getByRole("button", { name: "Close", exact: true }).click();

    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "picked.txt",
        mimeType: "text/plain",
        contents: "keyboard file picker\n",
      },
    ]);
    const pickerUploads = page.getByRole("dialog", { name: "Uploads" });
    await expect(uploadJob(pickerUploads, "picked.txt")).toContainText(
      "Succeeded",
    );
    await pickerUploads
      .getByRole("button", { name: "Close", exact: true })
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
    await expect(retryJob).toContainText("Succeeded");
    await uploads.getByRole("button", { name: "Close", exact: true }).click();
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
      .getByRole("button", { name: "Close", exact: true })
      .click();
    const cancelled = await page.request.get(
      "/api/v1/shares/writable/metadata?path=cancelled.txt",
    );
    expect(cancelled.status()).toBe(404);
  });

  test("aborts an upload when browser history changes its destination", async ({
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
      await route.abort("aborted").catch(() => undefined);
    });
    await chooseFiles(page.getByLabel("Choose files to upload"), [
      {
        name: "cancel-on-navigation.txt",
        mimeType: "text/plain",
        contents: "must remain temporary\n",
      },
    ]);
    await expect(
      page.getByRole("progressbar", {
        name: "Upload progress for cancel-on-navigation.txt",
      }),
    ).toBeVisible();

    await page.goBack();
    releaseUpload();
    await expect(page).toHaveURL(/\/writable$/);
    await expect(page.getByRole("dialog", { name: "Uploads" })).toHaveCount(0);
    const cancelled = await page.request.get(
      "/api/v1/shares/writable/metadata?path=Projects%2Fcancel-on-navigation.txt",
    );
    expect(cancelled.status()).toBe(404);
  });

  test("selects files with click and Shift-click, downloads them as one ZIP, and moves them to Trash", async ({
    page,
  }) => {
    await openSignedIn(page, "/writable", "writer");
    await chooseFiles(page.getByLabel("Choose files to upload"), [
      { name: "select-a.txt", mimeType: "text/plain", contents: "first\n" },
      { name: "select-b.txt", mimeType: "text/plain", contents: "second\n" },
      { name: "select-c.txt", mimeType: "text/plain", contents: "third\n" },
    ]);
    const uploads = page.getByRole("dialog", { name: "Uploads" });
    await expect(uploadJob(uploads, "select-c.txt")).toContainText("Succeeded");
    await uploads.getByRole("button", { name: "Close", exact: true }).click();

    const listing = directoryListing(page);
    const first = listing.getByRole("checkbox", {
      name: "Select select-a.txt",
    });
    const last = listing.getByRole("checkbox", { name: "Select select-c.txt" });
    const row = listing.getByRole("listitem").filter({
      has: page.getByRole("checkbox", { name: "Select select-a.txt" }),
    });
    // The checkbox takes the icon's place only while the row is hovered.
    await page.mouse.move(0, 0);
    await expect(first).toHaveCSS("opacity", "0");
    await row.hover();
    await expect(first).toHaveCSS("opacity", "1");
    await expect(row.locator(".entry-icon")).toBeHidden();

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
    expect(zipEntryNames(archive)).toEqual(["select-a.txt", "select-b.txt"]);

    await bar.getByRole("button", { name: "Delete" }).click();
    const confirm = page.getByRole("dialog", {
      name: "Move 2 items to Trash?",
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

/** The entry names in a ZIP archive's central directory, in order. */
function zipEntryNames(archive: Buffer): string[] {
  const names: string[] = [];
  let at = archive.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  while (at !== -1 && archive.readUInt32LE(at) === 0x02014b50) {
    const nameLength = archive.readUInt16LE(at + 28);
    const extraLength = archive.readUInt16LE(at + 30);
    const commentLength = archive.readUInt16LE(at + 32);
    names.push(archive.toString("utf8", at + 46, at + 46 + nameLength));
    at += 46 + nameLength + extraLength + commentLength;
  }
  return names;
}

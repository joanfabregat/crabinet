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

  test("creates, edits, moves, and exactly deletes without crossing shares or overwriting", async ({
    page,
  }) => {
    await openSignedIn(page, "/browse/writable", "writer");

    await createEntry(page, "New folder", "Folder name", "e2e-folder");
    await expect(page.getByRole("link", { name: "e2e-folder" })).toBeVisible();

    await createEntry(page, "New file", "File name", "e2e-note.txt");
    await expect(
      page.getByRole("link", { name: "e2e-note.txt" }),
    ).toBeVisible();

    await page.getByRole("link", { name: "e2e-note.txt" }).click();
    await page.getByRole("button", { name: "Edit e2e-note.txt" }).click();
    const editor = page.getByLabel("UTF-8 text content");
    await expect(editor).toBeFocused();
    await editor.fill("Production-backed browser edit\n");
    await expect(page.getByText("Unsaved changes")).toBeVisible();
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);

    const saved = await readText(page, "writable", "e2e-note.txt");
    expect(saved).toBe("Production-backed browser edit\n");

    await entryAction(page, "e2e-note.txt", "Move").click();
    const moveDialog = page.getByRole("dialog", { name: "Move e2e-note.txt" });
    await moveDialog
      .getByRole("button", { name: "e2e-folder", exact: true })
      .click();
    await moveDialog.getByRole("button", { name: "Move here" }).click();
    await expect(page.getByRole("link", { name: "e2e-note.txt" })).toHaveCount(
      0,
    );

    await page.getByRole("link", { name: "e2e-folder" }).click();
    await expect(
      page.getByRole("link", { name: "e2e-note.txt" }),
    ).toBeVisible();

    await page.getByRole("link", { name: "e2e-note.txt" }).click();
    await entryAction(page, "e2e-note.txt", "Rename").click();
    const renameDialog = page.getByRole("dialog", {
      name: "Rename e2e-note.txt",
    });
    await renameDialog.getByLabel("New name").fill("note-renamed.md");
    await renameDialog.getByRole("button", { name: "Confirm" }).click();
    await expect(
      page.getByRole("heading", { name: "note-renamed.md" }),
    ).toBeVisible();
    await expect(page.getByRole("tab", { name: "Readable" })).toBeVisible();
    await expect(page).toHaveURL(/preview=e2e-folder%2Fnote-renamed\.md/);

    const originalDestination = await readText(
      page,
      "writable",
      "Projects/example.toml",
    );
    await entryAction(page, "note-renamed.md", "Rename").click();
    const targetNameDialog = page.getByRole("dialog", {
      name: "Rename note-renamed.md",
    });
    await targetNameDialog.getByLabel("New name").fill("example.toml");
    await targetNameDialog.getByRole("button", { name: "Confirm" }).click();
    await entryAction(page, "example.toml", "Move").click();
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

    await page.getByRole("link", { name: "example.toml" }).click();
    await expect(
      page.getByRole("heading", { name: "example.toml" }),
    ).toBeVisible();
    await entryAction(page, "example.toml", "Delete").click();
    const deleteDialog = page.getByRole("dialog", {
      name: "Delete file example.toml",
    });
    const confirmation = deleteDialog.getByRole("checkbox", {
      name: "I understand that example.toml will be permanently deleted",
    });
    await expect(
      deleteDialog.getByRole("button", { name: "Delete", exact: true }),
    ).toBeDisabled();
    await confirmation.check();
    await deleteDialog
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(page.getByRole("link", { name: "example.toml" })).toHaveCount(
      0,
    );
    await expect(
      page.getByRole("heading", { name: "example.toml" }),
    ).toHaveCount(0);
    await expect(page).not.toHaveURL(/preview=/);

    await page
      .getByLabel("Breadcrumb")
      .getByRole("link", { name: "Working files" })
      .click();
    await entryAction(page, "e2e-folder", "Delete").click();
    const folderDelete = page.getByRole("dialog", {
      name: "Delete folder e2e-folder",
    });
    await folderDelete
      .getByLabel("Type e2e-folder to confirm")
      .fill("e2e-folder");
    await folderDelete
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(page.getByRole("link", { name: "e2e-folder" })).toHaveCount(0);

    await entryAction(page, "Projects", "Delete").click();
    const nonEmptyDelete = page.getByRole("dialog", {
      name: "Delete folder Projects",
    });
    await nonEmptyDelete
      .getByLabel("Type Projects to confirm")
      .fill("Projects");
    await nonEmptyDelete
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(nonEmptyDelete.getByRole("alert")).toContainText(
      "destination already exists",
    );
    await nonEmptyDelete.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("link", { name: "Projects" })).toBeVisible();

    const readOnlyLeak = await page.request.get(
      "/api/v1/shares/read-only/metadata?path=e2e-note.txt",
    );
    expect(readOnlyLeak.status()).toBe(404);
  });

  test("detects a concurrent text edit and preserves the winning version", async ({
    context,
    page,
  }) => {
    await openSignedIn(page, "/browse/writable", "writer");
    const competingPage = await context.newPage();
    await competingPage.goto("/browse/writable");
    await expect(
      competingPage.getByLabel("Shared folders", { exact: true }),
    ).toBeVisible();

    await page.getByRole("link", { name: "README.md" }).click();
    await page.getByRole("button", { name: "Edit README.md" }).click();
    await expect(page.getByLabel("UTF-8 text content")).toBeFocused();
    await competingPage.getByRole("link", { name: "README.md" }).click();
    await competingPage.getByRole("button", { name: "Edit README.md" }).click();
    await expect(competingPage.getByLabel("UTF-8 text content")).toBeFocused();

    const winningText = "Saved by the first browser\n";
    await page.getByLabel("UTF-8 text content").fill(winningText);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);

    const losingEditor = competingPage.getByLabel("UTF-8 text content");
    await losingEditor.fill("Stale second-browser edit\n");
    await competingPage.getByRole("button", { name: "Save" }).click();
    const conflict = competingPage.getByRole("alert");
    await expect(conflict).toContainText("changed after you opened it");
    await expect(losingEditor).toBeDisabled();
    expect(await readText(page, "writable", "README.md")).toBe(winningText);

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
    await openSignedIn(page, "/browse/writable", "writer");
    await expect(page.getByRole("link", { name: "README.md" })).toBeVisible();
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
      page.getByRole("link", { name: "sse-external" }),
    ).toBeVisible();

    await entryAction(page, "sse-external", "Delete").click();
    const dialog = page.getByRole("dialog", {
      name: "Delete folder sse-external",
    });
    await dialog
      .getByLabel("Type sse-external to confirm")
      .fill("sse-external");
    await dialog.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(page.getByRole("link", { name: "sse-external" })).toHaveCount(
      0,
    );
  });

  test("uploads by native drop and file picker with partial limits, conflict, and explicit replacement", async ({
    page,
  }) => {
    await openSignedIn(page, "/browse/writable", "writer");
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
        await expect(overlay).toContainText("Drop files to upload");
        await expect(overlay).toContainText("Working files");
      },
    );
    await expect(page.getByTestId("upload-drop-overlay")).toHaveCount(0);

    const uploads = page.getByRole("dialog", { name: "Uploads" });
    await expect(uploadJob(uploads, "dragged.txt")).toContainText("Succeeded");
    await expect(uploadJob(uploads, "replace-me.txt")).toContainText(
      "Needs attention",
    );
    await expect(uploadJob(uploads, "too-large.bin")).toContainText(
      "This file is larger than the server allows.",
    );
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
    await expect(page.getByRole("link", { name: "dragged.txt" })).toBeVisible();
    await expect(page.getByRole("link", { name: "picked.txt" })).toBeVisible();
    const readOnlyLeak = await page.request.get(
      "/api/v1/shares/read-only/metadata?path=dragged.txt",
    );
    expect(readOnlyLeak.status()).toBe(404);
  });

  test("shows upload progress, survives a disconnect retry, and cancels explicitly", async ({
    page,
  }) => {
    await openSignedIn(page, "/browse/writable", "writer");
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
    await openSignedIn(page, "/browse/writable", "writer");
    await page.getByRole("link", { name: "Projects" }).click();
    await expect(page).toHaveURL(/path=Projects/);

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
    await expect(page).toHaveURL(/\/browse\/writable$/);
    await expect(page.getByRole("dialog", { name: "Uploads" })).toHaveCount(0);
    const cancelled = await page.request.get(
      "/api/v1/shares/writable/metadata?path=Projects%2Fcancel-on-navigation.txt",
    );
    expect(cancelled.status()).toBe(404);
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
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog).toHaveCount(0);
}

function entryAction(page: Page, entry: string, action: string): Locator {
  return page
    .getByLabel(`Actions for ${entry}`)
    .getByRole("button", { name: `${action} ${entry}`, exact: true });
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

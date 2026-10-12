import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { openSignedIn, csrfToken } from "./helpers";

test("search suggestions open nested files and preserve the query when closing preview", async ({
  page,
}) => {
  let releaseDirectory = () => {};
  const directoryReady = new Promise<void>((resolve) => {
    releaseDirectory = resolve;
  });
  await page.route("**/api/v1/shares/read-only/directory?*", async (route) => {
    await directoryReady;
    await route.continue();
  });
  await openSignedIn(page, "/read-only");
  const input = page.getByRole("combobox", { name: "Search files" });
  await input.fill("notes");
  releaseDirectory();
  await expect(page.getByRole("option", { name: /notes.txt/ })).toBeVisible();
  await expect(input).toBeFocused();
  await input.press("ArrowDown");
  await input.press("Enter");
  await expect(page).toHaveURL(/search=notes/);
  await expect(page.locator(".preview-panel")).toContainText("notes.txt");
  await page
    .getByRole("button", { name: "Close preview of notes.txt" })
    .click();
  await expect(
    page.getByRole("region", { name: "Search results" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "notes.txt", exact: true }),
  ).toBeVisible();
  await page.getByRole("link", { name: "nested", exact: true }).click();
  await expect(page).toHaveURL(/\/read-only\/nested$/);
  await page.goBack();
  await expect(input).toHaveValue("notes");
});

test("visual filters work and search results are accessible", async ({
  page,
}, testInfo) => {
  await openSignedIn(page, "/read-only");
  const search = page.getByRole("banner").getByRole("search");
  await expect(search).toBeVisible();
  // The idle bar hides its scope and filter controls until it has focus.
  await page.getByRole("combobox", { name: "Search files" }).focus();
  await page.getByRole("button", { name: "Search filters" }).click();
  const dialog = page.getByRole("dialog", { name: "Search filters" });
  await expect(dialog).toBeVisible();
  const barBounds = await search.boundingBox();
  const panelBounds = await dialog.boundingBox();
  expect(panelBounds!.y).toBeGreaterThanOrEqual(
    barBounds!.y + barBounds!.height,
  );
  expect(
    (await new AxeBuilder({ page }).exclude(".app-footer").analyze())
      .violations,
  ).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath("search-filters.png") });
  await dialog.getByLabel("Extension", { exact: true }).fill("log");
  await dialog.getByLabel("File size", { exact: true }).fill("10");
  await dialog.getByRole("button", { name: "Apply filters" }).click();
  await expect(
    page.getByRole("link", { name: "server.log", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Search filters (2 applied)" }),
  ).toBeVisible();
  const accessibility = await new AxeBuilder({ page })
    .exclude(".app-footer")
    .analyze();
  expect(accessibility.violations).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});

test("all-share results use granted shares and preview the result's own share", async ({
  page,
}) => {
  await openSignedIn(page, "/read-only", "writer");
  const input = page.getByRole("combobox", { name: "Search files" });
  await input.focus();
  await page
    .getByRole("combobox", { name: "Search scope" })
    .selectOption("all");
  await input.fill("README");
  await expect(page.getByRole("option", { name: /README.md/ })).toBeVisible();
  await page.getByRole("option", { name: /README.md/ }).click();
  await expect(page).toHaveURL(/previewShare=writable/);
  await expect(page.locator(".preview-panel")).toContainText("README.md");
});

test("successful file mutations appear in suggestions and stale deletions are omitted", async ({
  page,
}) => {
  await openSignedIn(page, "/writable", "writer");
  const csrf = await csrfToken(page);
  const path = `search-e2e-${Date.now()}.txt`;
  const create = await page.request.post("/api/v1/shares/writable/files", {
    headers: { "X-CSRF-Token": csrf, Origin: new URL(page.url()).origin },
    data: { path },
  });
  expect(create.ok()).toBe(true);
  try {
    const input = page.getByRole("combobox", { name: "Search files" });
    await input.fill(path);
    await expect(
      page.getByRole("option", { name: new RegExp(path) }),
    ).toBeVisible({ timeout: 15000 });
  } finally {
    const metadata = (await (
      await page.request.get(
        `/api/v1/shares/writable/metadata?${new URLSearchParams({ path })}`,
      )
    ).json()) as { etag: string };
    const removed = await page.request.delete(
      `/api/v1/shares/writable/entry?${new URLSearchParams({ path })}`,
      {
        headers: {
          "X-CSRF-Token": csrf,
          "If-Match": metadata.etag,
          Origin: new URL(page.url()).origin,
        },
      },
    );
    expect(removed.ok()).toBe(true);
  }
  await page.getByRole("combobox", { name: "Search files" }).press("Enter");
  await expect(
    page
      .getByRole("region", { name: "Search results" })
      .getByRole("link", { name: path, exact: true }),
  ).toHaveCount(0);
});

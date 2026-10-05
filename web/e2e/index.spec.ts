import { readFile } from "node:fs/promises";

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Response } from "@playwright/test";

import { csrfToken, openFolders, openSignedIn, signIn } from "./helpers";

test("login, secure session cookie, read-only enforcement, and logout", async ({
  context,
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Sign in to Crabinet" }),
  ).toBeVisible();

  await page.getByLabel("Email or username", { exact: true }).fill("reader");
  await page.getByLabel("Password").fill("incorrect-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Sign-in failed");

  await signIn(page, "reader");
  await expect(
    page.getByRole("img", { name: "Read only", includeHidden: true }),
  ).toHaveCount(1);
  await expect(
    page.getByRole("region", { name: "File operations" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /^(Edit|Rename|Move|Delete) / }),
  ).toHaveCount(0);
  await expect(
    page
      .locator(".directory-heading-actions")
      .getByRole("button", { name: /^Copy full path for / }),
  ).toBeVisible();

  const cookies = await context.cookies();
  const sessionCookie = cookies.find(
    (cookie) => cookie.name === "__Host-crabinet_session",
  );
  expect(sessionCookie).toMatchObject({
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });
  expect(sessionCookie?.value).toMatch(/^[0-9a-f]{64}$/);

  const token = await csrfToken(page);
  const origin = new URL(page.url()).origin;
  const forbidden = await page.request.post(
    `${origin}/api/v1/shares/read-only/directories`,
    {
      data: { path: "must-not-exist" },
      headers: { Origin: origin, "X-CSRF-Token": token },
    },
  );
  expect(forbidden.status()).toBe(403);

  const forbiddenUpload = await page.request.post(
    `${origin}/api/v1/shares/read-only/uploads?path=`,
    {
      headers: { Origin: origin, "X-CSRF-Token": token },
      multipart: {
        file: {
          name: "must-not-upload.txt",
          mimeType: "text/plain",
          buffer: Buffer.from("blocked"),
        },
      },
    },
  );
  expect(forbiddenUpload.status()).toBe(403);

  const isolated = await page.request.get(
    `${origin}/api/v1/shares/writable/directory?path=&limit=100`,
  );
  expect(isolated.status()).toBe(404);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to Crabinet" }),
  ).toBeVisible();
  expect(
    (await context.cookies()).some(
      (cookie) => cookie.name === "__Host-crabinet_session",
    ),
  ).toBe(false);
});

test("direct routes, tree share navigation, breadcrumbs, and browser history", async ({
  page,
}) => {
  // The former ?path= format still resolves and is rewritten in place.
  await page.goto("/browse/writable?path=Projects");
  await signIn(page, "writer");

  await expect(page).toHaveURL(/\/writable\/Projects$/);
  await expect(
    page.getByRole("heading", { name: "Projects", level: 1 }),
  ).toBeFocused();
  await expect(
    page.getByRole("link", { name: "example.toml", exact: true }),
  ).toBeVisible();

  await page
    .getByLabel("Breadcrumb")
    .getByRole("link", { name: "Working files", exact: true })
    .click();
  await expect(page).toHaveURL(/\/writable$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/writable\/Projects$/);
  await expect(
    page.getByRole("link", { name: "example.toml", exact: true }),
  ).toBeVisible();

  let sidebar = await openFolders(page);
  await sidebar
    .getByRole("link", { name: "Reference library", exact: true })
    .click();
  await expect(page).toHaveURL(/\/read-only$/);
  sidebar = await openFolders(page);
  await expect(sidebar.getByRole("img", { name: "Read only" })).toBeVisible();
  // Selecting a folder opens it without expanding it in the tree.
  const nested = sidebar.getByRole("link", { name: "nested", exact: true });
  await expect(nested).toHaveCount(0);
  await sidebar
    .getByRole("button", { name: "Expand Reference library" })
    .click();
  await expect(nested).toBeVisible();

  await nested.click();
  await expect(page).toHaveURL(/\/read-only\/nested$/);
  sidebar = await openFolders(page);
  await expect(sidebar.getByText("No subfolders")).toHaveCount(0);
  await sidebar.getByRole("button", { name: "Expand nested" }).click();
  await expect(sidebar.getByText("No subfolders")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("link", { name: "notes.txt", exact: true }),
  ).toBeVisible();
  await page.goBack();
  await expect(
    page.getByRole("link", { name: "Guide.md", exact: true }),
  ).toBeVisible();

  // A link ending in a file name opens its folder with the file previewed.
  await page.goto("/writable/Projects/example.toml");
  await expect(
    page.getByRole("heading", { name: "example.toml", level: 2 }),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/writable\/Projects\/example\.toml$/);
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "example.toml", level: 2 }),
  ).toBeVisible();
});

test("a start folder follows the user while direct links keep their destination", async ({
  page,
}) => {
  await openSignedIn(page, "/writable/Projects", "writer");
  const headingActions = page.locator(".directory-heading-actions");
  const newFile = headingActions.getByRole("button", { name: "New file" });
  const newFolder = headingActions.getByRole("button", { name: "New folder" });
  const upload = headingActions.getByRole("button", { name: "Upload files" });
  const copyPath = headingActions.getByRole("button", {
    name: "Copy full path for Projects",
  });
  await expect(newFile).toBeVisible();
  await expect(newFolder).toBeVisible();
  await expect(upload).toBeVisible();
  await expect(copyPath).toBeVisible();
  await expect(newFile).toHaveText("New file");
  await expect(newFolder).toHaveText("New folder");
  await expect(upload).toHaveText("Upload files");
  await copyPath.focus();
  await expect(page.getByRole("tooltip")).toHaveText(
    "Copy full path for Projects",
  );
  const sidebar = page.getByRole("complementary", { name: "Shared folders" });
  await expect(sidebar.getByRole("button", { name: "New file" })).toHaveCount(
    0,
  );
  await expect(sidebar.getByRole("button", { name: "New folder" })).toHaveCount(
    0,
  );
  await expect(page.locator(".directory-toolbar")).toHaveCount(0);
  await expect(
    page.getByRole("checkbox", { name: "Show hidden files" }),
  ).toHaveCount(0);
  const pageWidth = await page.evaluate(
    () => document.documentElement.scrollWidth,
  );
  expect(pageWidth).toBeLessThanOrEqual(page.viewportSize()!.width);

  const settingsButton = page.getByRole("button", { name: "Settings" });
  const signOutButton = page.getByRole("button", { name: "Sign out" });
  await expect(settingsButton).toHaveText("");
  await expect(signOutButton).toHaveText("");
  await settingsButton.focus();
  await expect(page.getByRole("tooltip")).toHaveText("Settings");
  await signOutButton.focus();
  await expect(page.getByRole("tooltip")).toHaveText("Sign out");
  await settingsButton.click();
  const settings = page.getByRole("dialog", { name: "Settings" });
  await settings.getByRole("tab", { name: "Files" }).click();
  await expect(
    settings.getByRole("checkbox", { name: "Show hidden files" }),
  ).toBeVisible();
  await settings.getByRole("tab", { name: "Start folder" }).click();
  const startFolder = settings.getByRole("combobox", {
    name: "Folder to open after sign-in",
  });
  await expect(startFolder.locator("option")).toHaveCount(3);
  await startFolder.selectOption("writable");
  await expect(startFolder).toHaveValue("writable");
  await settings.getByRole("button", { name: "Close Settings" }).click();
  await expect(settings).toHaveCount(0);

  await page.goto("/");
  await expect(page).toHaveURL(/\/writable$/);
  await page.goto("/read-only");
  await expect(page).toHaveURL(/\/read-only$/);
  await expect(page.getByRole("button", { name: "New file" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New folder" })).toHaveCount(0);

  await page.getByRole("button", { name: "Settings" }).click();
  await startFolder.selectOption("");
  await expect(startFolder).toHaveValue("");
  await page.goto("/");
  await expect(page).toHaveURL(/\/read-only$/);
});

test("action tooltips escape clipped panels and remain inside the viewport", async ({
  page,
}) => {
  await openSignedIn(page, "/writable", "writer");
  const copyPath = page
    .locator(".directory-heading-actions")
    .getByRole("button", { name: "Copy full path for Working files" });
  await copyPath.scrollIntoViewIfNeeded();
  await copyPath.focus();

  const tooltip = page.getByRole("tooltip");
  await expect(tooltip).toHaveText("Copy full path for Working files");
  await expect(tooltip).toBeVisible();
  expect(
    await tooltip.evaluate((element) =>
      Boolean(element.closest(".directory-panel, .share-tree, .preview-panel")),
    ),
  ).toBe(false);

  const box = await tooltip.boundingBox();
  const triggerBox = await copyPath.boundingBox();
  const viewport = page.viewportSize();
  expect(box).not.toBeNull();
  expect(triggerBox).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(viewport!.width);
  const centeredLeft = triggerBox!.x + (triggerBox!.width - box!.width) / 2;
  const expectedLeft = Math.min(
    Math.max(centeredLeft, 8),
    viewport!.width - box!.width - 8,
  );
  expect(box!.x).toBeCloseTo(expectedLeft, 0);
});

test("hostile Markdown and HTML remain inert in-panel and in a new tab", async ({
  context,
  page,
}) => {
  const externalRequests: string[] = [];
  context.on("response", (response) => {
    // Parse instead of matching a prefix, so the check is on the exact host
    // and covers every scheme and port the hostile fixtures could reach.
    if (new URL(response.url()).hostname === "attacker.invalid") {
      externalRequests.push(response.url());
    }
  });
  let dialogs = 0;
  page.on("dialog", async (dialog) => {
    dialogs += 1;
    await dialog.dismiss();
  });
  context.on("page", (openedPage) => {
    openedPage.on("dialog", async (dialog) => {
      dialogs += 1;
      await dialog.dismiss();
    });
  });

  await openSignedIn(page);
  await page.getByRole("link", { name: "Guide.md", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Guide.md", level: 2 }),
  ).toBeFocused();
  await expect(
    page
      .getByTestId("markdown-document")
      .getByRole("heading", { name: "Welcome to Crabinet" }),
  ).toBeVisible();
  await expect(page.getByTestId("markdown-document")).not.toContainText(
    "window.__indexHostileScript",
  );
  const markdown = page.getByTestId("markdown-document");
  await expect(markdown.getByRole("note")).toContainText(
    "Grants are checked again on every request.",
  );
  await expect(
    markdown.getByRole("cell", { name: "Writer", exact: true }),
  ).toBeVisible();
  await expect(markdown.getByRole("checkbox")).toHaveCount(2);
  await expect(markdown.getByLabel("Code block")).toHaveClass(/shiki-source/);
  await expect(markdown.locator("a[href]")).toHaveCount(0);
  await expect(markdown).toContainText("[unsafe link](javascript:");
  expect(await page.locator("script").count()).toBe(1);
  expect(
    await page.getByTestId("markdown-document").locator("img, form").count(),
  ).toBe(0);
  expect(externalRequests).toEqual([]);
  expect(dialogs).toBe(0);

  const readable = page.getByRole("tab", { name: "Readable" });
  await readable.focus();
  await readable.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Source" })).toBeFocused();
  await expect(page.getByLabel("Markdown source")).toContainText(
    "javascript:window.__indexJavascriptLink=true",
  );
  await page.getByRole("button", { name: "Close preview of Guide.md" }).click();

  await page.getByRole("link", { name: "hostile.html", exact: true }).click();
  const frame = page.getByTitle("Sandboxed HTML preview for hostile.html");
  await expect(frame).toHaveAttribute("sandbox", "");
  await expect(frame).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/html/rendered?path=hostile.html&v=0-0",
  );
  await expect(frame.contentFrame().locator("body")).toContainText("Sign out");
  expect(await page.evaluate(() => localStorage.getItem("hostile"))).toBeNull();
  expect(externalRequests).toEqual([]);
  expect(dialogs).toBe(0);

  const [renderedPage] = await Promise.all([
    page.waitForEvent("popup"),
    page
      .getByRole("link", { name: "Open rendered HTML in new tab", exact: true })
      .click(),
  ]);
  // The new tab is Crabinet's own viewer, framing the same sandboxed page.
  await expect(renderedPage).toHaveURL(
    /\/read-only\/hostile\.html\?view=rendered$/,
  );
  await expect(
    renderedPage.getByRole("heading", { name: "hostile.html", level: 1 }),
  ).toBeVisible();
  const viewerFrame = renderedPage.getByTitle(
    "Sandboxed HTML preview for hostile.html",
  );
  await expect(viewerFrame).toHaveAttribute("sandbox", "");
  await expect(viewerFrame).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/html/rendered?path=hostile.html",
  );
  await expect(viewerFrame.contentFrame().locator("body")).toContainText(
    "Sign out",
  );
  const hostileFrame = renderedPage.frame({
    url: /\/preview\/html\/rendered\?path=hostile\.html$/,
  });
  expect(
    await hostileFrame?.evaluate(() =>
      Boolean(
        (window as Window & { __indexHostileHtml?: boolean })
          .__indexHostileHtml,
      ),
    ),
  ).toBe(false);
  expect(await renderedPage.evaluate(() => window.opener)).toBeNull();
  expect(
    await renderedPage.evaluate(() => localStorage.getItem("hostile")),
  ).toBeNull();
  expect(externalRequests).toEqual([]);

  // The rendered endpoint itself refuses to become a top-level document.
  const direct = await renderedPage.goto(
    "/api/v1/shares/read-only/preview/html/rendered?path=hostile.html",
  );
  expect(direct?.status()).toBe(403);
  expect(direct?.headers()["content-type"]).toBe("text/plain; charset=utf-8");
  await expect(renderedPage.locator("body")).toContainText("sandboxed viewer");
  expect(await renderedPage.locator("script, form, img, svg").count()).toBe(0);
  expect(externalRequests).toEqual([]);
  await renderedPage.close();

  await page.getByRole("tab", { name: "Source" }).click();
  const sourceFrame = page.getByTitle("Inert HTML source for hostile.html");
  await expect(sourceFrame).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/html?path=hostile.html&v=0-0",
  );
  await expect(sourceFrame.contentFrame().locator("body")).toContainText(
    "window.__indexHostileHtml",
  );
  expect(
    await sourceFrame.contentFrame().locator("script, form, img, svg").count(),
  ).toBe(0);

  const sourceResponse = await page.request.get(
    "/api/v1/shares/read-only/preview/html?path=hostile.html",
  );
  expect(sourceResponse.status()).toBe(200);
  expect(sourceResponse.headers()["content-type"]).toBe(
    "text/plain; charset=utf-8",
  );
  expect(sourceResponse.headers()["content-security-policy"]).toContain(
    "sandbox; default-src 'none'",
  );
  expect(sourceResponse.headers()["x-content-type-options"]).toBe("nosniff");
  expect(sourceResponse.headers()["referrer-policy"]).toBe("no-referrer");

  const [sourcePage] = await Promise.all([
    page.waitForEvent("popup"),
    page
      .getByRole("link", {
        name: "Open hostile.html in a new tab",
        exact: true,
      })
      .click(),
  ]);
  await sourcePage.waitForLoadState("domcontentloaded");
  await expect(sourcePage.locator("body")).toContainText(
    "window.__indexHostileHtml",
  );
  expect(await sourcePage.locator("script, form, img, svg").count()).toBe(0);
  expect(await sourcePage.evaluate(() => window.opener)).toBeNull();
  expect(context.pages()).toHaveLength(2);
  expect(externalRequests).toEqual([]);
  expect(dialogs).toBe(0);
});

test("rendered HTML in a new tab cannot navigate that tab away", async ({
  context,
  page,
}) => {
  // Nothing may reach the external origin: record any attempt and fail it.
  const externalRequests: string[] = [];
  await context.route("https://example.com/**", async (route) => {
    externalRequests.push(route.request().url());
    await route.abort("blockedbyclient");
  });

  await openSignedIn(page, "/read-only/navigation.html");
  await expect(
    page.getByRole("heading", { name: "navigation.html", level: 2 }),
  ).toBeVisible();
  const [viewer] = await Promise.all([
    page.waitForEvent("popup"),
    page
      .getByRole("link", { name: "Open rendered HTML in new tab", exact: true })
      .click(),
  ]);
  const appOrigin = new URL(page.url()).origin;
  const viewerUrl = `${appOrigin}/read-only/navigation.html?view=rendered`;
  await expect(viewer).toHaveURL(viewerUrl);
  expect(await viewer.evaluate(() => window.opener)).toBeNull();

  const frame = viewer.getByTitle("Sandboxed HTML preview for navigation.html");
  await expect(frame).toHaveAttribute("sandbox", "");
  const content = frame.contentFrame();
  await expect(
    content.getByRole("heading", { name: "Leaving Crabinet" }),
  ).toBeVisible();

  // A target=_top link is refused by the iframe sandbox and leaves the page
  // in place; a plain link may only try to move the frame, which the
  // application CSP refuses, so it goes last.
  await content
    .getByRole("link", { name: "Continue in this tab", exact: true })
    .click();
  expect(viewer.url()).toBe(viewerUrl);
  await content
    .getByRole("link", { name: "Continue to the external site", exact: true })
    .click();
  expect(viewer.url()).toBe(viewerUrl);
  // The page also asks for a refresh to the external origin after two
  // seconds; wait past it.
  await viewer.waitForTimeout(3_000);

  expect(viewer.url()).toBe(viewerUrl);
  expect(await viewer.evaluate(() => window.location.href)).toBe(viewerUrl);
  await expect(
    viewer.getByRole("heading", { name: "navigation.html", level: 1 }),
  ).toBeVisible();
  expect(externalRequests).toEqual([]);

  // Back returns to the file in its folder.
  await viewer
    .getByRole("link", { name: "Back to folder", exact: true })
    .click();
  await expect(viewer).toHaveURL(`${appOrigin}/read-only/navigation.html`);
  await expect(
    viewer.getByRole("heading", { name: "navigation.html", level: 2 }),
  ).toBeVisible();
  expect(externalRequests).toEqual([]);
});

test("keyboard navigation, responsive layout, and primary views pass axe", async ({
  page,
}) => {
  await page.goto("/");

  const homeLink = page.getByRole("link", {
    name: "Crabinet home",
    exact: true,
  });
  await homeLink.focus();
  await expect(homeLink).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Username")).toBeFocused();

  let results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter(({ impact }) =>
      ["critical", "serious"].includes(impact ?? ""),
    ),
  ).toEqual([]);

  await signIn(page, "reader");
  await page.getByRole("link", { name: "hello.rs", exact: true }).click();
  await expect(page.getByLabel("File source")).toBeVisible();

  await expect(page.getByRole("button", { name: "Reset zoom" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Zoom out" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Zoom in" })).toHaveCount(0);
  await page.getByRole("button", { name: "Expand preview" }).click();
  const fullScreenPreview = page.locator(".preview-panel.is-fullscreen");
  await expect(fullScreenPreview).toBeVisible();
  await expect(page.locator(".preview-modal-backdrop")).toBeVisible();
  await expect(page.getByText("Expanded preview")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Restore side preview" }),
  ).toHaveAttribute("data-tooltip", "Restore side preview");
  const fullScreenBox = await fullScreenPreview.boundingBox();
  const viewport = page.viewportSize();
  expect(fullScreenBox).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(fullScreenBox!.x).toBeGreaterThan(0);
  expect(fullScreenBox!.y).toBeGreaterThanOrEqual(31);
  expect(Math.round(fullScreenBox!.width)).toBeLessThan(viewport!.width);
  expect(Math.round(fullScreenBox!.height)).toBeLessThan(viewport!.height);
  const scrollBehavior = await fullScreenPreview.evaluate((panel) => {
    const spacer = document.createElement("div");
    spacer.style.height = "2000px";
    spacer.style.flex = "0 0 2000px";
    panel.append(spacer);
    panel.scrollTop = 300;
    const result = {
      overflowY: getComputedStyle(panel).overflowY,
      scrollable: panel.scrollHeight > panel.clientHeight,
      scrolled: panel.scrollTop > 0,
    };
    spacer.remove();
    return result;
  });
  expect(scrollBehavior).toEqual({
    overflowY: "auto",
    scrollable: true,
    scrolled: true,
  });
  const backdropStyles = await page
    .locator(".preview-modal-backdrop")
    .evaluate((element) => ({
      background: getComputedStyle(element).backgroundColor,
      blur: getComputedStyle(element).backdropFilter,
    }));
  expect(backdropStyles.background).not.toBe("rgba(0, 0, 0, 0)");
  expect(backdropStyles.blur).toContain("blur");
  results = await new AxeBuilder({ page })
    .exclude("iframe")
    .exclude(".app-footer")
    .analyze();
  expect(
    results.violations.filter(({ impact }) =>
      ["critical", "serious"].includes(impact ?? ""),
    ),
  ).toEqual([]);
  await page
    .locator(".preview-modal-backdrop")
    .click({ position: { x: 4, y: 4 } });
  await expect(
    page.getByRole("button", { name: "Expand preview" }),
  ).toBeVisible();
  await expect(fullScreenPreview).toHaveCount(0);

  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);

  results = await new AxeBuilder({ page })
    .exclude("iframe")
    .exclude(".app-footer")
    .analyze();
  expect(
    results.violations.filter(({ impact }) =>
      ["critical", "serious"].includes(impact ?? ""),
    ),
  ).toEqual([]);
});

test("the folder toolbar drops its labels before leaving the title's line", async ({
  page,
}) => {
  const actions = page.locator(".directory-heading-actions");
  // Buttons differ in height, so compare vertical centres: a wrapped button
  // shows up as a second row.
  const rows = () =>
    actions.evaluate((element) => {
      const centres = Array.from(element.querySelectorAll("button")).map(
        (button) => {
          const box = button.getBoundingClientRect();
          return Math.round(box.top + box.height / 2);
        },
      );
      return {
        rows: new Set(centres).size,
        overflow:
          element.scrollWidth > element.clientWidth ||
          element.querySelector("button")!.getBoundingClientRect().left <
            element.getBoundingClientRect().left,
        compact: element.classList.contains("is-compact"),
        beside:
          element.getBoundingClientRect().top <
          document.querySelector("#directory-title")!.getBoundingClientRect()
            .bottom,
      };
    });

  // Labels fit beside the title at some width only without a preview; with
  // one open, whether they ever fit depends on the fonts installed.
  for (const [route, expectLabels] of [
    ["/writable/Projects", true],
    ["/writable/Projects/example.toml", false],
  ] as const) {
    if (route.endsWith(".toml")) await page.goto(route);
    else await openSignedIn(page, route, "writer");
    await expect(page.getByRole("button", { name: "New file" })).toBeVisible();
    let sawCompact = false;
    let sawLabels = false;
    let sawIconsBeside = false;
    for (let width = 300; width <= 1400; width += 20) {
      await page.setViewportSize({ width, height: 800 });
      // Two frames let the resize observer deliver and the class apply.
      await page.evaluate(
        () =>
          new Promise((resolve) =>
            requestAnimationFrame(() => requestAnimationFrame(resolve)),
          ),
      );
      await expect
        .poll(rows, { message: `${route} at ${width}px` })
        .toMatchObject({ rows: 1, overflow: false });
      const state = await rows();
      sawCompact ||= state.compact;
      sawLabels ||= !state.compact;
      sawIconsBeside ||= state.compact && state.beside;
    }
    expect(sawCompact).toBe(true);
    if (expectLabels) expect(sawLabels).toBe(true);
    expect(sawIconsBeside).toBe(true);
  }
});

test("a folder downloads as a ZIP of its files", async ({ page }) => {
  await openSignedIn(page, "/read-only/nested");

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page
      .getByRole("link", { name: "Download nested as ZIP", exact: true })
      .click(),
  ]);
  expect(download.suggestedFilename()).toBe("nested.zip");
  expect(await download.failure()).toBeNull();
  const archive = await readFile((await download.path())!);
  // Entries are stored, so names and contents appear verbatim.
  expect(archive.subarray(0, 4).toString("latin1")).toBe("PK\u0003\u0004");
  const text = archive.toString("utf8");
  expect(text).toContain("nested/notes.txt");
  expect(text).toContain(
    "This file proves direct nested routes and browser history work.",
  );
  // The download leaves the folder open.
  await expect(page).toHaveURL(/\/read-only\/nested$/);
});

test("a folder row shows its size, from the listing once the server has it cached", async ({
  page,
}) => {
  const sizeRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname === "/api/v1/shares/read-only/folder-size") {
      sizeRequests.push(url.searchParams.get("path") ?? "");
    }
  });
  const rootListing = () =>
    page.waitForResponse((response) => {
      const url = new URL(response.url());
      return (
        url.pathname === "/api/v1/shares/read-only/directory" &&
        url.searchParams.get("path") === ""
      );
    });
  const listedSize = async (listing: Promise<Response>) => {
    const body = (await (await listing).json()) as {
      entries: Array<{ name: string; folderSize?: unknown }>;
    };
    return body.entries.find((entry) => entry.name === "nested")?.folderSize;
  };

  const first = rootListing();
  await openSignedIn(page, "/read-only");
  const row = page
    .getByRole("list", { name: "Folder contents" })
    .getByRole("listitem")
    .filter({ has: page.getByRole("link", { name: "nested", exact: true }) });
  // The Size column stays visible on narrow screens, so phones get it too.
  await expect(row.locator(".entry-meta")).toBeVisible();
  await expect(row.locator(".entry-meta")).toHaveText("64 B");
  // An earlier test may have had the folder walked within the cache's
  // minute; otherwise the client asked for it.
  if ((await listedSize(first)) === undefined) {
    expect(sizeRequests).toEqual(["nested"]);
  }

  // Now cached, the size comes with the listing and nothing is asked.
  sizeRequests.length = 0;
  const second = rootListing();
  await page.reload();
  expect(await listedSize(second)).toEqual({ size: 64, complete: true });
  await expect(row.locator(".entry-meta")).toHaveText("64 B");
  await expect(page.getByRole("img", { name: "Calculating size" })).toHaveCount(
    0,
  );
  expect(sizeRequests).toEqual([]);
  const results = await new AxeBuilder({ page })
    .include(".entry-list")
    .analyze();
  expect(results.violations).toEqual([]);
});

test("an iPad in portrait shows two columns", async ({ page }) => {
  await page.setViewportSize({ width: 820, height: 1180 });
  await openSignedIn(page);

  const tree = page.getByRole("complementary", { name: "Shared folders" });
  const list = page.locator(".directory-column");
  await expect(tree).toBeVisible();
  const treeBox = (await tree.boundingBox())!;
  const listBox = (await list.boundingBox())!;
  expect(listBox.x).toBeGreaterThanOrEqual(treeBox.x + treeBox.width);
  expect(Math.abs(listBox.y - treeBox.y)).toBeLessThan(2);

  await page.getByRole("link", { name: "hello.rs", exact: true }).click();
  const preview = page.locator(".preview-panel");
  await expect(page.getByLabel("File source")).toBeVisible();
  await expect(tree).toBeHidden();
  const openListBox = (await list.boundingBox())!;
  const previewBox = (await preview.boundingBox())!;
  expect(previewBox.x).toBeGreaterThanOrEqual(
    openListBox.x + openListBox.width,
  );
  expect(Math.abs(previewBox.y - openListBox.y)).toBeLessThan(2);

  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
});

test("file rows keep room for their names on desktops, tablets, and phones", async ({
  browser,
}, testInfo) => {
  test.skip(
    testInfo.project.name !== "desktop-chromium",
    "each layout below sets its own viewport and input",
  );
  // The name the iPad screenshot wrapped as "test-" / "pattern.m" / "p4".
  const longName = "test-pattern.mp4";
  const layouts = [
    // label, viewport, touch, preview open, inline actions, menu
    ["desktop", 1440, 960, false, false, 5, false],
    ["desktop with a preview", 1440, 960, false, true, 5, false],
    ["iPad landscape", 1180, 820, true, false, 5, false],
    ["iPad landscape with a preview", 1180, 820, true, true, 2, true],
    ["iPad portrait", 820, 1180, true, false, 2, true],
    ["iPad portrait with a preview", 820, 1180, true, true, 0, true],
    ["phone", 390, 844, true, false, 0, true],
  ] as const;
  for (const [label, width, height, touch, preview, inline, menu] of layouts) {
    const context = await browser.newContext({
      viewport: { width, height },
      hasTouch: touch,
    });
    const page = await context.newPage();
    try {
      await openSignedIn(
        page,
        preview ? "/writable/README.md" : "/writable",
        "writer",
      );
      if (preview) {
        await expect(
          page.getByRole("heading", { name: "README.md", level: 2 }),
        ).toBeVisible();
      }
      expect(
        await page.evaluate(() => matchMedia("(pointer: coarse)").matches),
        label,
      ).toBe(touch);
      const row = page
        .getByRole("list", { name: "Folder contents" })
        .getByRole("listitem")
        .filter({
          has: page.getByRole("link", { name: "README.md", exact: true }),
        });
      await expect(row).toBeVisible();

      const actions = row.getByRole("group", { name: "Actions for README.md" });
      const shown = actions.locator(".entry-actions-inline .entry-action");
      const visible = await shown.evaluateAll(
        (elements) =>
          elements.filter((element) => element.checkVisibility()).length,
      );
      expect(visible, label).toBe(inline);
      const more = row.getByRole("button", {
        name: "More actions for README.md",
      });
      if (menu) await expect(more, label).toBeVisible();
      else await expect(more, label).toBeHidden();
      if (inline === 2) {
        // Download and Delete stay; the rarer actions wait in the menu.
        await expect(
          row.getByRole("link", { name: "Download README.md" }),
        ).toBeVisible();
        await expect(
          row.getByRole("button", { name: "Delete README.md" }),
        ).toBeVisible();
        await expect(
          row.getByRole("button", { name: "Rename README.md" }),
        ).toBeHidden();
      }

      const layout = await row.evaluate((element, name) => {
        const link = element.querySelector<HTMLElement>(".entry-name")!;
        const primary = element.querySelector<HTMLElement>(".entry-primary")!;
        const context = document.createElement("canvas").getContext("2d")!;
        context.font = getComputedStyle(link).font;
        const buttons = Array.from(
          element.querySelectorAll<HTMLElement>(".entry-action"),
        )
          .filter((button) => button.checkVisibility())
          .map((button) => button.getBoundingClientRect());
        return {
          nameWidth: context.measureText(name).width,
          room: primary.clientWidth,
          overflow: element.scrollWidth > element.clientWidth,
          smallestTarget: Math.min(
            ...buttons.map((box) => Math.min(box.width, box.height)),
          ),
          widestStep: Math.max(
            0,
            ...buttons
              .slice(1)
              .map((box, index) => box.left - buttons[index]!.left),
          ),
          listWidth: element.closest(".entry-list")!.clientWidth,
        };
      }, longName);
      expect(layout.overflow, label).toBe(false);
      expect(layout.nameWidth, label).toBeLessThanOrEqual(layout.room);
      if (touch) {
        expect(layout.smallestTarget, label).toBeGreaterThanOrEqual(44);
      }
      // In a narrower list the buttons sit side by side; only Delete keeps a
      // small gap.
      if (layout.listWidth <= 704) {
        expect(layout.widestStep, label).toBeLessThanOrEqual(touch ? 49 : 35);
      }

      if (menu && inline === 2) {
        // The menu still opens beside its button inside the list's
        // size container, and holds the rarer actions.
        await more.click();
        const list = page.getByRole("menu", { name: "Actions for README.md" });
        await expect(
          list.getByRole("menuitem", { name: "Rename" }),
        ).toBeVisible();
        const trigger = (await more.boundingBox())!;
        const opened = (await list.boundingBox())!;
        expect(
          Math.abs(opened.y - (trigger.y + trigger.height)),
          label,
        ).toBeLessThan(12);
        expect(
          Math.abs(opened.x + opened.width - (trigger.x + trigger.width)),
          label,
        ).toBeLessThan(2);
        await page.keyboard.press("Escape");
        const results = await new AxeBuilder({ page })
          .include(".entry-list")
          .analyze();
        expect(results.violations, label).toEqual([]);
      }
    } finally {
      await context.close();
    }
  }
});

test("night mode follows the system, can be pinned, and passes axe", async ({
  page,
}) => {
  const seriousViolations = async (exclude?: string) => {
    // The version footer is deliberately faint; see .app-footer.
    const builder = new AxeBuilder({ page }).exclude(".app-footer");
    if (exclude) builder.exclude(exclude);
    return (await builder.analyze()).violations.filter(({ impact }) =>
      ["critical", "serious"].includes(impact ?? ""),
    );
  };
  const pageBackground = () =>
    page.evaluate(() => getComputedStyle(document.documentElement).background);

  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Sign in to Crabinet" }),
  ).toBeVisible();
  expect(await pageBackground()).toContain("rgb(15, 21, 18)");
  expect(await seriousViolations()).toEqual([]);

  await signIn(page, "reader");
  await page.getByRole("link", { name: "hello.rs", exact: true }).click();
  const source = page.getByLabel("File source");
  await expect(source).toHaveAttribute("aria-busy", "false");
  const token = source.locator("span[style*='--shiki-dark']").first();
  const tokenColors = await token.evaluate((element) => ({
    color: getComputedStyle(element).color,
    dark: element.style.getPropertyValue("--shiki-dark"),
  }));
  const probe = await page.evaluate((hex) => {
    const element = document.createElement("span");
    element.style.color = hex;
    document.body.append(element);
    const color = getComputedStyle(element).color;
    element.remove();
    return color;
  }, tokenColors.dark);
  expect(tokenColors.color).toBe(probe);
  expect(await seriousViolations("iframe")).toEqual([]);

  await page.getByRole("button", { name: "Settings" }).click();
  const dialog = page.getByRole("dialog", { name: "Settings" });
  expect(await seriousViolations("iframe")).toEqual([]);
  const savedAppearance = (theme: string) =>
    page.waitForResponse(
      (response) =>
        response.url().endsWith("/api/v1/preferences/display") &&
        response.request().postDataJSON()?.theme === theme &&
        response.ok(),
    );
  const savedLight = savedAppearance("light");
  await dialog.getByRole("tab", { name: "Appearance" }).click();
  await dialog.getByLabel("Theme").selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await pageBackground()).toContain("rgb(242, 244, 239)");
  await savedLight;

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await pageBackground()).toContain("rgb(242, 244, 239)");
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCSS(
    "border-top-color",
    "rgb(174, 184, 176)",
  );

  // The choice is saved to the account, so later tests signing in as the
  // same user would inherit it; restore the default.
  await page.getByRole("button", { name: "Settings" }).click();
  const savedSystem = savedAppearance("system");
  await dialog.getByRole("tab", { name: "Appearance" }).click();
  await dialog.getByLabel("Theme").selectOption("system");
  await savedSystem;
  await expect(page.locator("html")).not.toHaveAttribute("data-theme");
});

test("connection failure can recover and an expired session returns to login", async ({
  page,
}) => {
  await page.route("**/api/v1/session", async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "temporarily_unavailable", message: "retry" },
      }),
    });
  });
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText(
    "Crabinet is unavailable",
  );
  await page.unroute("**/api/v1/session");
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to Crabinet" }),
  ).toBeVisible();

  await signIn(page, "reader");
  await expect(
    page.getByRole("link", { name: "Guide.md", exact: true }),
  ).toBeVisible();
  await page.route("**/api/v1/shares/*/preview?**", async (route) => {
    await route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "unauthorized", message: "session expired" },
      }),
    });
  });
  await page.getByRole("link", { name: "Guide.md", exact: true }).click();
  await expect(
    page.getByText("Your session expired. Sign in again to continue."),
  ).toBeVisible();
});

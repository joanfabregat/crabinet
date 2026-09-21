import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { csrfToken, openSignedIn, signIn } from "./helpers";

test("login, secure session cookie, read-only enforcement, and logout", async ({
  context,
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Sign in to Index" }),
  ).toBeVisible();

  await page.getByLabel("Username").fill("reader");
  await page.getByLabel("Password").fill("incorrect-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Sign-in failed");

  await signIn(page, "reader");
  await expect(page.getByLabel("Read only")).toHaveText("R");
  await expect(
    page.getByRole("region", { name: "File operations" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /^(Edit|Rename|Move|Delete) / }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /^Copy full path for / }).first(),
  ).toBeVisible();

  const cookies = await context.cookies();
  const sessionCookie = cookies.find(
    (cookie) => cookie.name === "index_session",
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
    page.getByRole("heading", { name: "Sign in to Index" }),
  ).toBeVisible();
  expect(
    (await context.cookies()).some((cookie) => cookie.name === "index_session"),
  ).toBe(false);
});

test("direct routes, tree share navigation, breadcrumbs, and browser history", async ({
  page,
}) => {
  await page.goto("/browse/writable?path=Projects");
  await signIn(page, "writer");

  await expect(page).toHaveURL(/\/browse\/writable\?path=Projects$/);
  await expect(
    page.getByRole("heading", { name: "Projects", level: 1 }),
  ).toBeFocused();
  await expect(page.getByRole("link", { name: "example.toml" })).toBeVisible();

  await page
    .getByLabel("Breadcrumb")
    .getByRole("link", { name: "Working files" })
    .click();
  await expect(page).toHaveURL(/\/browse\/writable$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/browse\/writable\?path=Projects$/);
  await expect(page.getByRole("link", { name: "example.toml" })).toBeVisible();

  await page
    .getByLabel("Shared folders", { exact: true })
    .getByRole("link", { name: "Reference library" })
    .click();
  await expect(page).toHaveURL(/\/browse\/read-only$/);
  await expect(page.getByLabel("Read only")).toHaveText("R");
  await expect(page.getByRole("link", { name: "nested" })).toBeVisible();

  await page.getByRole("link", { name: "nested" }).click();
  await expect(page).toHaveURL(/path=nested/);
  await expect(page.getByRole("link", { name: "notes.txt" })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("link", { name: "Guide.md" })).toBeVisible();
});

test("hostile Markdown and HTML remain inert in-panel and in a new tab", async ({
  context,
  page,
}) => {
  const externalRequests: string[] = [];
  context.on("response", (response) => {
    if (response.url().startsWith("https://attacker.invalid")) {
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
  await page.getByRole("link", { name: "Guide.md" }).click();
  await expect(
    page.getByRole("heading", { name: "Guide.md", level: 2 }),
  ).toBeFocused();
  await expect(page.getByTestId("markdown-document")).toContainText(
    "window.__indexHostileScript",
  );
  expect(await page.locator("script").count()).toBe(1);
  expect(await page.locator("img, form").count()).toBe(0);
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

  await page.getByRole("link", { name: "hostile.html" }).click();
  const frame = page.getByTitle("Sandboxed HTML preview for hostile.html");
  await expect(frame).toHaveAttribute("sandbox", "");
  await expect(frame).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/html/rendered?path=hostile.html",
  );
  await expect(frame.contentFrame().locator("body")).toContainText("Sign out");
  expect(await page.evaluate(() => localStorage.getItem("hostile"))).toBeNull();
  expect(externalRequests).toEqual([]);
  expect(dialogs).toBe(0);

  const [renderedPage] = await Promise.all([
    page.waitForEvent("popup"),
    page.getByRole("link", { name: "Open rendered HTML in new tab" }).click(),
  ]);
  await renderedPage.waitForLoadState("domcontentloaded");
  await expect(renderedPage.locator("body")).toContainText("Sign out");
  expect(
    await renderedPage.evaluate(() =>
      Boolean(
        (window as Window & { __indexHostileHtml?: boolean })
          .__indexHostileHtml,
      ),
    ),
  ).toBe(false);
  expect(await renderedPage.evaluate(() => window.opener)).toBeNull();
  expect(renderedPage.url()).toContain(
    "/api/v1/shares/read-only/preview/html/rendered?path=hostile.html",
  );
  expect(externalRequests).toEqual([]);
  await renderedPage.close();

  await page.getByRole("tab", { name: "Source" }).click();
  const sourceFrame = page.getByTitle("Inert HTML source for hostile.html");
  await expect(sourceFrame).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/html?path=hostile.html",
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
    page.getByRole("link", { name: "Open HTML source in new tab" }).click(),
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

test("keyboard navigation, responsive layout, and primary views pass axe", async ({
  page,
}) => {
  await page.goto("/");

  const homeLink = page.getByRole("link", { name: "Index home" });
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
  await page.getByRole("link", { name: "hello.rs" }).click();
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
  ).toContainText("Restore side preview");
  const fullScreenBox = await fullScreenPreview.boundingBox();
  const viewport = page.viewportSize();
  expect(fullScreenBox).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(fullScreenBox!.x).toBeGreaterThan(0);
  expect(fullScreenBox!.y).toBeGreaterThan(0);
  expect(Math.round(fullScreenBox!.width)).toBeLessThan(viewport!.width);
  expect(Math.round(fullScreenBox!.height)).toBeLessThan(viewport!.height);
  const backdropStyles = await page
    .locator(".preview-modal-backdrop")
    .evaluate((element) => ({
      background: getComputedStyle(element).backgroundColor,
      blur: getComputedStyle(element).backdropFilter,
    }));
  expect(backdropStyles.background).not.toBe("rgba(0, 0, 0, 0)");
  expect(backdropStyles.blur).toContain("blur");
  results = await new AxeBuilder({ page }).exclude("iframe").analyze();
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

  results = await new AxeBuilder({ page }).exclude("iframe").analyze();
  expect(
    results.violations.filter(({ impact }) =>
      ["critical", "serious"].includes(impact ?? ""),
    ),
  ).toEqual([]);
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
  await expect(page.getByRole("alert")).toContainText("Index is unavailable");
  await page.unroute("**/api/v1/session");
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to Index" }),
  ).toBeVisible();

  await signIn(page, "reader");
  await expect(page.getByRole("link", { name: "Guide.md" })).toBeVisible();
  await page.route("**/api/v1/shares/*/preview?**", async (route) => {
    await route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "unauthorized", message: "session expired" },
      }),
    });
  });
  await page.getByRole("link", { name: "Guide.md" }).click();
  await expect(
    page.getByText("Your session expired. Sign in again to continue."),
  ).toBeVisible();
});

import { expect, test, type BrowserContext, type Page } from "@playwright/test";

import { openSignedIn } from "./helpers";

const notice =
  "Showing the first 1000 lines (52.0 kB) of 312.0 kB. Open in new tab or download for the full file.";

test("a log above the preview limit shows its head, the notice, and opens whole", async ({
  page,
}) => {
  await openSignedIn(page, "/read-only");
  await page.getByRole("link", { name: "server.log", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "server.log", level: 2 }),
  ).toBeFocused();
  const panel = page.getByRole("complementary", { name: "server.log" });
  await expect(panel.getByText(notice)).toBeVisible();
  const source = panel.getByLabel("File source");
  await expect(source).toContainText(
    "2026-01-01T00:00:00Z entry 00001 synthetic log line",
  );
  await expect(source).toContainText("entry 01000 synthetic log line");
  await expect(source).not.toContainText("entry 01001");
  await expect(panel.getByRole("button", { name: /^Edit/ })).toHaveCount(0);

  const response = await page.request.get(
    "/api/v1/shares/read-only/preview?path=server.log",
  );
  expect(response.status()).toBe(200);
  const document = (await response.json()) as Record<string, unknown>;
  expect(document).toMatchObject({
    kind: "text",
    truncated: true,
    size: 312_000,
    shownBytes: 52_000,
    shownLines: 1000,
    openable: true,
  });

  // Open in new tab serves the whole file as inert text.
  const [opened] = await Promise.all([
    page.waitForEvent("popup"),
    panel
      .getByRole("link", { name: "Open server.log in a new tab", exact: true })
      .click(),
  ]);
  await opened.waitForLoadState("domcontentloaded");
  await expect(opened.locator("body")).toContainText(
    "entry 06000 synthetic log line",
  );
  await opened.close();
});

/**
 * Records dialogs and every request for another origin that the browser did
 * not block before it reached the network.
 *
 * Chromium reports a subresource refused by the CSP (`csp`) or by its
 * cross-origin SVG reference rule (`origin`) as a failed request, without
 * sending it; Firefox reports nothing for such a request. Anything else, a
 * response or a failure from the network itself such as an unresolvable
 * host, means the request left the browser.
 */
function watchHostileEffects(context: BrowserContext, origin: string) {
  const effects = { dialogs: [] as string[], foreign: [] as string[] };
  const watchPage = (watched: Page) => {
    watched.on("dialog", async (dialog) => {
      effects.dialogs.push(dialog.message());
      await dialog.dismiss();
    });
  };
  const isForeign = (raw: string) => {
    const url = new URL(raw);
    return (
      url.origin !== origin &&
      url.protocol !== "data:" &&
      url.protocol !== "about:"
    );
  };
  context.on("page", watchPage);
  context.pages().forEach(watchPage);
  context.on("requestfailed", (request) => {
    const reason = request.failure()?.errorText ?? "";
    if (isForeign(request.url()) && reason !== "csp" && reason !== "origin") {
      effects.foreign.push(`${request.url()} failed: ${reason}`);
    }
  });
  context.on("response", (response) => {
    if (isForeign(response.url())) {
      effects.foreign.push(`${response.url()} answered ${response.status()}`);
    }
  });
  return effects;
}

test("a hostile SVG renders as an inert image in the panel and in a new tab", async ({
  context,
  page,
  baseURL,
}) => {
  const origin = new URL(baseURL!).origin;
  const effects = watchHostileEffects(context, origin);

  await openSignedIn(page, "/read-only");
  await page.getByRole("link", { name: "hostile.svg", exact: true }).click();
  const panel = page.getByRole("complementary", { name: "hostile.svg" });
  const image = panel.getByRole("img", { name: "Preview of hostile.svg" });
  await expect(image).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/svg?path=hostile.svg&v=0-0",
  );
  await expect
    .poll(() =>
      image.evaluate((element: HTMLImageElement) => element.naturalWidth),
    )
    .toBe(320);
  await expect(
    panel.getByRole("status", { name: "Loading preview" }),
  ).toHaveCount(0);
  await expect(panel.getByRole("tab", { name: "Image" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  // Clicking the image reaches no link or handler inside it.
  await image.click({ position: { x: 50, y: 175 } });
  await image.click({ position: { x: 160, y: 175 } });
  await page.waitForTimeout(500);
  await expect(page).toHaveURL(/\/read-only\/hostile\.svg$/);
  expect(
    await page.evaluate(() => localStorage.getItem("hostile-svg")),
  ).toBeNull();

  await panel.getByRole("tab", { name: "Source" }).click();
  await expect(panel.getByLabel("File source")).toContainText(
    'window.__hostileSvg = "script";',
  );

  const svgResponse = await page.request.get(
    "/api/v1/shares/read-only/preview/svg?path=hostile.svg",
  );
  expect(svgResponse.status()).toBe(200);
  expect(svgResponse.headers()["content-type"]).toBe("image/svg+xml");
  expect(svgResponse.headers()["content-security-policy"]).toMatch(
    /^sandbox; default-src 'none'/,
  );
  expect(svgResponse.headers()["x-content-type-options"]).toBe("nosniff");

  // Open in new tab shows the image as a top-level document.
  const [svgPage] = await Promise.all([
    page.waitForEvent("popup"),
    panel
      .getByRole("link", { name: "Open hostile.svg in a new tab", exact: true })
      .click(),
  ]);
  const documentResponse = await page.request.get(
    "/api/v1/shares/read-only/open?path=hostile.svg",
  );
  expect(documentResponse.headers()["content-type"]).toBe("image/svg+xml");
  expect(documentResponse.headers()["content-security-policy"]).toMatch(
    /^sandbox; default-src 'none'/,
  );
  await svgPage.waitForLoadState("load");
  const openedUrl = svgPage.url();
  expect(openedUrl).toContain("/api/v1/shares/read-only/open?path=hostile.svg");
  // The page is drawn as SVG, and a meta refresh in a foreignObject does not
  // move it.
  expect(
    await svgPage.evaluate(() => document.documentElement.namespaceURI),
  ).toBe("http://www.w3.org/2000/svg");
  await svgPage.waitForTimeout(1500);
  expect(svgPage.url()).toBe(openedUrl);
  expect(
    await svgPage.evaluate(
      () => (window as Window & { __hostileSvg?: string }).__hostileSvg,
    ),
  ).toBeUndefined();

  // Neither a javascript: link, an event handler, a form, nor a popup link
  // does anything, whether clicked by pointer or activated directly (Firefox
  // gives the small foreignObject's controls no pointer target).
  for (const selector of [
    "#javascript-link",
    "#click-handler",
    "#hostile-submit",
    "#popup-link",
  ]) {
    const target = svgPage.locator(selector);
    await target.click({ force: true });
    await target.dispatchEvent("click");
    await svgPage.waitForTimeout(300);
    expect(svgPage.url(), selector).toBe(openedUrl);
  }
  expect(
    await svgPage.evaluate(
      () => (window as Window & { __hostileSvg?: string }).__hostileSvg,
    ),
  ).toBeUndefined();
  expect(context.pages()).toHaveLength(2);
  await svgPage.close();

  expect(
    await page.evaluate(() => localStorage.getItem("hostile-svg")),
  ).toBeNull();
  expect(
    (await context.cookies()).some((cookie) => cookie.name === "hostile-svg"),
  ).toBe(false);
  expect(effects.dialogs).toEqual([]);
  expect(effects.foreign).toEqual([]);
});

test("HTML above the preview limit shows its head in the panel and renders whole in the viewer", async ({
  context,
  page,
  baseURL,
}) => {
  const origin = new URL(baseURL!).origin;
  const effects = watchHostileEffects(context, origin);

  await openSignedIn(page, "/read-only");
  await page.getByRole("link", { name: "large.html", exact: true }).click();
  const panel = page.getByRole("complementary", { name: "large.html" });
  await expect(panel.getByText(/^Showing the first 1000 lines/)).toBeVisible();
  await expect(panel.getByLabel("File source")).toContainText(
    "synthetic paragraph 00001 of a large page",
  );
  // The panel never frames a head.
  await expect(panel.locator("iframe")).toHaveCount(0);

  const response = await page.request.get(
    "/api/v1/shares/read-only/preview?path=large.html",
  );
  expect(await response.json()).toMatchObject({
    kind: "html_source",
    truncated: true,
    size: 294_080,
    renderable: true,
  });

  const [viewer] = await Promise.all([
    page.waitForEvent("popup"),
    panel
      .getByRole("link", { name: "Open rendered HTML in new tab", exact: true })
      .click(),
  ]);
  await expect(viewer).toHaveURL(/\/read-only\/large\.html\?view=rendered$/);
  const frame = viewer.getByTitle("Sandboxed HTML preview for large.html");
  await expect(frame).toHaveAttribute("sandbox", "");
  await expect(frame).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/html/rendered?path=large.html",
  );
  // The whole document streams in, not only the head the panel shows.
  await expect(frame.contentFrame().locator("#last")).toHaveText(
    "End of the large page",
  );
  await viewer.close();

  // Under the same headers as a small document.
  const rendered = await page.request.get(
    "/api/v1/shares/read-only/preview/html/rendered?path=large.html",
  );
  expect(rendered.status()).toBe(200);
  expect(rendered.headers()["content-type"]).toBe("text/html; charset=utf-8");
  expect(rendered.headers()["content-security-policy"]).toMatch(
    /^sandbox; default-src 'none'/,
  );
  expect(rendered.headers()["x-content-type-options"]).toBe("nosniff");
  expect(rendered.headers()["content-length"]).toBe("294080");

  // Above the render limit, the viewer refuses and the route answers 413.
  const huge = await page.request.get(
    "/api/v1/shares/read-only/preview/html/rendered?path=huge.html",
  );
  expect(huge.status()).toBe(413);
  await page.goto("/read-only/huge.html?view=rendered");
  await expect(page.getByText("File is too large to render")).toBeVisible();
  await expect(page.locator("iframe")).toHaveCount(0);

  expect(effects.dialogs).toEqual([]);
  expect(effects.foreign).toEqual([]);
});

test("an SVG above the preview limit is drawn whole and opens as an image", async ({
  page,
}) => {
  await openSignedIn(page, "/read-only");
  await page.getByRole("link", { name: "large.svg", exact: true }).click();
  const panel = page.getByRole("complementary", { name: "large.svg" });
  const image = panel.getByRole("img", { name: "Preview of large.svg" });
  await expect(image).toHaveAttribute(
    "src",
    "/api/v1/shares/read-only/preview/svg?path=large.svg&v=0-0",
  );
  await expect
    .poll(() =>
      image.evaluate((element: HTMLImageElement) => element.naturalWidth),
    )
    .toBe(320);
  await panel.getByRole("tab", { name: "Source" }).click();
  await expect(panel.getByText(/^Showing the first 1000 lines/)).toBeVisible();

  const opened = await page.request.get(
    "/api/v1/shares/read-only/open?path=large.svg",
  );
  expect(opened.headers()["content-type"]).toBe("image/svg+xml");
  expect(opened.headers()["content-security-policy"]).toMatch(
    /^sandbox; default-src 'none'/,
  );
  expect(opened.headers()["content-length"]).toBe("437369");
});

test("a HEIC image is served as the original and explains when the browser cannot show it", async ({
  page,
}) => {
  await openSignedIn(page, "/read-only");
  await page.getByRole("link", { name: "photo.heic", exact: true }).click();
  const panel = page.getByRole("complementary", { name: "photo.heic" });

  const response = await page.request.get(
    "/api/v1/shares/read-only/preview?path=photo.heic",
  );
  expect(await response.json()).toMatchObject({
    kind: "image",
    mimeType: "image/heic",
    openable: true,
    thumbnailable: false,
  });
  const thumbnail = await page.request.get(
    "/api/v1/shares/read-only/thumbnail?path=photo.heic&size=1600",
  );
  expect(thumbnail.status()).toBe(415);
  const opened = await page.request.get(
    "/api/v1/shares/read-only/open?path=photo.heic",
  );
  expect(opened.headers()["content-type"]).toBe("image/heic");
  expect(opened.headers()["content-security-policy"]).toMatch(
    /^sandbox; default-src 'none'/,
  );

  // Chromium does not decode HEIC (Safari does), so the panel says so and
  // offers the download instead of a generic error.
  const fallback = panel.getByRole("alert");
  await expect(fallback).toContainText(
    "This browser can't display HEIC images. Download it to view.",
  );
  await expect(
    fallback.getByRole("link", { name: "Download image" }),
  ).toHaveAttribute(
    "href",
    "/api/v1/shares/read-only/download?path=photo.heic",
  );
});

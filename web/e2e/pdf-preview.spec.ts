import { expect, test } from "@playwright/test";

import { openSignedIn } from "./helpers";

test("a PDF previews its first page with pdf.js under the application CSP", async ({
  page,
}) => {
  const cspViolations: string[] = [];
  const pageErrors: string[] = [];
  page.on("console", (message) => {
    const text = message.text();
    if (/content security policy|refused to/i.test(text)) {
      cspViolations.push(text);
    }
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));
  const openRequests: { status: number; range: string | null }[] = [];
  page.on("response", (response) => {
    if (new URL(response.url()).pathname.endsWith("/open")) {
      openRequests.push({
        status: response.status(),
        range: response.request().headers()["range"] ?? null,
      });
    }
  });
  // Recorded in the page itself as well, so violations reported only as
  // events (from the worker or a blocked fetch) are caught too.
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __cspViolations: string[] }).__cspViolations = seen;
    document.addEventListener("securitypolicyviolation", (event) => {
      seen.push(`${event.effectiveDirective} ${event.blockedURI}`);
    });
  });

  await openSignedIn(page);
  await page.getByRole("link", { name: "text.pdf", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "text.pdf", level: 2 }),
  ).toBeFocused();

  const firstPage = page.getByRole("img", { name: "First page of text.pdf" });
  await expect(firstPage).toBeVisible();
  await expect(
    page.getByRole("status", { name: "Loading preview" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "Open text.pdf in a new tab", exact: true }),
  ).toHaveAttribute("href", "/api/v1/shares/read-only/open?path=text.pdf");
  await expect(
    page
      .getByRole("complementary", { name: "text.pdf" })
      .getByRole("link", { name: "Download text.pdf", exact: true }),
  ).toBeVisible();

  // Page 1 of the fixture has a red band across its top; page 2 is a blue
  // square. The canvas must hold page 1's pixels, not a blank page.
  const pixel = await firstPage.evaluate((element) => {
    const canvas = element as HTMLCanvasElement;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("canvas has no 2d context");
    const x = Math.floor(canvas.width / 2);
    const y = Math.floor(canvas.height * (132 / 792));
    return Array.from(context.getImageData(x, y, 1, 1).data);
  });
  expect(pixel[0]).toBeGreaterThan(150);
  expect(pixel[1]).toBeLessThan(80);
  expect(pixel[2]).toBeLessThan(80);

  // pdf.js fetched the inline route itself; every response was a success.
  expect(openRequests.length).toBeGreaterThan(0);
  for (const request of openRequests) {
    expect([200, 206]).toContain(request.status);
  }

  expect(cspViolations).toEqual([]);
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __cspViolations: string[] }).__cspViolations,
    ),
  ).toEqual([]);
  expect(pageErrors).toEqual([]);
});

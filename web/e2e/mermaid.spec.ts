import { expect, test } from "@playwright/test";

import { openSignedIn } from "./helpers";

for (const [name, text] of [
  ["diagram.mmd", "Copy path"],
  ["sequence.mermaid", "File contents"],
] as const) {
  test(`renders standalone ${name} and exposes keyboard-operated source`, async ({
    page,
  }) => {
    await openSignedIn(page, `/read-only/${name}`);
    const diagram = page.frameLocator('iframe[title="Mermaid diagram"]');
    await expect(diagram.locator("svg")).toBeVisible();
    await expect(diagram.locator("svg")).toContainText(text);
    if (name === "diagram.mmd")
      await expect(diagram.locator("math")).toBeVisible();
    const readable = page.getByRole("tab", { name: "Diagram", exact: true });
    await readable.focus();
    await page.keyboard.press("ArrowRight");
    await expect(
      page.getByRole("tab", { name: "Source", exact: true }),
    ).toBeFocused();
    await expect(page.getByLabel("Mermaid source")).toContainText(
      name === "diagram.mmd" ? "flowchart LR" : "sequenceDiagram",
    );
    await expect(page.locator('iframe[title="Mermaid diagram"]')).toHaveCount(
      0,
    );
    await page.keyboard.press("ArrowLeft");
    await expect(readable).toBeFocused();
    await expect(diagram.locator("svg")).toBeVisible();
  });
}

test("renders fenced Mermaid blocks and contains invalid diagram failures", async ({
  page,
}) => {
  await openSignedIn(page, "/read-only/diagrams.md");
  const frames = page.locator('iframe[title="Mermaid diagram"]');
  // The last frame is lazy-loaded and starts below the preview's scroll fold.
  await page.locator(".markdown-mermaid").last().scrollIntoViewIfNeeded();
  await expect(
    page.getByText(
      "This diagram could not be rendered. Its source is still available.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(frames).toHaveCount(2);
  await expect(frames.nth(0).contentFrame().locator("svg")).toContainText(
    "Finish",
  );
  await expect(frames.nth(1).contentFrame().locator("svg")).toContainText(
    "Hello",
  );
  const source = page.getByText("Diagram source", { exact: true }).last();
  await source.click();
  await expect(page.getByLabel("Mermaid source").last()).toContainText(
    "this is not a diagram",
  );
});

test("enforces the edge budget against diagram configuration overrides", async ({
  page,
}) => {
  const source =
    '%%{init: {"maxEdges":100000}}%%\nflowchart LR\n' +
    Array.from(
      { length: 251 },
      (_, index) => `N${index} --> N${index + 1}`,
    ).join("\n");
  await page.route("**/preview?path=diagram.mmd", (route) =>
    route.fulfill({
      json: {
        kind: "code",
        language: "mermaid",
        source,
        size: source.length,
        truncated: false,
      },
    }),
  );
  await openSignedIn(page, "/read-only/diagram.mmd");
  await expect(
    page.getByText(
      "This diagram could not be rendered. Its source is still available.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(page.locator('iframe[title="Mermaid diagram"]')).toHaveCount(0);
  await page.getByRole("tab", { name: "Source", exact: true }).click();
  await expect(page.getByLabel("Mermaid source")).toContainText(
    "N250 --> N251",
  );
});

test("isolates diagram scripts, session access, config overrides, links, and network", async ({
  page,
  context,
  baseURL,
}) => {
  const foreign: string[] = [];
  const origin = new URL(baseURL!).origin;
  await context.route("https://example.com/**", (route) => {
    foreign.push(route.request().url());
    return route.abort();
  });
  context.on("response", (response) => {
    if (new URL(response.url()).origin !== origin) foreign.push(response.url());
  });
  await openSignedIn(page, "/read-only/hostile-diagram.mmd");
  const element = page.locator('iframe[title="Mermaid diagram"]');
  await expect(element).toHaveAttribute("sandbox", "allow-scripts");
  const frame = element.contentFrame();
  await expect(frame.locator("svg")).toContainText("Safe label");
  const response = await page.request.get("/mermaid-renderer.html");
  const csp = response.headers()["content-security-policy"]!;
  expect(csp).toContain("sandbox allow-scripts;");
  expect(csp).not.toContain("allow-same-origin");
  expect(csp).toContain("connect-src 'none'");
  expect(csp).toContain("img-src 'none'");
  const isolation = await frame.locator("body").evaluate(async () => {
    let parentDenied = false;
    let cookiesDenied = false;
    let apiDenied = false;
    try {
      void window.parent.document;
    } catch {
      parentDenied = true;
    }
    try {
      void document.cookie;
    } catch {
      cookiesDenied = true;
    }
    try {
      await fetch("/api/v1/session");
    } catch {
      apiDenied = true;
    }
    return { parentDenied, cookiesDenied, apiDenied };
  });
  expect(isolation).toEqual({
    parentDenied: true,
    cookiesDenied: true,
    apiDenied: true,
  });
  await expect(frame.locator("svg a[href], svg a[xlink\\:href]")).toHaveCount(
    0,
  );
  expect(foreign).toEqual([]);
});

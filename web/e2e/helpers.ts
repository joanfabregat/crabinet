import {
  expect,
  type Locator,
  type Page,
  type TestInfo,
} from "@playwright/test";

export const E2E_PASSWORD = "e2e-password";

export async function signIn(
  page: Page,
  username: "reader" | "writer" = "reader",
) {
  await page.getByLabel("Email or username", { exact: true }).fill(username);
  await page.getByLabel("Password").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(
    page.getByLabel("Shared folders", { exact: true }),
  ).toBeAttached();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
}

export async function openSignedIn(
  page: Page,
  path = "/",
  username: "reader" | "writer" = "reader",
) {
  await page.goto(path);
  await signIn(page, username);
}

export async function csrfToken(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const response = await fetch("/api/v1/session", {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error(`session failed: ${response.status}`);
    const session = (await response.json()) as { csrfToken?: unknown };
    if (typeof session.csrfToken !== "string") {
      throw new Error("session response omitted csrfToken");
    }
    return session.csrfToken;
  });
}

export interface BrowserFile {
  name: string;
  mimeType: string;
  contents: string;
}

/** Native drop helper reserved for the mutation-flow suite added with the upload UI. */
export async function dropFiles(
  target: Locator,
  files: BrowserFile[],
  beforeDrop?: () => Promise<void>,
) {
  const dataTransfer = await target.page().evaluateHandle((items) => {
    const transfer = new DataTransfer();
    for (const item of items) {
      transfer.items.add(
        new File([item.contents], item.name, { type: item.mimeType }),
      );
    }
    return transfer;
  }, files);
  try {
    await target.dispatchEvent("dragenter", { dataTransfer });
    await target.dispatchEvent("dragover", { dataTransfer });
    await beforeDrop?.();
    await target.dispatchEvent("drop", { dataTransfer });
  } finally {
    await dataTransfer.dispose();
  }
}

/** Keyboard/file-picker alternative for the same future upload-flow suite. */
export async function chooseFiles(input: Locator, files: BrowserFile[]) {
  await input.setInputFiles(
    files.map((file) => ({
      name: file.name,
      mimeType: file.mimeType,
      buffer: Buffer.from(file.contents),
    })),
  );
}

/**
 * The folder tree, opening its drawer first on screens too narrow for it.
 *
 * Callers reach the tree after a navigation, and every navigation closes the
 * drawer, but only in an effect after the new route renders: the URL can
 * already match while the previous page's drawer is still open. Reading
 * `aria-expanded` at that moment would skip the click and leave the tree to
 * close underneath the caller, so wait for the drawer to settle closed, then
 * open it.
 */
export async function openFolders(page: Page): Promise<Locator> {
  const toggle = page.getByRole("button", { name: "Folders" });
  if (await toggle.isVisible()) {
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
  }
  const tree = page.getByLabel("Shared folders", { exact: true });
  await expect(tree).toBeVisible();
  return tree;
}

/**
 * Whether this project is the one that changes server state for its browser
 * engine. Every engine has its own server (see `playwright.config.ts`), so
 * stateful suites run once per engine, in its desktop project; against one
 * external server (`CRABINET_E2E_BASE_URL`) they run only in Chromium.
 */
export function ownsServerState(testInfo: TestInfo): boolean {
  return process.env.CRABINET_E2E_BASE_URL
    ? testInfo.project.name === "desktop-chromium"
    : testInfo.project.name.startsWith("desktop-");
}

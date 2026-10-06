import { expect, test, type Page } from "@playwright/test";
import { csrfToken, signIn } from "./helpers";

/**
 * OpenID Connect sign-in through the fake provider in `fake-oidc.ts`, which
 * Crabinet reaches over HTTPS and trusts only through `auth.oidc.ca_file`.
 * These run in the `oidc-*` projects against their own server; password
 * sign-in stays enabled there as well.
 */

const accounts = {
  reader: "reader@example.com",
  writer: "writer@example.com",
  stranger: "stranger@example.com",
} as const;
type Account = keyof typeof accounts;

const loginHeading = (page: Page) =>
  page.getByRole("heading", { name: "Sign in to Crabinet" });

/** Follows the sign-in link to the provider's consent page. */
async function startSignIn(page: Page) {
  await page.getByRole("link", { name: "Sign in with Google" }).click();
  await expectConsentPage(page);
}

/** The provider is a separate site from Crabinet, as in production. */
async function expectConsentPage(page: Page) {
  await expect(
    page.getByRole("heading", { name: "Fake identity provider" }),
  ).toBeVisible();
  expect(new URL(page.url()).host).not.toBe(
    new URL(test.info().project.use.baseURL!).host,
  );
}

async function approveAs(page: Page, account: Account) {
  await page
    .getByRole("button", { name: `Continue as ${accounts[account]}` })
    .click();
}

async function expectSignedIn(page: Page) {
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
}

/** The path and query of the current page. */
function location(page: Page): string {
  const url = new URL(page.url());
  return `${url.pathname}${url.search}`;
}

/** Records every host the page requests, to prove none left the origin. */
function requestedHosts(page: Page): Set<string> {
  const hosts = new Set<string>();
  page.on("request", (request) => hosts.add(new URL(request.url()).host));
  return hosts;
}

async function setStartFolder(page: Page, shareId: string | null) {
  const token = await csrfToken(page);
  await page.evaluate(
    async ({ shareId, token }) => {
      const response = await fetch("/api/v1/preferences", {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({
          defaultFolder: shareId === null ? null : { shareId, path: "" },
        }),
      });
      if (!response.ok) throw new Error(`preferences: ${response.status}`);
    },
    { shareId, token },
  );
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(loginHeading(page)).toBeVisible();
}

/** A refused callback shows the API's error and creates no session. */
async function expectRefusedCallback(page: Page) {
  expect(new URL(page.url()).pathname).toBe("/api/v1/auth/oidc/callback");
  await expect(page.locator("body")).toContainText("authentication_failed");
  const session = await page.request.get("/api/v1/session");
  expect(session.status()).toBe(401);
  await page.goto("/");
  await expect(loginHeading(page)).toBeVisible();
}

test("a deep link survives OIDC sign-in", async ({ page }) => {
  await page.goto("/read-only/nested");
  await expect(loginHeading(page)).toBeVisible();
  await startSignIn(page);
  await approveAs(page, "reader");
  await expectSignedIn(page);
  await expect(page).toHaveURL(/\/read-only\/nested$/);
  await expect(
    page.getByRole("link", { name: "notes.txt", exact: true }),
  ).toBeVisible();
});

test("OIDC sign-in at the root opens the start folder", async ({ page }) => {
  // Saves a start folder for the writer, who holds two shares.
  await page.goto("/");
  await startSignIn(page);
  await approveAs(page, "writer");
  await expectSignedIn(page);
  await setStartFolder(page, "writable");
  await signOut(page);

  await page.goto("/");
  await startSignIn(page);
  await approveAs(page, "writer");
  await expect(page).toHaveURL(/\/writable$/);
  await expectSignedIn(page);

  // Without a start folder, the root opens the first share as before.
  await setStartFolder(page, null);
  await signOut(page);
  await page.goto("/");
  await startSignIn(page);
  await approveAs(page, "writer");
  await expect(page).toHaveURL(/\/read-only$/);
  await expectSignedIn(page);
});

test("a tampered return location never leaves the app", async ({ page }) => {
  const hosts = requestedHosts(page);
  const origin = new URL(test.info().project.use.baseURL!).origin;
  for (const returnTo of [
    "//evil.example",
    "/api/v1/session",
    "https://evil.example/",
    "/%2F%2Fevil.example",
    "/read-only/../api/v1/session",
  ]) {
    await page.goto(
      `/api/v1/auth/oidc/start?${new URLSearchParams({ return_to: returnTo }).toString()}`,
    );
    await expectConsentPage(page);
    expect(page.url()).not.toContain("evil.example");
    await approveAs(page, "reader");
    // The callback sends the browser to `/`, which opens the reader's
    // only share.
    await expect(page).toHaveURL(`${origin}/read-only`);
    await expectSignedIn(page);
    await signOut(page);
  }
  expect([...hosts].filter((host) => host.includes("evil"))).toEqual([]);
});

test("an expired session signs in again on the same page", async ({ page }) => {
  await page.goto("/read-only/nested");
  await startSignIn(page);
  await approveAs(page, "reader");
  await expectSignedIn(page);

  // The session ends while the page is open; the next request finds it gone.
  // That is either the click below or a background request (the directory
  // event stream, folder sizes) that gets there first and removes the link.
  await page.context().clearCookies({ name: "__Host-crabinet_session" });
  const expired = page.getByText(
    "Your session expired. Sign in again to continue.",
  );
  await Promise.race([
    expired.waitFor(),
    page
      .getByRole("link", { name: "notes.txt", exact: true })
      .click()
      .catch(() => undefined),
  ]);
  await expect(expired).toBeVisible();
  const expiredAt = location(page);
  expect(expiredAt).toMatch(/^\/read-only\/nested(\/notes\.txt)?(\?|$)/);

  await startSignIn(page);
  await approveAs(page, "reader");
  await expectSignedIn(page);
  expect(location(page)).toBe(expiredAt);
  if (expiredAt.includes("notes.txt")) {
    await expect(
      page.getByRole("heading", { name: "notes.txt", level: 2 }),
    ).toBeVisible();
  }
});

test("a provider error fails sign-in without following the return path", async ({
  page,
}) => {
  await page.goto("/read-only/nested");
  await startSignIn(page);
  await page.getByRole("button", { name: "Cancel" }).click();
  await expectRefusedCallback(page);
});

test("a callback for another sign-in attempt is refused", async ({ page }) => {
  // The first attempt reaches the provider, then a second attempt in the same
  // browser replaces its transaction. Approving the first one now returns a
  // genuine code with a state the browser no longer holds.
  await page.goto("/read-only/nested");
  await startSignIn(page);
  const firstAttempt = page.url();
  await page.goto("/read-only");
  await startSignIn(page);
  await page.goto(firstAttempt);
  await expectConsentPage(page);
  await approveAs(page, "reader");
  await expectRefusedCallback(page);

  // A forged state is refused the same way.
  await page.goto("/read-only/nested");
  await startSignIn(page);
  await page.goto(
    "/api/v1/auth/oidc/callback?code=forged-code&state=forged-state",
  );
  await expectRefusedCallback(page);
});

test("an identity without an account is told so", async ({ page }) => {
  await page.goto("/read-only/nested");
  await startSignIn(page);
  await approveAs(page, "stranger");
  await expect(
    page.getByText("This identity is not authorized for Crabinet."),
  ).toBeVisible();
  expect(location(page)).toBe("/?oidc_error=unrecognized");
  const session = await page.request.get("/api/v1/session");
  expect(session.status()).toBe(401);
});

test("password sign-in still works beside OIDC", async ({ page }) => {
  await page.goto("/read-only/nested");
  await expect(
    page.getByRole("link", { name: "Sign in with Google" }),
  ).toBeVisible();
  await signIn(page, "reader");
  await expectSignedIn(page);
  await expect(page).toHaveURL(/\/read-only\/nested$/);
});

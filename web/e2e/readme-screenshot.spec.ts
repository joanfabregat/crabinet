import { expect, test } from "@playwright/test";

import { openSignedIn } from "./helpers";

test("capture the deterministic authenticated browser", async ({ page }) => {
  test.skip(
    process.env.INDEX_UPDATE_README_SCREENSHOT !== "1",
    "run npm run screenshot:readme to update the checked-in image",
  );
  await page.setViewportSize({ width: 1440, height: 960 });
  await openSignedIn(page, "/browse/writable", "writer");
  await page.getByRole("link", { name: "README.md" }).click();
  await expect(
    page.getByRole("heading", { name: "README.md", level: 2 }),
  ).toBeFocused();
  await expect(page.getByTestId("markdown-document")).toBeVisible();

  await page.screenshot({
    path: "../docs/images/index-browser.png",
    fullPage: true,
    animations: "disabled",
    caret: "hide",
  });
});

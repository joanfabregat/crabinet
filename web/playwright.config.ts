import { defineConfig, devices } from "@playwright/test";

const port = Number.parseInt(process.env.CRABINET_E2E_PORT ?? "4173", 10);
const externalBaseURL = process.env.CRABINET_E2E_BASE_URL;

/**
 * Each browser engine gets its own production server, on consecutive ports,
 * so suites that change server state run once per engine against fresh
 * fixtures. Projects of one engine share its server.
 */
const engines = ["chromium", "webkit", "firefox"] as const;
type Engine = (typeof engines)[number];
const enginePort = (engine: Engine) => port + engines.indexOf(engine);
/**
 * Playwright's WebKit on Linux does not keep `Secure` cookies over plain
 * HTTP, even on `localhost`, so its server sits behind a TLS proxy with a
 * throwaway certificate (`e2e/tls-proxy.ts`), as production does.
 */
const usesTLS = (engine: Engine) => engine === "webkit";
const serverURL = (engine: Engine) =>
  externalBaseURL ??
  `${usesTLS(engine) ? "https" : "http"}://localhost:${String(enginePort(engine))}`;

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 7_500 },
  reporter: [
    ["line"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
  ],
  use: {
    locale: "en-US",
    timezoneId: "America/Los_Angeles",
    colorScheme: "light",
    reducedMotion: "reduce",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: externalBaseURL
    ? undefined
    : engines.map((engine) => ({
        command: "sh ./e2e/run-server.sh",
        env: {
          CRABINET_E2E_PORT: String(enginePort(engine)),
          CRABINET_E2E_TLS: usesTLS(engine) ? "1" : "0",
        },
        url: `${serverURL(engine)}/health/ready`,
        ignoreHTTPSErrors: usesTLS(engine),
        reuseExistingServer: false,
        timeout: 120_000,
        stdout: "pipe" as const,
        stderr: "pipe" as const,
      })),
  projects: [
    {
      name: "desktop-chromium",
      use: {
        browserName: "chromium",
        baseURL: serverURL("chromium"),
        viewport: { width: 1440, height: 960 },
      },
    },
    {
      name: "mobile-chromium",
      use: {
        browserName: "chromium",
        baseURL: serverURL("chromium"),
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 1,
        hasTouch: true,
        isMobile: true,
      },
    },
    // Playwright's WebKit build, not Apple's Safari: the same engine and
    // layout, but Linux networking and a GStreamer media stack.
    {
      name: "desktop-webkit",
      use: {
        ...devices["Desktop Safari"],
        baseURL: serverURL("webkit"),
        ignoreHTTPSErrors: true,
        viewport: { width: 1440, height: 960 },
        deviceScaleFactor: 1,
      },
    },
    {
      name: "ipad-webkit",
      use: {
        ...devices["iPad Pro 11 landscape"],
        baseURL: serverURL("webkit"),
        ignoreHTTPSErrors: true,
        deviceScaleFactor: 1,
      },
    },
    {
      name: "desktop-firefox",
      use: {
        ...devices["Desktop Firefox"],
        baseURL: serverURL("firefox"),
        viewport: { width: 1440, height: 960 },
        deviceScaleFactor: 1,
      },
    },
  ],
});

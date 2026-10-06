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
/**
 * OpenID Connect sign-in runs against one more server, on the next port,
 * with OIDC enabled beside passwords and a fake provider (`e2e/fake-oidc.ts`)
 * that Crabinet trusts through `auth.oidc.ca_file`. Its callback must be
 * HTTPS, so it is always behind the TLS proxy. Keeping it apart leaves every
 * other suite's sign-in page and server unchanged. Each engine's `oidc-`
 * project uses it; the suite changes only sessions and one preference it
 * restores, so the engines can share it. It needs a provider beside the
 * server, so it does not run against an external server.
 */
const oidcPort = port + engines.length;
const oidcURL = `https://localhost:${String(oidcPort)}`;
const oidcSpec = /oidc\.spec\.ts$/;

const engineServers = engines.map((engine) => ({
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
}));
const oidcServer = {
  command: "sh ./e2e/run-server.sh",
  env: {
    CRABINET_E2E_PORT: String(oidcPort),
    CRABINET_E2E_TLS: "1",
    CRABINET_E2E_OIDC: "1",
  },
  url: `${oidcURL}/health/ready`,
  ignoreHTTPSErrors: true,
  reuseExistingServer: false,
  timeout: 120_000,
  stdout: "pipe" as const,
  stderr: "pipe" as const,
};

const oidcProjects = externalBaseURL
  ? []
  : [
      { name: "oidc-chromium", device: devices["Desktop Chrome"] },
      { name: "oidc-webkit", device: devices["Desktop Safari"] },
      { name: "oidc-firefox", device: devices["Desktop Firefox"] },
    ].map(({ name, device }) => ({
      name,
      testMatch: oidcSpec,
      use: {
        ...device,
        baseURL: oidcURL,
        // The browser does not need to trust the provider or the proxy:
        // what is under test is Crabinet's trust in the provider.
        ignoreHTTPSErrors: true,
        deviceScaleFactor: 1,
      },
    }));

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
  webServer: externalBaseURL ? undefined : [...engineServers, oidcServer],
  projects: [
    {
      name: "desktop-chromium",
      testIgnore: oidcSpec,
      use: {
        browserName: "chromium",
        baseURL: serverURL("chromium"),
        viewport: { width: 1440, height: 960 },
      },
    },
    {
      name: "mobile-chromium",
      testIgnore: oidcSpec,
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
      testIgnore: oidcSpec,
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
      testIgnore: oidcSpec,
      use: {
        ...devices["iPad Pro 11 landscape"],
        baseURL: serverURL("webkit"),
        ignoreHTTPSErrors: true,
        deviceScaleFactor: 1,
      },
    },
    {
      name: "desktop-firefox",
      testIgnore: oidcSpec,
      use: {
        ...devices["Desktop Firefox"],
        baseURL: serverURL("firefox"),
        viewport: { width: 1440, height: 960 },
        deviceScaleFactor: 1,
      },
    },
    ...oidcProjects,
  ],
});

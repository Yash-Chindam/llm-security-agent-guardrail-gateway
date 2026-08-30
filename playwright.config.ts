import { defineConfig } from "@playwright/test";

const python =
  process.env.PLAYWRIGHT_PYTHON ??
  (process.platform === "win32" ? '".\\.venv\\Scripts\\python.exe"' : "python");

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI
    ? [["line"], ["html", { open: "never" }]]
    : [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:18080",
    extraHTTPHeaders: { Accept: "application/json" },
    trace: "retain-on-failure",
  },
  webServer: {
    command: `${python} -m uvicorn guardrail_gateway.app:app --host 127.0.0.1 --port 18080`,
    url: "http://127.0.0.1:18080/health/ready",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});

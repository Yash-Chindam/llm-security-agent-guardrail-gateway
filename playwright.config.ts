import { defineConfig } from "@playwright/test";

import { E2E_AUDIENCE, E2E_ISSUER, E2E_SIGNING_KEY } from "./tests/e2e/auth";

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
    // The gateway refuses every request without signing material, and reports
    // itself not ready, so the e2e deployment is given a key the tests share.
    env: {
      GUARDRAIL_JWT_SECRET: E2E_SIGNING_KEY,
      GUARDRAIL_JWT_ISSUER: E2E_ISSUER,
      GUARDRAIL_JWT_AUDIENCE: E2E_AUDIENCE,
    },
  },
});

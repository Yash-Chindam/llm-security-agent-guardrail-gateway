import { createHmac } from "node:crypto";

/**
 * The signing material the e2e gateway is started with, set in
 * playwright.config.ts. These tests authenticate like any other caller, so the
 * end-to-end run exercises the real credential path rather than a test bypass.
 */
export const E2E_SIGNING_KEY =
  "e2e-signing-key-0123456789abcdef-not-a-deployment-secret";
export const E2E_ISSUER = "https://issuer.e2e.test";
export const E2E_AUDIENCE = "guardrail-gateway";

const base64url = (input: Buffer | string): string =>
  Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

export type TokenOptions = {
  identity: string;
  tenant: string;
  roles?: string[];
  lifetimeSeconds?: number;
};

/** Mint an HS256 credential the gateway will verify. */
export const mintToken = ({
  identity,
  tenant,
  roles = ["caller"],
  lifetimeSeconds = 300,
}: TokenOptions): string => {
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({
      sub: identity,
      tenant,
      roles,
      iss: E2E_ISSUER,
      aud: E2E_AUDIENCE,
      iat: issuedAt,
      exp: issuedAt + lifetimeSeconds,
    }),
  );
  const signature = base64url(
    createHmac("sha256", E2E_SIGNING_KEY).update(`${header}.${payload}`).digest(),
  );
  return `${header}.${payload}.${signature}`;
};

export const authHeader = (options: TokenOptions): Record<string, string> => ({
  Authorization: `Bearer ${mintToken(options)}`,
});

export const CALLER = authHeader({
  identity: "e2e-user",
  tenant: "acme",
  roles: ["caller", "operator"],
});
export const REVIEWER = authHeader({
  identity: "e2e-reviewer",
  tenant: "acme",
  roles: ["caller", "reviewer"],
});

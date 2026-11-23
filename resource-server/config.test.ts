import assert from "node:assert/strict";
import test from "node:test";
import { getResourceServerConfig } from "./config.ts";

test("getResourceServerConfig derives the high value order acr from the discovered issuer", async () => {
  const authServerBase = "https://auth.example.test";
  const discoveredIssuer = "https://auth.example.test/issuer";
  const previousFetch = globalThis.fetch;
  const previousAuthServerBase = process.env.AUTH_SERVER_BASE;
  globalThis.fetch = async function (input) {
    assert.equal(
      String(input),
      `${authServerBase}/.well-known/openid-configuration`,
    );
    return new Response(
      JSON.stringify({
        issuer: discoveredIssuer,
        jwks_uri: `${discoveredIssuer}/.well-known/jwks.json`,
      }),
      { status: 200 },
    );
  };
  process.env.AUTH_SERVER_BASE = authServerBase;

  try {
    const config = await getResourceServerConfig();

    assert.equal(config.issuer, discoveredIssuer);
    assert.equal(
      config.highValueOrderAcr,
      `${new URL(discoveredIssuer).origin}/acr/level-2`,
    );
  } finally {
    globalThis.fetch = previousFetch;
    if (previousAuthServerBase === undefined) {
      delete process.env.AUTH_SERVER_BASE;
    } else {
      process.env.AUTH_SERVER_BASE = previousAuthServerBase;
    }
  }
});

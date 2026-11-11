import assert from "node:assert/strict";
import test from "node:test";
import { createServerContext } from "./server-context.ts";
import { getTestServerConfig } from "./test/test-utils.ts";

test("server contexts create independent stores for each server instance", async () => {
  const serverConfig = getTestServerConfig();
  const first = await createServerContext({ serverConfig });
  const second = await createServerContext({ serverConfig });

  for (const name of [
    "pendingAuthorizationStore",
    "authorizationCodeStore",
    "sessionStore",
    "tokenStore",
    "userStore",
    "refreshTokenStore",
  ] as const) {
    assert.notEqual(first[name], second[name], name);
  }
});

test("server context configures the default session store from server config", async () => {
  const sessionLengthSeconds = 10;
  const context = await createServerContext({
    serverConfig: getTestServerConfig({ sessionLengthSeconds }),
  });

  const session = context.sessionStore.newSession({
    userId: "user-id",
    amr: ["pwd"],
    authTime: 0,
  });

  assert.equal(
    session.expiresAt - session.createdAt,
    sessionLengthSeconds * 1000,
  );
});

test("server context preserves explicit dependency overrides", async () => {
  const overrides = await createServerContext({
    serverConfig: getTestServerConfig(),
  });
  const context = await createServerContext(overrides);

  for (const name of Object.keys(overrides) as (keyof typeof overrides)[]) {
    assert.equal(context[name], overrides[name], name);
  }
});

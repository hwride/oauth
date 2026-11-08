import assert from "node:assert/strict";
import test from "node:test";

let configVersion = 0;
const conformanceRedirectUri =
  "https://localhost.emobix.co.uk:8443/test/a/oauth-local/callback";

async function getRedirectUris(overrides: NodeJS.ProcessEnv = {}) {
  const names = [
    "CLIENT_PORT",
    "CLIENT_OPAQUE_BASE",
    "CLIENT_JWT_BASE",
    "CLIENT_PUBLIC_BASE",
  ];
  const saved = names.map((name) => process.env[name]);
  try {
    for (const name of names) {
      delete process.env[name];
    }
    Object.assign(process.env, overrides);
    const configUrl = new URL("./clients-config.ts", import.meta.url);
    configUrl.searchParams.set("test", String(configVersion++));
    const { clientsConfig } = await import(configUrl.href);
    return clientsConfig.map((client) => client.redirectUris);
  } finally {
    names.forEach((name, index) => {
      if (saved[index] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[index];
      }
    });
  }
}

test("callback URIs default to client port 3000", async () => {
  assert.deepEqual(await getRedirectUris(), [
    ["http://localhost:3000/callback"],
    ["http://localhost:3000/callback"],
    ["http://localhost:3000/callback"],
    [conformanceRedirectUri],
    [conformanceRedirectUri],
  ]);
});

test("local app callback URIs follow a custom CLIENT_PORT", async () => {
  assert.deepEqual(await getRedirectUris({ CLIENT_PORT: "3100" }), [
    ["http://localhost:3100/callback"],
    ["http://localhost:3100/callback"],
    ["http://localhost:3100/callback"],
    [conformanceRedirectUri],
    [conformanceRedirectUri],
  ]);
});

test("explicit client bases take precedence over CLIENT_PORT", async () => {
  assert.deepEqual(
    await getRedirectUris({
      CLIENT_PORT: "3100",
      CLIENT_OPAQUE_BASE: "https://opaque.example.test:3101",
      CLIENT_JWT_BASE: "https://jwt.example.test:3102",
      CLIENT_PUBLIC_BASE: "https://public.example.test:3103",
    }),
    [
      ["https://opaque.example.test:3101/callback"],
      ["https://jwt.example.test:3102/callback"],
      ["https://public.example.test:3103/callback"],
      [conformanceRedirectUri],
      [conformanceRedirectUri],
    ],
  );
});

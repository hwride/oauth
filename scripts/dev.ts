import { setTimeout as sleep } from "node:timers/promises";
import {
  defaultAuthorizationServerPort,
  main as startAuthorizationServer,
} from "../authorization-server/server.ts";
import { defaultClientPort, main as startClient } from "../client/client.ts";
import {
  defaultResourceServerPort,
  main as startResourceServer,
} from "../resource-server/resource-server.ts";

const authServerDiscoveryTimeoutMs = 20_000;

async function main() {
  // Auth server
  const authorizationServerPort = Number(
    process.env.AUTH_SERVER_PORT ?? defaultAuthorizationServerPort,
  );
  const authServerBase =
    process.env.AUTH_SERVER_BASE ??
    `http://localhost:${authorizationServerPort}`;
  const localAuthServerBase = `http://localhost:${authorizationServerPort}`;
  process.env.CLIENT_JWT_BASE ??= "http://localhost:3000";
  process.env.CLIENT_OPAQUE_BASE ??= "http://localhost:3001";
  process.env.AUTH_SERVER_PORT = String(authorizationServerPort);
  process.env.ISSUER ??= authServerBase;

  // Resource server and client
  process.env.AUTH_SERVER_BASE = authServerBase;

  // Resource server
  const resourceServerPort = Number(
    process.env.RESOURCE_SERVER_PORT ?? defaultResourceServerPort,
  );
  process.env.RESOURCE_SERVER_PORT = String(resourceServerPort);
  process.env.DEFAULT_RESOURCE =
    process.env.DEFAULT_RESOURCE ?? "https://orders-api.example.test";

  // Client
  const clientPort = Number(process.env.CLIENT_PORT ?? defaultClientPort);
  process.env.CLIENT_PORT = String(clientPort);
  process.env.CLIENT_ID ??= "client-id-jwt";
  process.env.CLIENT_SECRET ??= "other-test-client-secret";
  process.env.DEFAULT_SCOPES ??= "openid orders:read";
  process.env.DEFAULT_ACR_VALUES ??= `${new URL(process.env.ISSUER ?? authServerBase).origin}/acr/level-2`;

  console.log("Starting authorization server...");
  await startAuthorizationServer();

  console.log("Waiting for authorization server...");
  await waitForAuthServerDiscovery(localAuthServerBase);

  console.log("Starting resource server...");
  await startResourceServer();
  console.log("Starting client...");
  await startClient();
}

async function waitForAuthServerDiscovery(authServerBase: string) {
  const authServerDiscoveryUrl = new URL(
    "/.well-known/openid-configuration",
    authServerBase,
  );
  const timeoutAt = Date.now() + authServerDiscoveryTimeoutMs;
  let lastError: unknown;

  while (Date.now() < timeoutAt) {
    const remainingMs = timeoutAt - Date.now();
    try {
      const response = await fetch(authServerDiscoveryUrl, {
        signal: AbortSignal.timeout(Math.min(1000, remainingMs)),
      });
      if (response.status === 200) {
        return;
      }
      lastError = new Error(
        `Discovery endpoint returned HTTP ${response.status}`,
      );
    } catch (error) {
      lastError = error;
    }

    await sleep(100);
  }

  throw new Error(
    `Timed out waiting ${authServerDiscoveryTimeoutMs}ms for ${authServerDiscoveryUrl}`,
    { cause: lastError },
  );
}

await main();

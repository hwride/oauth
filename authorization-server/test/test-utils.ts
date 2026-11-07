import { createServerContext, type ServerContext } from "../server-context.ts";
import { generateKeyPair } from "jose";
import type { ServerConfig } from "../config/server-config.ts";

const jwtSigningAlg = "RS256";
const testSigningKeys = await generateKeyPair(jwtSigningAlg);

const defaultServerConfig: ServerConfig = {
  jwtSigningAlg,
  publicKey: testSigningKeys.publicKey,
  privateKey: testSigningKeys.privateKey,
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  userInfoUri: "https://issuer.example.test/userinfo",
  authorizationCodeLifetimeSeconds: 60 * 10,
  mfaTransactionLifetimeSeconds: 60 * 10,
  mfaMaxAttempts: 5,
};

export function getTestServerConfig(
  overrides: Partial<ServerConfig> = {},
): ServerConfig {
  return {
    ...defaultServerConfig,
    ...overrides,
  };
}

export function getTestServerContext(overrides: Partial<ServerContext> = {}) {
  return createServerContext({
    serverConfig: getTestServerConfig(),
    ...overrides,
  });
}

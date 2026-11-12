import { createServerContext, type ServerContext } from "./server-context.ts";
import formbody from "@fastify/formbody";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import { clientsConfig } from "./config/clients-config.ts";
import type { ServerConfig } from "./config/server-config.ts";
import { registerAuthorizationRoute } from "./routes/authorization-route.ts";
import { registerJwksRoute } from "./routes/jwks-route.ts";
import { registerOpenIdConfigurationRoute } from "./routes/openid-configuration-route.ts";
import { registerSignupRoute } from "./routes/signup-route.ts";
import { registerTokenRoute } from "./routes/token-route.ts";
import { registerTotpRegistrationRoute } from "./routes/totp-registration-route.ts";
import { registerMfaChallengeTotpRoute } from "./routes/mfa-challenge-totp-route.ts";
import { registerUserinfoRoute } from "./routes/userinfo-route.ts";

export const defaultAuthorizationServerPort = 4000;

if (import.meta.main) {
  main();
}

export async function main() {
  const fastify = await createServer();

  try {
    await fastify.listen({
      port: getAuthorizationServerPort(),
      host: process.env.AUTH_SERVER_HOST ?? "localhost",
    });
    fastify.log.info("Authorization server is booted");
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export async function createServer(overrides: Partial<ServerContext> = {}) {
  const context = await createServerContext(overrides);
  const fastify = Fastify({
    logger: {
      transport: {
        target: "pino-pretty",
        options: {
          translateTime: "HH:MM:ss Z",
          ignore: "pid,hostname",
        },
      },
    },
    disableRequestLogging: false,
  });

  logAuthorizationServerConfig(fastify, context.serverConfig);

  fastify.register(formbody);
  fastify.register(cookie);

  registerOpenIdConfigurationRoute(fastify, context);
  registerAuthorizationRoute(fastify, context);
  registerSignupRoute(fastify, context);
  registerTokenRoute(fastify, context);
  registerTotpRegistrationRoute(fastify, context);
  registerMfaChallengeTotpRoute(fastify, context);
  registerJwksRoute(fastify, context);
  registerUserinfoRoute(fastify, context);

  return fastify;
}

function logAuthorizationServerConfig(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
) {
  fastify.log.info(
    {
      port: getAuthorizationServerPort(),
      issuer: serverConfig.issuer,
      authorizationEndpoint: serverConfig.authorizationEndpoint,
      tokenEndpoint: serverConfig.tokenEndpoint,
      jwksUri: serverConfig.jwksUri,
      authorizationCodeLifetimeSeconds:
        serverConfig.authorizationCodeLifetimeSeconds,
      mfaTransactionLifetimeSeconds: serverConfig.mfaTransactionLifetimeSeconds,
      mfaMaxAttempts: serverConfig.mfaMaxAttempts,
      clients: clientsConfig.map(function (client) {
        return {
          clientId: client.clientId,
          clientAuthMethod: client.clientAuthMethod,
          clientSecret:
            "clientSecret" in client && client.clientSecret
              ? "<redacted-non-empty>"
              : null,
          redirectUris: client.redirectUris,
          accessTokenType: client.accessTokenType,
          accessTokenLifetimeSeconds: client.accessTokenLifetimeSeconds,
          idTokenLifetimeSeconds: client.idTokenLifetimeSeconds,
          refreshTokenLifetimeSeconds: client.refreshTokenLifetimeSeconds,
        };
      }),
    },
    "Authorization server config",
  );
}

function getAuthorizationServerPort() {
  return Number(process.env.AUTH_SERVER_PORT ?? defaultAuthorizationServerPort);
}

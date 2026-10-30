import formbody from "@fastify/formbody";
import Fastify, { type FastifyInstance } from "fastify";
import { clientsConfig, type ClientConfig } from "./config/clients-config.ts";
import { getServerConfig, type ServerConfig } from "./config/server-config.ts";
import { defaultUsers } from "./default-users.ts";
import { registerAuthorizationRoute } from "./routes/authorization-route.ts";
import { registerJwksRoute } from "./routes/jwks-route.ts";
import { registerOpenIdConfigurationRoute } from "./routes/openid-configuration-route.ts";
import { registerSignupRoute } from "./routes/signup-route.ts";
import { registerTokenRoute } from "./routes/token-route.ts";
import { registerTotpRegistrationRoute } from "./routes/totp-registration-route.ts";
import { registerUserinfoRoute } from "./routes/userinfo-route.ts";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "./stores/authorization-code-store.ts";
import {
  createRefreshTokenStore,
  type RefreshTokenStore,
} from "./stores/refresh-token-store.ts";
import { createTokenStore, type TokenStore } from "./stores/token-store.ts";
import { createUserStore, type UserStore } from "./stores/user-store.ts";

export const defaultAuthorizationServerPort = 4000;

if (import.meta.main) {
  main();
}

export async function main() {
  const fastify = await createServer();

  try {
    await fastify.listen({
      port: getAuthorizationServerPort(),
    });
    fastify.log.info("Authorization server is booted");
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export async function createServer(
  serverConfig?: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  tokenStore: TokenStore = createTokenStore(),
  userStore: UserStore = createUserStore(defaultUsers()),
  refreshTokenStore?: RefreshTokenStore,
) {
  const resolvedServerConfig = serverConfig ?? (await getServerConfig());
  const resolvedRefreshTokenStore =
    refreshTokenStore ?? createRefreshTokenStore();
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
    disableRequestLogging: true,
  });

  logAuthorizationServerConfig(fastify, resolvedServerConfig);

  fastify.register(formbody);

  registerOpenIdConfigurationRoute(fastify, resolvedServerConfig);
  registerAuthorizationRoute(
    fastify,
    resolvedServerConfig,
    authorizationCodeStore,
    userStore,
  );
  registerSignupRoute(fastify, resolvedServerConfig, userStore);
  registerTokenRoute(
    fastify,
    resolvedServerConfig,
    authorizationCodeStore,
    tokenStore,
    resolvedRefreshTokenStore,
    userStore,
  );
  registerTotpRegistrationRoute(fastify);
  registerJwksRoute(fastify, resolvedServerConfig);
  registerUserinfoRoute(fastify, resolvedServerConfig, userStore);

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
      clients: clientsConfig.map(function (client) {
        return {
          clientId: client.clientId,
          requiresMfa: client.requiresMfa ?? false,
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

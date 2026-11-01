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
import { registerMfaChallengeTotpRoute } from "./routes/mfa-challenge-totp-route.ts";
import { registerUserinfoRoute } from "./routes/userinfo-route.ts";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "./stores/authorization-code-store.ts";
import {
  createPendingAuthorizationStore,
  type PendingAuthorizationStore,
} from "./stores/pending-authorization-store.ts";
import {
  createRefreshTokenStore,
  type RefreshTokenStore,
} from "./stores/refresh-token-store.ts";
import { createTokenStore, type TokenStore } from "./stores/token-store.ts";
import { createUserStore, type UserStore } from "./stores/user-store.ts";
import { createTimeBasedOneTimePasswordValidator } from "../otp/time-based-one-time-password.ts";
import { devTotpConfig } from "./config/dev-totp-config.ts";
import { fromBase32 } from "../util/base-encoding.ts";

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
  pendingAuthorizationStore: PendingAuthorizationStore = createPendingAuthorizationStore(),
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  tokenStore: TokenStore = createTokenStore(),
  userStore: UserStore = createUserStore(defaultUsers()),
  refreshTokenStore?: RefreshTokenStore,
) {
  // We'll want to do per use validators later, for testing we've just shared the same validator between all users.
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: fromBase32(devTotpConfig.secretBase32),
    hashAlgorithm: "SHA1",
    codeType: 'numeric', // otpauth:// URLs don't support providing alphanumeric as a type
    codeLength: devTotpConfig.digits,
    timeStepSeconds: devTotpConfig.period
  });

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
    pendingAuthorizationStore,
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
  registerMfaChallengeTotpRoute(
    fastify,
    resolvedServerConfig,
    pendingAuthorizationStore,
    authorizationCodeStore,
    userStore,
    totpValidator,
  );
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
      mfaTransactionLifetimeSeconds: serverConfig.mfaTransactionLifetimeSeconds,
      clients: clientsConfig.map(function (client) {
        return {
          clientId: client.clientId,
          requiresMfa: client.requiresMfa,
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

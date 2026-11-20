import type { ServerContext } from "../server-context.ts";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { jwtVerify } from "jose";
import type { ServerConfig } from "../config/server-config.ts";
import type { GrantStore } from "../stores/grant-store.ts";
import type { UserStore } from "../stores/user-store.ts";
import { getUserClaims } from "../utils/oidc-utils.ts";

const bearerChallenge = `Bearer realm="userinfo"`;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */
export function registerUserinfoRoute(
  fastify: FastifyInstance,
  { serverConfig, grantStore, userStore }: ServerContext,
) {
  fastify.get("/userinfo", async function (request, reply) {
    return await handleUserinfoRequest(
      request,
      reply,
      serverConfig,
      grantStore,
      userStore,
    );
  });

  fastify.post("/userinfo", async function (request, reply) {
    return await handleUserinfoRequest(
      request,
      reply,
      serverConfig,
      grantStore,
      userStore,
    );
  });
}

async function handleUserinfoRequest(
  request: FastifyRequest,
  reply: FastifyReply,
  serverConfig: ServerConfig,
  grantStore: GrantStore,
  userStore: UserStore,
) {
  const token = extractBearerToken(request.headers.authorization);
  if (!token) {
    return sendBearerChallenge(reply);
  }

  if (grantStore.loadAccessToken(token) == null) {
    return sendInvalidTokenResponse(reply);
  }

  try {
    const { payload } = await jwtVerify(
      token,
      serverConfig.signingKey.publicKey,
      {
        algorithms: [serverConfig.jwtSigningAlg],
        audience: serverConfig.issuer,
        issuer: serverConfig.issuer,
        requiredClaims: ["sub", "exp"],
        typ: "at+jwt",
      },
    );

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      return sendInvalidTokenResponse(reply);
    }

    const user = userStore.loadUserById(payload.sub);
    if (user == null) {
      return sendInvalidTokenResponse(reply);
    }

    const response = {
      sub: user.userId,
      ...getUserClaims(user, payload.scope),
    };

    return reply.code(200).send(response);
  } catch {
    return sendInvalidTokenResponse(reply);
  }
}

function extractBearerToken(
  authorizationHeader: string | undefined,
): string | undefined {
  if (!authorizationHeader) {
    return undefined;
  }

  const [scheme, token, extra] = authorizationHeader.trim().split(/\s+/);
  if (scheme !== "Bearer" || !token || extra != null) {
    return undefined;
  }

  return token;
}

function sendBearerChallenge(reply: FastifyReply) {
  return reply.header("WWW-Authenticate", bearerChallenge).code(401).send();
}

function sendInvalidTokenResponse(reply: FastifyReply) {
  return reply
    .header("WWW-Authenticate", `${bearerChallenge}, error="invalid_token"`)
    .code(401)
    .send({
      error: "invalid_token",
    });
}

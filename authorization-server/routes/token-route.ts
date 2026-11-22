import type { ServerContext } from "../server-context.ts";
import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import { type JWTPayload, SignJWT } from "jose";
import { type ClientConfig, clientsConfig } from "../config/clients-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { AccessTokenRecord, GrantStore } from "../stores/grant-store.ts";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import { hasOpenIdScope } from "../utils/oidc-utils.ts";
import { hasScope } from "../utils/oauth-utils.ts";

type TokenRequestBody = {
  grant_type?: string;
  /**
   * Only required if using client_secret_post authentication or no authentication.
   */
  client_id?: string;
  client_secret?: string;
  // Authorization code grant.
  code?: string;
  redirect_uri?: string;
  code_verifier?: string;
  // Refresh token grant.
  refresh_token?: string;
};

type AuthorizationCodeGrantResponse = {
  token_type: "Bearer";
  access_token: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
};

type RefreshTokenGrantResponse = {
  token_type: "Bearer";
  access_token: string;
  expires_in: number;
  id_token?: string;
  scope?: string;
};

/**
 * OAuth 2.0, Authorization Code Grant, Access Token Request
 * https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 *
 * OAuth 2.0, Issuing an Access Token, Successful Response
 * https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 * OAuth 2.0, Issuing an Access Token, Error Response
 * https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export function registerTokenRoute(
  fastify: FastifyInstance,
  { serverConfig, grantStore }: ServerContext,
) {
  const tokenEndpointPath = new URL(serverConfig.tokenEndpoint).pathname;

  fastify.post<{
    Body: TokenRequestBody;
  }>(tokenEndpointPath, async function (request, reply) {
    let clientConfig: ClientConfig | undefined;

    // OAuth 2.0, Client Authentication
    // https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
    // client_secret_basic authentication
    if (request.headers.authorization != null) {
      const clientCredentials = parseBasicAuthorizationHeader(
        request.headers.authorization,
      );
      if (!clientCredentials) {
        return reply
          .code(401)
          .header("www-authenticate", 'Basic realm="token"')
          .send({
            error: "invalid_client",
          });
      }

      // Find a configured client matching the client ID in the given credentials.
      const matchingClientConfig = clientsConfig.find(function (client) {
        return client.clientId === clientCredentials.clientId;
      });

      // Check if matching client is configured to support basic auth and the secret matches.
      if (
        matchingClientConfig == null ||
        matchingClientConfig.clientAuthMethod !== "client_secret_basic" ||
        matchingClientConfig.clientSecret !== clientCredentials.clientSecret
      ) {
        return reply
          .code(401)
          .header("www-authenticate", 'Basic realm="token"')
          .send({
            error: "invalid_client",
          });
      }
      clientConfig = matchingClientConfig;

      // client_id isn't required if using Basic auth, but if they provide it
      // then check it matches the authenticated client.
      if (
        request.body.client_id &&
        request.body.client_id !== clientCredentials.clientId
      ) {
        return reply.code(401).send({
          error: "invalid_client",
        });
      }
    }
    // No auth header, could be a public client, client_secret_post auth, or invalid.
    else {
      const matchingClientConfig = clientsConfig.find(function (client) {
        return client.clientId === request.body.client_id;
      });

      if (matchingClientConfig == null) {
        return reply.code(401).send({
          error: "invalid_client",
          error_description: "Client not found",
        });
      }
      clientConfig = matchingClientConfig;

      if (matchingClientConfig.clientAuthMethod === "client_secret_basic") {
        return reply
          .code(401)
          .header("www-authenticate", 'Basic realm="token"')
          .send({
            error: "invalid_client",
            error_description: "Client requires Basic authentication",
          });
      } else if (
        matchingClientConfig.clientAuthMethod === "client_secret_post"
      ) {
        if (matchingClientConfig.clientSecret !== request.body.client_secret) {
          return reply.code(401).send({
            error: "invalid_client",
            error_description: "client_secret_post authentication failed",
          });
        }
      }
      // We never expect to get there.
      else if (matchingClientConfig.clientAuthMethod !== "none") {
        return reply.code(401).send({
          error: "invalid_client",
        });
      }
    }

    if (clientConfig == null) {
      return reply.code(401).send({
        error: "invalid_client",
      });
    }

    // Switch on grant type.
    if (request.body.grant_type === "authorization_code") {
      return await authCodeGrant({
        body: request.body,
        reply,
        serverConfig,
        clientConfig,
        grantStore,
      });
    } else if (request.body.grant_type === "refresh_token") {
      return await refreshTokenGrant({
        body: request.body,
        reply,
        serverConfig,
        clientConfig,
        grantStore,
      });
    } else {
      return reply.code(400).send({
        error: "unsupported_grant_type",
      });
    }
  });
}

async function authCodeGrant({
  body,
  reply,
  serverConfig,
  clientConfig,
  grantStore,
}: {
  body: TokenRequestBody;
  reply: FastifyReply;
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  grantStore: GrantStore;
}) {
  if (!body.code) {
    return reply.code(400).send({
      error: "invalid_request",
      error_description: "Missing code",
    });
  }

  // Consume the code immediately so every redemption attempt is single-use.
  const authCodeRecord = grantStore.consumeAuthorizationCode(body.code);
  if (authCodeRecord == null) {
    // If an authorization code is re-used we revoke the corresponding grant and tokens.
    const grant = grantStore.getGrantByAuthorizationCode(body.code);
    if (grant?.authorizationCode.usedAt != null) {
      grantStore.revokeGrant(grant.grantId);
    }
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Unknown, used, or invalidated code",
    });
  }

  if (Date.now() > authCodeRecord.expiresAt) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Code expired",
    });
  }

  // Check the client that authenticated matches the one that asked for the auth code.
  if (authCodeRecord.clientId !== clientConfig.clientId) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Code does not match client",
    });
  }

  // redirect_uri is optional, but if it does exist, it must match the value from the authorization request.
  if (
    body.redirect_uri != null &&
    body.redirect_uri !== authCodeRecord.redirectUri
  ) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Invalid redirect_uri",
    });
  }

  // PKCE check. https://datatracker.ietf.org/doc/html/rfc7636
  if (
    authCodeRecord.codeChallengeMethod === "plain" &&
    body.code_verifier !== authCodeRecord.codeChallenge
  ) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "plain code_verifier does not match",
    });
  } else if (authCodeRecord.codeChallengeMethod === "S256") {
    if (body.code_verifier == null) {
      return reply.code(400).send({
        error: "invalid_grant",
        error_description: "Missing code_verifier",
      });
    }
    const codeChallengeFromBody = createHash("sha256")
      .update(body.code_verifier)
      .digest("base64url");
    if (codeChallengeFromBody !== authCodeRecord.codeChallenge) {
      return reply.code(400).send({
        error: "invalid_grant",
        error_description: "S256 code_verifier does not match",
      });
    }
  }

  const authTime = getAuthTimeForTokens(authCodeRecord);

  // Issue an access token.
  const access_token = await generateAccessToken({
    serverConfig,
    clientConfig,
    grantStore,
    grantId: authCodeRecord.grantId,
    scope: authCodeRecord.scope,
    subject: authCodeRecord.subject,
    resource: authCodeRecord.resource,
    amr: authCodeRecord.amr,
    authTime,
  });

  const response: AuthorizationCodeGrantResponse = {
    token_type: "Bearer",
    access_token,
    // OAuth 2.0 Token Response: expires_in
    // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    expires_in: clientConfig.accessTokenLifetimeSeconds,
  };
  // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
  // Scope is required if different to requested, otherwise optional.
  // Just always include will satisfy the spec.
  if (authCodeRecord.scope) {
    response.scope = authCodeRecord.scope;
  }

  // OpenID Connect ID token
  if (hasOpenIdScope(authCodeRecord.scope)) {
    response.id_token = await generateIdToken({
      serverConfig,
      clientConfig,
      subject: authCodeRecord.subject,
      nonce: authCodeRecord.nonce,
      amr: authCodeRecord.amr,
      authTime,
    });
  }

  // Refresh token
  if (hasScope(authCodeRecord.scope, "offline_access")) {
    response.refresh_token = grantStore.generateRefreshToken(
      authCodeRecord.grantId,
      {
        clientId: authCodeRecord.clientId,
        resource: authCodeRecord.resource,
        scope: authCodeRecord.scope,
        subject: authCodeRecord.subject,
        amr: authCodeRecord.amr,
        requiresAuthTime: authCodeRecord.requiresAuthTime,
        authTime: authCodeRecord.authTime,
      },
      clientConfig.refreshTokenLifetimeSeconds,
    );
  }

  return (
    reply
      // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
      // These headers are required by spec for token responses.
      .header("Cache-Control", "no-store")
      .header("Pragma", "no-cache")
      .send(response)
  );
}

async function refreshTokenGrant({
  body,
  reply,
  serverConfig,
  clientConfig,
  grantStore,
}: {
  body: TokenRequestBody;
  reply: FastifyReply;
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  grantStore: GrantStore;
}) {
  if (!body.refresh_token) {
    return reply.code(400).send({
      error: "invalid_request",
      error_description: "Missing refresh_token",
    });
  }

  // Check a matching refresh token exists.
  const refreshRecord = grantStore.getRefreshToken(body.refresh_token);
  if (refreshRecord == null) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Invalid refresh_token",
    });
  }

  // If the refresh token is expired delete it and fail the request.
  const expiresAt = new Date(refreshRecord.expiresAt);
  const now = new Date();
  if (now > expiresAt) {
    grantStore.deleteRefreshToken(body.refresh_token);
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Refresh token expired",
    });
  }

  // Check the refresh token matches the client.
  if (refreshRecord.clientId !== clientConfig.clientId) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Invalid client",
    });
  }

  const authTime = getAuthTimeForTokens(refreshRecord);

  // Issue a new access token.
  const access_token = await generateAccessToken({
    serverConfig,
    clientConfig,
    grantStore,
    grantId: refreshRecord.grantId,
    resource: refreshRecord.resource,
    scope: refreshRecord.scope,
    subject: refreshRecord.subject,
    amr: refreshRecord.amr,
    authTime,
  });
  // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
  const response: RefreshTokenGrantResponse = {
    token_type: "Bearer",
    access_token,
    expires_in: clientConfig.accessTokenLifetimeSeconds,
  };
  // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
  // Scope is required if different to requested, otherwise optional.
  // Just always include will satisfy the spec.
  if (refreshRecord.scope) {
    response.scope = refreshRecord.scope;
  }

  // OpenID Connect ID token
  // https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
  if (hasOpenIdScope(refreshRecord.scope)) {
    response.id_token = await generateIdToken({
      serverConfig,
      clientConfig,
      subject: refreshRecord.subject,
      amr: refreshRecord.amr,
      // no nonce on refresh requests
      authTime,
    });
  }

  return (
    reply
      // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
      // These headers are required by spec for token responses.
      .header("Cache-Control", "no-store")
      .header("Pragma", "no-cache")
      .send(response)
  );
}

function parseBasicAuthorizationHeader(
  authorizationHeader: string | undefined,
) {
  if (!authorizationHeader?.startsWith("Basic ")) {
    return undefined;
  }

  const encodedCredentials = authorizationHeader.slice("Basic ".length);
  const decodedCredentials = Buffer.from(encodedCredentials, "base64").toString(
    "utf8",
  );
  const separatorIndex = decodedCredentials.indexOf(":");
  if (separatorIndex < 0) {
    return undefined;
  }

  return {
    clientId: decodedCredentials.slice(0, separatorIndex),
    clientSecret: decodedCredentials.slice(separatorIndex + 1),
  };
}

/**
 * Generate an access token.
 *
 * OAuth 2.0 Access Token - https://www.rfc-editor.org/info/rfc6749/#section-1.4
 * JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens https://datatracker.ietf.org/doc/html/rfc9068
 */
async function generateAccessToken({
  serverConfig,
  clientConfig,
  grantStore,
  grantId,
  scope,
  subject,
  resource,
  amr,
  authTime,
}: {
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  grantStore: GrantStore;
  grantId: string;
  scope?: string;
  subject: string;
  resource?: string;
  amr?: AuthenticationMethodReference[];
  authTime?: number;
}) {
  if (clientConfig.accessTokenType === "opaque") {
    // Generate and save an access token.
    const accessToken = randomUUID();
    const accessTokenRecord: AccessTokenRecord = {
      type: "opaque",
      clientId: clientConfig.clientId,
    };

    // OAuth 2.0 Step Up Authentication Challenge Protocol, Token Introspection
    // https://www.rfc-editor.org/rfc/rfc9470.html#name-oauth-20-token-introspection
    // This defines providing acr and auth_time on the introspection endpoint.
    // As we include amr on our JWT tokens, save that too for opaque tokens.
    if (amr) {
      accessTokenRecord.amr = amr;
    }
    if (authTime != null) {
      accessTokenRecord.authTime = authTime;
    }

    if (scope) {
      accessTokenRecord.scope = scope;
    }
    grantStore.saveAccessToken(accessToken, grantId, accessTokenRecord);
    return accessToken;
  }
  // accessTokenType === "jwt"
  else {
    // JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
    // https://datatracker.ietf.org/doc/html/rfc9068
    const payload: JWTPayload = {
      iss: serverConfig.issuer,
      aud: getAccessTokenAudience(serverConfig.issuer, scope, resource),
      sub: subject,
      client_id: clientConfig.clientId,
      jti: randomUUID(),
    };

    if (amr) {
      payload.amr = amr;
    }
    if (authTime != null) {
      payload.auth_time = authTime;
    }

    if (scope) {
      payload.scope = scope;
    }
    const nowSeconds = getNowSeconds();
    const accessToken = await new SignJWT(payload)
      .setProtectedHeader({ alg: serverConfig.jwtSigningAlg, typ: "at+jwt" })
      .setIssuedAt(nowSeconds)
      .setExpirationTime(nowSeconds + clientConfig.accessTokenLifetimeSeconds)
      .sign(serverConfig.signingKey.privateKey);
    const accessTokenRecord: AccessTokenRecord = {
      type: "jwt",
    };
    grantStore.saveAccessToken(accessToken, grantId, accessTokenRecord);
    return accessToken;
  }
}

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 */
async function generateIdToken({
  serverConfig,
  clientConfig,
  subject,
  nonce,
  amr,
  authTime,
}: {
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  subject: string;
  nonce?: string;
  amr?: AuthenticationMethodReference[];
  authTime?: number;
}) {
  const idTokenPayload: JWTPayload = {
    iss: serverConfig.issuer,
    aud: clientConfig.clientId,
    sub: subject,
    jti: randomUUID(),
  };
  if (nonce) {
    idTokenPayload.nonce = nonce;
  }
  if (amr) {
    // OIDC Core defines the amr claim for ID Tokens:
    // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    idTokenPayload.amr = amr;
  }
  if (authTime != null) {
    idTokenPayload.auth_time = authTime;
  }

  // We don't copy OIDC standard claims to ID token if issuing an access token.
  // See https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims

  const nowSeconds = getNowSeconds();
  return await new SignJWT(idTokenPayload)
    .setProtectedHeader({ alg: serverConfig.jwtSigningAlg })
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + clientConfig.idTokenLifetimeSeconds)
    .sign(serverConfig.signingKey.privateKey);
}

function getAccessTokenAudience(
  issuer: string,
  scope: string | undefined,
  resource: string | undefined,
) {
  if (resource) {
    if (hasOpenIdScope(scope)) {
      return [issuer, resource];
    }

    return resource;
  }

  return issuer;
}

function getNowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Get the auth time to include on tokens. Only returns if required, and converts to seconds.
 */
export function getAuthTimeForTokens({
  requiresAuthTime,
  authTime,
}: {
  requiresAuthTime: boolean;
  /** Auth time in ms Unix time */
  authTime: number;
}) {
  if (requiresAuthTime) {
    // Round down to avoid accidentally giving an auth_time in the future.
    return Math.floor(authTime / 1000);
  } else {
    return undefined;
  }
}

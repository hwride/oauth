import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { clientsConfig, type ClientConfig } from "../config/clients-config.ts";
import {
  getResourceConfig,
  isSupportedResource,
  type SupportedResource,
} from "../config/resources-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { AuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import { type PendingAuthorizationStore } from "../stores/pending-authorization-store.ts";
import type { UserRecord, UserStore } from "../stores/user-store.ts";
import type {
  AuthorizationRequest,
  AuthorizationRequestError,
} from "../types/authorization-request.ts";
import { getAllowedScopesForUser } from "../utils/rbac-utils.ts";

type AuthorizeQueryParams = {
  client_id?: string;
  response_type?: string;
  redirect_uri?: string;
  scope?: string;
  nonce?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  resource?: string;
};

export function registerAuthorizationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  pendingAuthorizationStore: PendingAuthorizationStore,
  authorizationCodeStore: AuthorizationCodeStore,
  userStore: UserStore,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;

  // Main authorization endpoint.
  fastify.get<{
    Querystring: AuthorizeQueryParams;
  }>(authorizationEndpointPath, async function (request, reply) {
    const validationResult = validateAuthorizationRequest(request.query);
    if (validationResult.ok === false) {
      return reply
        .code(validationResult.authorizationError.statusCode)
        .send(validationResult.authorizationError.error);
    }

    return reply
      .type("text/html; charset=utf-8")
      .send(
        renderLoginPage(
          authorizationEndpointPath,
          validationResult.authorizationRequest,
        ),
      );
  });

  // Endpoint to submit login form to if login is required.
  fastify.post<{
    Body: AuthorizeQueryParams & {
      username?: string;
      password?: string;
    };
  }>(authorizationEndpointPath, async function (request, reply) {
    const validationResult = validateAuthorizationRequest(request.body);
    if (validationResult.ok === false) {
      return reply
        .code(validationResult.authorizationError.statusCode)
        .send(validationResult.authorizationError.error);
    }
    const { authorizationRequest, clientConfig } = validationResult;

    const user = authenticateUser(
      userStore,
      request.body.username,
      request.body.password,
    );
    if (user == null) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderLoginPage(
            authorizationEndpointPath,
            authorizationRequest,
            "Invalid username or password",
          ),
        );
    }

    // Challenge MFA if required.
    if (clientConfig.requiresMfa) {
      // Save the pending authorization request in our store against a transaction ID.
      // Then when an MFA challenge is made, we can ensure it must match the correct transaction.
      const transactionId = randomUUID();
      pendingAuthorizationStore.savePendingAuthorization(transactionId, {
        authorizationRequest,
        subject: user.userId,
        expiresAt:
          Date.now() + serverConfig.mfaTransactionLifetimeSeconds * 1000,
      });
      return reply.redirect(`/mfa-challenge-totp?tx=${transactionId}`);
    }

    return reply.redirect(
      createAuthorizationRedirectUrl(
        serverConfig,
        authorizationCodeStore,
        authorizationRequest,
        user,
      ),
    );
  });
}

type AuthorizationRequestValidationResult =
  | {
      ok: true;
      authorizationRequest: AuthorizationRequest;
      clientConfig: ClientConfig;
    }
  | {
      ok: false;
      authorizationError: AuthorizationRequestError;
    };

const unrestrictedScopes = new Set([
  "openid",
  "profile",
  "email",
  "address",
  "phone",
  "offline_access",
]);

function validateAuthorizationRequest(
  input: AuthorizeQueryParams,
): AuthorizationRequestValidationResult {
  // Check for valid input.
  // OAuth 2.0, Authorization Response, Error Response
  // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
  if (!input.redirect_uri) {
    return {
      ok: false,
      authorizationError: {
        statusCode: 400,
        error: {
          error: "invalid_request",
          error_description: "Missing redirect_uri",
        },
      },
    };
  }

  // Check for a matching client.
  const clientConfig = clientsConfig.find(function (client) {
    return client.clientId === input.client_id;
  });
  if (!clientConfig) {
    return {
      ok: false,
      authorizationError: {
        statusCode: 400,
        error: {
          error: "invalid_request",
          error_description: "Invalid client_id",
        },
      },
    };
  }

  // Check for matching redirect URI.
  if (!clientConfig.redirectUris.includes(input.redirect_uri)) {
    return {
      ok: false,
      authorizationError: {
        statusCode: 400,
        error: {
          error: "invalid_request",
          error_description: "Invalid redirect_uri",
        },
      },
    };
  }

  // Check for supported grant type.
  if (input.response_type !== "code") {
    return {
      ok: false,
      authorizationError: {
        statusCode: 400,
        error: {
          error: "unsupported_response_type",
        },
      },
    };
  }

  let requestedResource: SupportedResource | undefined;
  if (input.resource) {
    if (!isSupportedResource(input.resource)) {
      return {
        ok: false,
        authorizationError: createInvalidTargetError(),
      };
    }
    requestedResource = input.resource;
  }

  const successResponse: AuthorizationRequest = {
    clientId: clientConfig.clientId,
    redirectUri: input.redirect_uri,
    responseType: input.response_type,
    scope: input.scope,
    nonce: input.nonce,
    state: input.state,
    resource: requestedResource,
  };

  // Expose PKCE data. https://datatracker.ietf.org/doc/html/rfc7636
  if (input.code_challenge) {
    if (
      input.code_challenge_method != null &&
      !["plain", "S256"].includes(input.code_challenge_method)
    ) {
      return {
        ok: false,
        authorizationError: {
          statusCode: 400,
          error: {
            error: "invalid_request",
            error_description: "Unsupported code_challenge_method",
          },
        },
      };
    }

    successResponse.codeChallenge = input.code_challenge;
    successResponse.codeChallengeMethod =
      input.code_challenge_method === "S256" ? "S256" : "plain";
  }

  return {
    ok: true,
    authorizationRequest: successResponse,
    clientConfig,
  };
}

function renderLoginPage(
  authorizationEndpointPath: string,
  authorizationRequest: AuthorizationRequest,
  errorMessage?: string,
) {
  const escapedErrorMessage = errorMessage
    ? `<p>${escapeHtml(errorMessage)}</p>`
    : "";
  const signupPathSearchParams = new URLSearchParams({
    client_id: authorizationRequest.clientId,
    response_type: authorizationRequest.responseType,
    redirect_uri: authorizationRequest.redirectUri,
  });
  const setIfExists = (
    sourceKey: Exclude<keyof AuthorizationRequest, "clientId">,
    targetKey: string,
  ) => {
    if (authorizationRequest[sourceKey]) {
      signupPathSearchParams.set(targetKey, authorizationRequest[sourceKey]);
    }
  };
  setIfExists("state", "state");
  setIfExists("scope", "scope");
  setIfExists("nonce", "nonce");
  setIfExists("codeChallenge", "code_challenge");
  setIfExists("codeChallengeMethod", "code_challenge_method");
  setIfExists("resource", "resource");
  const signupPath = `/signup?${signupPathSearchParams.toString()}`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Login</title>
  </head>
  <body>
    <h1>Login</h1>
    <p>Sign in to continue for client ${escapeHtml(authorizationRequest.clientId)}.</p>
    ${escapedErrorMessage}
    <form method="post" action="${escapeHtml(authorizationEndpointPath)}">
      <input type="hidden" name="client_id" value="${escapeHtml(authorizationRequest.clientId)}">
      <input type="hidden" name="response_type" value="${escapeHtml(authorizationRequest.responseType)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(authorizationRequest.redirectUri)}">
      <input type="hidden" name="scope" value="${escapeHtml(authorizationRequest.scope ?? "")}">
      <input type="hidden" name="nonce" value="${escapeHtml(authorizationRequest.nonce ?? "")}">
      <input type="hidden" name="state" value="${escapeHtml(authorizationRequest.state ?? "")}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(authorizationRequest.codeChallenge ?? "")}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(authorizationRequest.codeChallengeMethod ?? "")}">
      <input type="hidden" name="resource" value="${escapeHtml(authorizationRequest.resource ?? "")}">
      <label>
        Username
        <input type="text" name="username" autocomplete="username" required>
      </label>
      <label>
        Password
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Login</button>
    </form>
    <p><a href="${escapeHtml(signupPath)}">Sign up</a></p>
  </body>
</html>`;
}

function authenticateUser(
  userStore: UserStore,
  username?: string,
  password?: string,
): UserRecord | undefined {
  if (!username || !password) {
    return undefined;
  }

  const user = userStore.loadUserByUsername(username);
  if (user?.password !== password) {
    return undefined;
  }
  return user;
}

export function createAuthorizationRedirectUrl(
  serverConfig: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore,
  authorizationRequest: AuthorizationRequest,
  user: UserRecord,
) {
  const code = randomUUID();
  authorizationCodeStore.saveAuthorizationCode(code, {
    clientId: authorizationRequest.clientId,
    subject: user.userId,
    redirectUri: authorizationRequest.redirectUri,
    scope: filterAllowedScopes(
      authorizationRequest.scope,
      user,
      authorizationRequest.resource,
    ),
    nonce: authorizationRequest.nonce,
    resource: authorizationRequest.resource,
    expiresAt:
      Date.now() + serverConfig.authorizationCodeLifetimeSeconds * 1000,
    codeChallenge: authorizationRequest.codeChallenge,
    codeChallengeMethod: authorizationRequest.codeChallengeMethod,
  });

  const redirectUrl = new URL(authorizationRequest.redirectUri);
  redirectUrl.searchParams.set("code", code);
  if (authorizationRequest.state) {
    redirectUrl.searchParams.set("state", authorizationRequest.state);
  }
  return redirectUrl.toString();
}

function filterAllowedScopes(
  requestedScope: string | undefined,
  user: UserRecord,
  requestedResource: SupportedResource | undefined,
): string | undefined {
  const filteredUserScopes = filterAllowedUserScopes(requestedScope, user);
  return filterAllowedResourceScopes(filteredUserScopes, requestedResource);
}

/**
 * Filter scopes according to what is allowed for a user.
 *
 * Takes into account user roles and allowed scopes.
 */
function filterAllowedUserScopes(
  requestedScope: string | undefined,
  user: UserRecord,
): string | undefined {
  if (!requestedScope) {
    return requestedScope;
  }

  const requestedScopes = requestedScope
    .split(/\s+/)
    .filter((scope) => scope.length > 0);

  const allowedScopes = new Set<string>(getAllowedScopesForUser(user));
  const filteredScopes = requestedScopes.filter((scope) => {
    return unrestrictedScopes.has(scope) || allowedScopes.has(scope);
  });

  return filteredScopes.length > 0 ? filteredScopes.join(" ") : undefined;
}

/**
 * Filter scopes according to what is allowed for a resource.
 */
function filterAllowedResourceScopes(
  requestedScope: string | undefined,
  requestedResource: SupportedResource | undefined,
): string | undefined {
  if (!requestedScope || !requestedResource) {
    return requestedScope;
  }

  const resourceConfig = getResourceConfig(requestedResource);
  const allowedScopes = new Set<string>(resourceConfig.allowedScopes);
  const requestedScopes = requestedScope
    .split(/\s+/)
    .filter((scope) => scope.length > 0);

  const filteredScopes = requestedScopes.filter((scope) => {
    return unrestrictedScopes.has(scope) || allowedScopes.has(scope);
  });

  return filteredScopes.length > 0 ? filteredScopes.join(" ") : undefined;
}

function createInvalidTargetError(): AuthorizationRequestError {
  return {
    statusCode: 400,
    error: {
      error: "invalid_target",
      error_description: "Unsupported resource indicator",
    },
  };
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

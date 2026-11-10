import type { ServerContext } from "../server-context.ts";
import type { FastifyInstance } from "fastify";
import { type ClientConfig, clientsConfig } from "../config/clients-config.ts";
import {
  isSupportedResource,
  type SupportedResource,
} from "../config/resources-config.ts";
import type { UserRecord, UserStore } from "../stores/user-store.ts";
import type {
  AuthorizationRequest,
  AuthorizationRequestError,
} from "../types/authorization-request.ts";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import { isUuidV4 } from "../utils/uuid.ts";
import { escapeHtml } from "../utils/html-utils.ts";
import { createAuthorizationRedirectUrl } from "../utils/authorization-route-utils.ts";
import {
  getSessionCookie,
  getSessionCookieClear,
  loadSessionFromCookie,
} from "../utils/session-utils.ts";

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
  {
    serverConfig,
    pendingAuthorizationStore,
    authorizationCodeStore,
    sessionStore,
    userStore,
  }: ServerContext,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;

  // Main authorization endpoint.
  fastify.get<{
    Querystring: AuthorizeQueryParams;
  }>(authorizationEndpointPath, async function (request, reply) {
    // Make sure we don't leak tx ID query param.
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
    const validationResult = validateAuthorizationRequest(request.query);
    if (validationResult.ok === false) {
      return reply
        .code(validationResult.authorizationError.statusCode)
        .send(validationResult.authorizationError.error);
    }

    // If there's an existing auth server session, we can skip authentication and return immediately.
    const sessionResult = loadSessionFromCookie(
      request,
      sessionStore,
      userStore,
    );
    if (sessionResult.ok === true) {
      return reply.redirect(
        createAuthorizationRedirectUrl(
          serverConfig,
          authorizationCodeStore,
          validationResult.authorizationRequest,
          sessionResult.user,
          sessionResult.session.amr,
        ),
      );
    }
    // If there is a problem with the session, proceed to normal login and clear the existing session if one was present.
    else if (sessionResult.sessionIdWasPresent) {
      reply.header("Set-Cookie", getSessionCookieClear());
    }

    const transactionId = pendingAuthorizationStore.newPendingAuthorization({
      stage: "login",
      authorizationRequest: validationResult.authorizationRequest,
      amr: [],
      mfaFailedAttempts: 0,
      expiresAt: Date.now() + serverConfig.mfaTransactionLifetimeSeconds * 1000,
    });

    return reply
      .type("text/html; charset=utf-8")
      .send(
        renderLoginPage(
          authorizationEndpointPath,
          validationResult.authorizationRequest,
          transactionId,
        ),
      );
  });

  // Endpoint to submit login form to if login is required.
  fastify.post<{
    Querystring: { tx?: string };
    Body: {
      username?: string;
      password?: string;
    };
  }>(authorizationEndpointPath, async function (request, reply) {
    // Make sure we don't leak tx ID query param.
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
    const { tx } = request.query;
    if (!isUuidV4(tx)) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Login transaction ID not valid",
      });
    }

    const pending = pendingAuthorizationStore.loadPendingAuthorization(tx);
    if (pending == null) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Login transaction not found or expired",
      });
    }

    if (pending.stage !== "login") {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Login transaction is not waiting for login",
      });
    }
    const { authorizationRequest } = pending;

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
            tx,
            "Invalid username or password",
          ),
        );
    }

    // Challenge MFA when the authenticated user has a registered TOTP factor.
    if (
      user.mfaRegistrations?.some(
        (registration) => registration.type === "TOTP",
      )
    ) {
      const updateResult = pendingAuthorizationStore.updatePendingAuthorization(
        tx,
        "login",
        (record) => ({
          ...record,
          stage: "mfa",
          userId: user.userId,
          // Password authentication, represented by RFC 8176's "pwd" AMR value.
          amr: ["pwd"],
          mfaFailedAttempts: 0,
          expiresAt:
            Date.now() + serverConfig.mfaTransactionLifetimeSeconds * 1000,
        }),
      );
      if (updateResult !== "updated") {
        return reply.code(400).send({
          error: "invalid_request",
          error_description: "Login transaction not found or expired",
        });
      }
      return reply.redirect(`/mfa-challenge-totp?tx=${tx}`);
    }

    // Consume the transaction once authorization is complete.
    if (!pendingAuthorizationStore.deletePendingAuthorization(tx)) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Login transaction not found or expired",
      });
    }

    // We successfully authenticated with password here, create a session.
    const amr: AuthenticationMethodReference[] = ["pwd"];
    const session = sessionStore.newSession({
      userId: user.userId,
      amr,
    });

    return reply
      .header("Set-Cookie", getSessionCookie(session, serverConfig))
      .redirect(
        createAuthorizationRedirectUrl(
          serverConfig,
          authorizationCodeStore,
          authorizationRequest,
          user,
          // Password authentication, represented by RFC 8176's "pwd" AMR value.
          amr,
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
  transactionId: string,
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
  const loginActionUrl = new URL(authorizationEndpointPath, "http://localhost");
  loginActionUrl.searchParams.set("tx", transactionId);
  const loginAction = loginActionUrl.pathname + loginActionUrl.search;

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
    <form method="post" action="${escapeHtml(loginAction)}">
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

function createInvalidTargetError(): AuthorizationRequestError {
  return {
    statusCode: 400,
    error: {
      error: "invalid_target",
      error_description: "Unsupported resource indicator",
    },
  };
}

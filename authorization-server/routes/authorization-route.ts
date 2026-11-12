import type { ServerContext } from "../server-context.ts";
import type { FastifyInstance } from "fastify";
import { type ClientConfig, clientsConfig } from "../config/clients-config.ts";
import {
  isSupportedResource,
  type SupportedResource,
} from "../config/resources-config.ts";
import type { UserRecord, UserStore } from "../stores/user-store.ts";
import {
  type AuthorizationRequest,
  type AuthorizationRequestError,
  type Prompt,
  prompts,
} from "../types/authorization-request.ts";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import { isUuidV4 } from "../utils/uuid.ts";
import { escapeHtml } from "../utils/html-utils.ts";
import { issueAuthorizationCodeAndRedirect } from "../utils/authorization-route-utils.ts";
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
  max_age?: string;
  prompt?: string;
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
  // Authentication Request - https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
  fastify.get<{
    Querystring: AuthorizeQueryParams;
  }>(authorizationEndpointPath, async function (request, reply) {
    // Make sure we don't leak tx ID query param.
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");

    // Validate authorization request data.
    const validationResult = validateAuthorizationRequest(request.query);
    if (validationResult.ok === false) {
      return reply
        .code(validationResult.authorizationError.statusCode)
        .send(validationResult.authorizationError.error);
    }

    const { authorizationRequest } = validationResult;
    const { maxAge, prompt } = authorizationRequest;
    const requiresAuthTime = maxAge != null;

    // If there's an existing auth server session and it passes max_age requirements, we can skip authentication and
    // return immediately.
    const sessionResult = loadSessionFromCookie(
      request,
      sessionStore,
      userStore,
    );
    if (sessionResult.ok === true) {
      let canUseSession = true;

      // Force a fresh-auth here.
      if (maxAge === 0 || prompt?.includes("login")) {
        canUseSession = false;
      }
      // Otherwise if max_age was included, check if our session passes the freshness check.
      else if (maxAge != null && maxAge > 0) {
        const maxAgeMs = maxAge * 1000;
        const sessionAge = Date.now() - sessionResult.session.authTime;
        canUseSession = sessionAge <= maxAgeMs;
      }

      // Otherwise allow re-use of the session.
      if (canUseSession) {
        return reply.redirect(
          issueAuthorizationCodeAndRedirect(
            serverConfig,
            authorizationCodeStore,
            authorizationRequest,
            sessionResult.user,
            sessionResult.session.amr,
            sessionResult.session.authTime,
            requiresAuthTime,
          ),
        );
      }
    } else {
      // If there is a problem with the session, proceed to normal login and clear the existing session if one was present.
      // The loadSessionFromCookie util will have removed any invalid sessions if they exist.
      if (sessionResult.sessionIdWasPresent) {
        reply.header("Set-Cookie", getSessionCookieClear());
      }
    }

    // Should error if attempting to skip prompt without a session.
    if (prompt?.includes("none")) {
      return reply.code(400).send({
        error: "login_required",
        error_description: "Login is required",
      } satisfies AuthorizationRequestError["error"]);
    }

    // Create a new pending authorization transaction.
    const transactionId = pendingAuthorizationStore.newPendingAuthorization({
      stage: "login",
      authorizationRequest: validationResult.authorizationRequest,
      amr: [],
      mfaFailedAttempts: 0,
      expiresAt: Date.now() + serverConfig.mfaTransactionLifetimeSeconds * 1000,
      requiresAuthTime,
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
    const authTime = Date.now();

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
      authTime,
    });

    return reply
      .header("Set-Cookie", getSessionCookie(session, serverConfig))
      .redirect(
        issueAuthorizationCodeAndRedirect(
          serverConfig,
          authorizationCodeStore,
          authorizationRequest,
          user,
          // Password authentication, represented by RFC 8176's "pwd" AMR value.
          amr,
          authTime,
          pending.requiresAuthTime,
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

  const authorizationRequest: AuthorizationRequest = {
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

    authorizationRequest.codeChallenge = input.code_challenge;
    authorizationRequest.codeChallengeMethod =
      input.code_challenge_method === "S256" ? "S256" : "plain";
  }

  // max_age
  if (input.max_age != null) {
    const maxAge = Number(input.max_age);
    // We later store max age as ms, so don't allow values larger than can be stored as numbers in there.
    const maxValue = Math.floor(Number.MAX_SAFE_INTEGER / 1000);
    if (!/^\d+$/.test(input.max_age) || maxAge > maxValue) {
      return {
        ok: false,
        authorizationError: {
          statusCode: 400,
          error: {
            error: "invalid_request",
            error_description: "Invalid max_age",
          },
        },
      };
    }
    authorizationRequest.maxAge = maxAge;
  }

  // prompt
  if (input.prompt != null) {
    const promptError = {
      ok: false,
      authorizationError: {
        statusCode: 400,
        error: {
          error: "invalid_request",
          error_description: "Invalid prompt",
        },
      },
    } as const;

    if (typeof input.prompt !== "string") {
      return promptError;
    }

    // Check only valid prompts are given.
    const validPrompts: Set<string> = new Set(prompts);
    const promptParts = input.prompt.split(" ");
    let hasNone = false;
    const hasValidPrompts = promptParts.every((prompt) => {
      if (prompt === "none") hasNone = true;
      return validPrompts.has(prompt);
    });
    if (!hasValidPrompts) {
      return promptError;
    }

    // Check if none is provided, no other prompts are used.
    if (hasNone && promptParts.length > 1) {
      return promptError;
    }

    authorizationRequest.prompt = promptParts as Prompt[];
  }

  return {
    ok: true,
    authorizationRequest,
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
    if (authorizationRequest[sourceKey] != null) {
      signupPathSearchParams.set(
        targetKey,
        String(authorizationRequest[sourceKey]),
      );
    }
  };
  setIfExists("state", "state");
  setIfExists("scope", "scope");
  setIfExists("nonce", "nonce");
  setIfExists("codeChallenge", "code_challenge");
  setIfExists("codeChallengeMethod", "code_challenge_method");
  setIfExists("resource", "resource");
  setIfExists("maxAge", "max_age");
  if (authorizationRequest.prompt != null) {
    signupPathSearchParams.set("prompt", authorizationRequest.prompt.join(" "));
  }
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

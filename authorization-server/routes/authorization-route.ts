import type { ServerContext } from "../server-context.ts";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { type ClientConfig, clientsConfig } from "../config/clients-config.ts";
import {
  isSupportedResource,
  type SupportedResource,
} from "../config/resources-config.ts";
import type { UserRecord, UserStore } from "../stores/user-store.ts";
import {
  type AuthorizationRequest,
  type Prompt,
  prompts,
} from "../types/authorization-request.ts";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import { isUuidV4 } from "../utils/uuid.ts";
import { escapeHtml } from "../utils/html-utils.ts";
import {
  getMfaChallengeTotpPath,
  issueAuthorizationCodeAndRedirect,
} from "../utils/authorization-route-utils.ts";
import {
  getSessionCookie,
  getSessionCookieClear,
  loadSessionFromCookie,
} from "../utils/session-utils.ts";
import { getAcrLevel2, hasAcr } from "../utils/authentication-context-utils.ts";

/**
 * Parameter for OAuth authorization request or OIDC authentication request.
 */
type AuthorizeParams = {
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
  acr_values?: string;
  prompt?: string;
  request?: string;
};

type LoginFormBody = {
  username?: string;
  password?: string;
};

/**
 * /authorize route
 *
 * General flow is as follows:
 * 1. OAuth/OIDC authorization request is submitted, with either GET or POST.
 * 2. Validation of params is performed. If valid check for existing valid authentication server session. If valid go to
 *    step 5, if invalid go to step 3.
 * 3. A login transaction is created, and the user is return login page HTML and ?tx=<tx-id>.
 * 4. The user then submits the login form to POST /authorize/login. If credentials are valid, is MFA required? If yes
 *    go to step 5, if no go to step 6.
 * 5. Perform MFA. If successful go to step 6.
 * 6. Create an auth server session created for the user.
 * 7. Issued an authorization code and redirect to the configured client callback redirect URI with ?code=<code>.
 *
 * Authorization Endpoint - https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
 * Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 * Authentication Request - https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
 */
export function registerAuthorizationRoute(
  fastify: FastifyInstance,
  {
    serverConfig,
    pendingAuthorizationStore,
    grantStore,
    sessionStore,
    userStore,
  }: ServerContext,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;
  const loginEndpointPath = `${authorizationEndpointPath.replace(/\/$/, "")}/login`;

  /**
   * GET /authorize endpoint.
   */
  fastify.get<{
    Querystring: AuthorizeParams;
  }>(authorizationEndpointPath, async function (request, reply) {
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");

    // Validate authorization request data.
    const validationResult = validateAuthorizationRequest(request.query, reply);
    // In validation fails the util will have handled the response.
    if (validationResult.ok === false) {
      return;
    }

    return handleAuthorizationRequest({
      request,
      reply,
      loginEndpointPath,
      authorizationRequest: validationResult.authorizationRequest,
      serverConfig,
      pendingAuthorizationStore,
      grantStore,
      sessionStore,
      userStore,
    });
  });

  /**
   * POST /authorize endpoint.
   *
   * This is the POST version of submitting an authorization request. It creates a login transaction when user
   * authentication is required. See
   * - https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
   * - https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
   */
  fastify.post<{
    Body: AuthorizeParams;
  }>(authorizationEndpointPath, async function (request, reply) {
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
    const validationResult = validateAuthorizationRequest(request.body, reply);
    // If validation fails the util will have handled the response.
    if (validationResult.ok === false) {
      return;
    }

    return handleAuthorizationRequest({
      request,
      reply,
      loginEndpointPath,
      authorizationRequest: validationResult.authorizationRequest,
      serverConfig,
      pendingAuthorizationStore,
      grantStore,
      sessionStore,
      userStore,
    });
  });

  /**
   * POST /authorize/login endpoint.
   *
   * Handles credentials submitted for an active login transaction.
   */
  fastify.post<{
    Querystring: { tx?: string };
    Body: LoginFormBody;
  }>(loginEndpointPath, async function (request, reply) {
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
      return sendPostErrorResponse({
        reply,
        error: "invalid_request",
        error_description: "Login transaction not found or expired",
      });
    }

    if (pending.stage !== "login") {
      return sendRedirectErrorResponse({
        reply,
        redirectUri: pending.authorizationRequest.redirectUri,
        state: pending.authorizationRequest.state,
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
            loginEndpointPath,
            authorizationRequest,
            tx,
            "Invalid username or password",
          ),
        );
    }
    const authTime = Date.now();

    const requiresLevel2Acr = hasRequestedLevel2Acr(
      authorizationRequest,
      serverConfig.issuer,
    );
    const hasRegisteredTotp = userHasRegisteredTotp(user);

    // If the user has requested level-2 acr and does not have MFA registered then reject the request.
    if (requiresLevel2Acr && !hasRegisteredTotp) {
      pendingAuthorizationStore.deletePendingAuthorization(tx);
      return sendRedirectErrorResponse({
        reply,
        redirectUri: pending.authorizationRequest.redirectUri,
        state: pending.authorizationRequest.state,
        error: "unmet_authentication_requirements",
        error_description:
          "The requested authentication context cannot be satisfied",
      });
    }

    // Challenge MFA when enabled and the authenticated user has a registered TOTP factor.
    if (
      ((user.enforceMfaAtLogin ?? true) || requiresLevel2Acr) &&
      hasRegisteredTotp
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
        return sendRedirectErrorResponse({
          reply,
          redirectUri: pending.authorizationRequest.redirectUri,
          state: pending.authorizationRequest.state,
          error: "invalid_request",
          error_description: "Login transaction not found or expired",
        });
      }
      return reply.redirect(getMfaChallengeTotpPath(tx));
    }

    // Consume the transaction once authorization is complete.
    if (!pendingAuthorizationStore.deletePendingAuthorization(tx)) {
      return sendRedirectErrorResponse({
        reply,
        redirectUri: pending.authorizationRequest.redirectUri,
        state: pending.authorizationRequest.state,
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
          grantStore,
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
    };

function validateAuthorizationRequest(
  params: AuthorizeParams,
  reply: FastifyReply,
): AuthorizationRequestValidationResult {
  const sendPostErrorResponseHelper = ({
    error,
    error_description,
  }: {
    error: string;
    error_description: string;
  }) => {
    sendPostErrorResponse({
      reply,
      error,
      error_description,
    });
    return { ok: false } as const;
  };

  // Check for valid input.
  // OAuth 2.0, Authorization Response, Error Response
  // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
  if (!params.redirect_uri) {
    return sendPostErrorResponseHelper({
      error: "invalid_request",
      error_description: "Missing redirect_uri",
    });
  }
  const redirectUri = params.redirect_uri;

  // Check for a matching client.
  const clientConfig = clientsConfig.find(function (client) {
    return client.clientId === params.client_id;
  });
  if (!clientConfig) {
    return sendPostErrorResponseHelper({
      error: "invalid_request",
      error_description: "Invalid client_id",
    });
  }

  // Check for matching redirect URI.
  if (!clientConfig.redirectUris.includes(redirectUri)) {
    return sendPostErrorResponseHelper({
      error: "invalid_request",
      error_description: "Invalid redirect_uri",
    });
  }

  const sendRedirectErrorResponseHelper = ({
    error,
    error_description,
  }: {
    error: string;
    error_description: string;
  }) => {
    sendRedirectErrorResponse({
      reply,
      redirectUri,
      state: params.state != null ? params.state : undefined,
      error,
      error_description,
    });
    return { ok: false } as const;
  };

  if (params.request != null) {
    return sendRedirectErrorResponseHelper({
      error: "request_not_supported",
      error_description: "The request parameter is not supported",
    });
  }

  // Check for supported grant type.
  if (params.response_type !== "code") {
    return sendRedirectErrorResponseHelper({
      error: "unsupported_response_type",
      error_description: "Unsupported response_type value",
    });
  }

  let requestedResource: SupportedResource | undefined;
  if (params.resource) {
    if (!isSupportedResource(params.resource)) {
      return sendRedirectErrorResponseHelper({
        error: "invalid_target",
        error_description: "Unsupported resource indicator",
      });
    }
    requestedResource = params.resource;
  }

  const authorizationRequest: AuthorizationRequest = {
    clientId: clientConfig.clientId,
    redirectUri,
    responseType: params.response_type,
    scope: params.scope,
    nonce: params.nonce,
    state: params.state,
    resource: requestedResource,
  };
  if (params.acr_values != null) {
    authorizationRequest.acrValues = params.acr_values;
  }

  // Expose PKCE data. https://datatracker.ietf.org/doc/html/rfc7636
  if (params.code_challenge) {
    if (
      params.code_challenge_method != null &&
      !["plain", "S256"].includes(params.code_challenge_method)
    ) {
      return sendRedirectErrorResponseHelper({
        error: "invalid_request",
        error_description: "Unsupported code_challenge_method",
      });
    }

    authorizationRequest.codeChallenge = params.code_challenge;
    authorizationRequest.codeChallengeMethod =
      params.code_challenge_method === "S256" ? "S256" : "plain";
  }

  // max_age
  if (params.max_age != null) {
    const maxAge = Number(params.max_age);
    // We later store max age as ms, so don't allow values larger than can be stored as numbers in there.
    const maxValue = Math.floor(Number.MAX_SAFE_INTEGER / 1000);
    if (!/^\d+$/.test(params.max_age) || maxAge > maxValue) {
      return sendRedirectErrorResponseHelper({
        error: "invalid_request",
        error_description: "Invalid max_age",
      });
    }
    authorizationRequest.maxAge = maxAge;
  }

  // prompt
  if (params.prompt != null) {
    const sendInvalidPromptResponse = () =>
      sendRedirectErrorResponseHelper({
        error: "invalid_request",
        error_description: "Invalid prompt",
      });

    if (typeof params.prompt !== "string") {
      return sendInvalidPromptResponse();
    }

    // Check only valid prompts are given.
    const validPrompts: Set<string> = new Set(prompts);
    const promptParts = params.prompt.split(" ");
    let hasNone = false;
    const hasValidPrompts = promptParts.every((prompt) => {
      if (prompt === "none") hasNone = true;
      return validPrompts.has(prompt);
    });
    if (!hasValidPrompts) {
      return sendInvalidPromptResponse();
    }

    // Check if none is provided, no other prompts are used.
    if (hasNone && promptParts.length > 1) {
      return sendInvalidPromptResponse();
    }

    authorizationRequest.prompt = promptParts as Prompt[];
  }

  return {
    ok: true,
    authorizationRequest,
    clientConfig,
  };
}

/**
 * Main OAuth authorization request handler.
 *
 * Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 * Authentication Request - https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
 */
function handleAuthorizationRequest({
  request,
  reply,
  loginEndpointPath,
  authorizationRequest,
  serverConfig,
  pendingAuthorizationStore,
  grantStore,
  sessionStore,
  userStore,
}: {
  request: FastifyRequest;
  reply: FastifyReply;
  loginEndpointPath: string;
  authorizationRequest: AuthorizationRequest;
  serverConfig: ServerContext["serverConfig"];
  pendingAuthorizationStore: ServerContext["pendingAuthorizationStore"];
  grantStore: ServerContext["grantStore"];
  sessionStore: ServerContext["sessionStore"];
  userStore: ServerContext["userStore"];
}) {
  const { maxAge, prompt } = authorizationRequest;
  const requiresMfa = hasRequestedLevel2Acr(
    authorizationRequest,
    serverConfig.issuer,
  );
  const requiresAuthTime = maxAge != null;

  const sessionResult = loadSessionFromCookie(request, sessionStore, userStore);

  // Check if an existing session will satisfy authentication requirements.
  if (sessionResult.ok === true) {
    let canSkipAuthentication = true;

    // Force a fresh-auth here.
    if (maxAge === 0 || prompt?.includes("login")) {
      canSkipAuthentication = false;
    }
    // Otherwise if max_age was included, check if our session passes the freshness check.
    else if (maxAge != null && maxAge > 0) {
      const maxAgeMs = maxAge * 1000;
      const sessionAge = Date.now() - sessionResult.session.authTime;
      canSkipAuthentication = sessionAge <= maxAgeMs;
    }

    // A level-2 request requires a session established with MFA.
    if (requiresMfa && !sessionResult.session.amr.includes("mfa")) {
      canSkipAuthentication = false;
    }

    // Otherwise allow re-use of the session.
    if (canSkipAuthentication) {
      return reply.redirect(
        issueAuthorizationCodeAndRedirect(
          serverConfig,
          grantStore,
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
    return sendRedirectErrorResponse({
      reply,
      redirectUri: authorizationRequest.redirectUri,
      state: authorizationRequest.state,
      error: "login_required",
      error_description: "Login is required",
    });
  }

  // If MFA is required and there is an active session re-use the username/password auth
  // so we only need to prompt for MFA.
  if (requiresMfa && sessionResult.ok && !prompt?.includes("login")) {
    if (!userHasRegisteredTotp(sessionResult.user)) {
      return sendRedirectErrorResponse({
        reply,
        redirectUri: authorizationRequest.redirectUri,
        state: authorizationRequest.state,
        error: "unmet_authentication_requirements",
        error_description:
          "The requested authentication context cannot be satisfied",
      });
    }

    const transactionId = pendingAuthorizationStore.newPendingAuthorization({
      stage: "mfa",
      authorizationRequest,
      userId: sessionResult.user.userId,
      amr: sessionResult.session.amr,
      mfaFailedAttempts: 0,
      expiresAt: Date.now() + serverConfig.mfaTransactionLifetimeSeconds * 1000,
      requiresAuthTime,
    });

    return reply.redirect(getMfaChallengeTotpPath(transactionId));
  }

  // Create a new pending authorization transaction.
  const transactionId = pendingAuthorizationStore.newPendingAuthorization({
    stage: "login",
    authorizationRequest,
    amr: [],
    mfaFailedAttempts: 0,
    expiresAt: Date.now() + serverConfig.mfaTransactionLifetimeSeconds * 1000,
    requiresAuthTime,
  });

  return reply
    .type("text/html; charset=utf-8")
    .send(
      renderLoginPage(loginEndpointPath, authorizationRequest, transactionId),
    );
}

function hasRequestedLevel2Acr(
  authorizationRequest: AuthorizationRequest,
  issuer: string,
): boolean {
  return hasAcr(authorizationRequest.acrValues, getAcrLevel2(issuer));
}

function userHasRegisteredTotp(user: UserRecord): boolean {
  return (
    user.mfaRegistrations?.some(
      (registration) => registration.type === "TOTP",
    ) ?? false
  );
}

function renderLoginPage(
  loginEndpointPath: string,
  authorizationRequest: AuthorizationRequest,
  transactionId: string,
  errorMessage?: string,
) {
  const escapedErrorMessage = errorMessage
    ? `<p role="alert" style="color: red">${escapeHtml(errorMessage)}</p>`
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
  setIfExists("acrValues", "acr_values");
  if (authorizationRequest.prompt != null) {
    signupPathSearchParams.set("prompt", authorizationRequest.prompt.join(" "));
  }
  const signupPath = `/signup?${signupPathSearchParams.toString()}`;
  const loginActionUrl = new URL(loginEndpointPath, "http://localhost");
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

/**
 * Send a POST error response.
 *
 * Handles this case: If the Redirection URI is invalid, the Authorization Server MUST NOT redirect the User Agent to
 * the invalid Redirection URI.
 */
function sendPostErrorResponse({
  reply,
  error,
  error_description,
}: {
  reply: FastifyReply;
  error: string;
  error_description: string;
}) {
  return reply.code(400).send({
    error,
    error_description,
  });
}

/**
 * Send an error response to the redirect URI.
 *
 * Unless the Redirection URI is invalid, the Authorization Server returns the Client to the
 * Redirection URI specified in the Authorization Request with the appropriate error and state
 * parameters. Other parameters SHOULD NOT be returned.
 */
function sendRedirectErrorResponse({
  reply,
  redirectUri,
  state,
  error,
  error_description,
}: {
  reply: FastifyReply;
  redirectUri: string;
  state?: string;
  error: string;
  error_description: string;
}) {
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("error", error);
  redirectUrl.searchParams.set("error_description", error_description);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }
  reply.redirect(redirectUrl.toString());
  return reply;
}

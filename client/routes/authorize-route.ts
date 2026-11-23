import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";
import { escapeHtml } from "../utils/html-utils.ts";

export function registerAuthorizeRoute(
  fastify: FastifyInstance,
  authFlowContext: AuthFlowContext,
) {
  // OAuth, Authorization Code Grant, Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  // OIDC, Authorization Code Flow, Authentication Request - https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest
  fastify.get<{
    Querystring: {
      scope?: string;
      acr_values?: string;
      resource?: string;
      audience?: string;
      max_age?: string;
      prompt?: "none" | "login" | "consent" | "select_account";
      display?: "page" | "popup" | "touch" | "wap";
      ui_locales?: "en-GB" | "nl-BE" | "fr-BE";
      login_hint?: string;
      use_pkce?: "true" | "false";
      use_state?: "true" | "false";
      use_nonce?: "true" | "false";
      authorize_request_method?: "GET" | "POST";
    };
  }>("/authorize", async function (request, reply) {
    const clientId = process.env.CLIENT_ID!;
    const {
      scope,
      acr_values,
      resource,
      audience,
      max_age,
      prompt,
      display,
      ui_locales,
      login_hint,
      use_pkce,
      use_state,
      use_nonce,
      authorize_request_method,
    } = request.query;
    const authorizeRequestMethod =
      authorize_request_method === "POST" ? "POST" : "GET";

    const authorizeUrl = new URL(authFlowContext.authorizationEndpoint);
    const authorizeParams: Record<string, string> = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: authFlowContext.redirectUri,
    };

    if (use_state === "true") {
      authFlowContext.state = randomUUID();
      authorizeParams.state = authFlowContext.state;
    } else {
      authFlowContext.state = undefined;
    }

    if (use_nonce === "true") {
      // OIDC, ID token - https:openid.net/specs/openid-connect-core-1_0-final.html#IDToken
      authFlowContext.nonce = randomUUID();
      authorizeParams.nonce = authFlowContext.nonce;
    } else {
      authFlowContext.nonce = undefined;
    }

    if (use_pkce === "true") {
      // PKCE, Client Creates a Code Verifier - https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
      authFlowContext.codeVerifier = randomBytes(32).toString("base64url");
      // PKCE, Client Creates a Code Challenge - https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
      authorizeParams.code_challenge_method = "S256";
      authorizeParams.code_challenge = createHash("sha256")
        .update(authFlowContext.codeVerifier)
        .digest("base64url");
    } else {
      authFlowContext.codeVerifier = undefined;
    }

    if (scope) {
      const trimmedScope = scope.trim();
      authorizeParams.scope = trimmedScope;
      authFlowContext.isOidcFlow = trimmedScope.split(/\s+/).includes("openid");
    } else {
      authFlowContext.isOidcFlow = false;
    }
    if (acr_values?.trim()) {
      authorizeParams.acr_values = acr_values.trim();
    }
    if (resource) {
      authorizeParams.resource = resource.trim();
    }
    if (audience) {
      authorizeParams.audience = audience.trim();
    }
    if (max_age) {
      const parsedMaxAge = parseMaxAge(max_age);
      authFlowContext.maxAge = parsedMaxAge;
      authorizeParams.max_age = max_age.trim();
    } else {
      authFlowContext.maxAge = undefined;
    }
    if (prompt) {
      authorizeParams.prompt = prompt;
    }
    if (display) {
      authorizeParams.display = display;
    }
    if (ui_locales) {
      authorizeParams.ui_locales = ui_locales;
    }
    if (login_hint?.trim()) {
      authorizeParams.login_hint = login_hint.trim();
    }

    // If the user wants to use POST to the auth server's /authorize endpoint.
    // We send them back an auto-submitting form with our constructed authorization params.
    if (authorizeRequestMethod === "POST") {
      fastify.log.info(
        {
          authorizeRequestMethod,
          authorizationEndpoint: authorizeUrl,
          ...authorizeParams,
        },
        "/authorize - Authorization Request - POSTing to Authorization URL...",
      );
      return reply
        .type("text/html; charset=utf-8")
        .send(
          renderAuthorizationPostForm(authorizeUrl.toString(), authorizeParams),
        );
    }

    authorizeUrl.search = new URLSearchParams(authorizeParams).toString();
    fastify.log.info(
      {
        authorizeRequestMethod,
        authorizeUrl,
        ...Object.fromEntries(authorizeUrl.searchParams.entries()),
      },
      "/authorize - Authorization Request - redirecting to Authorization URL...",
    );
    return reply.redirect(authorizeUrl.toString());
  });
}

function parseMaxAge(maxAgeValue: string): number | undefined {
  const trimmedValue = maxAgeValue.trim();
  if (trimmedValue.length === 0) {
    return undefined;
  }

  const parsed = Number(trimmedValue);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    return undefined;
  }

  return parsed;
}

function renderAuthorizationPostForm(
  authorizationEndpoint: string,
  authorizationParams: Record<string, string>,
) {
  const hiddenInputs = Object.entries(authorizationParams)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`,
    )
    .join("\n      ");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Submitting authorization request</title>
  </head>
  <body>
    <form method="post" action="${escapeHtml(authorizationEndpoint)}">
      ${hiddenInputs}
      <noscript>
        <button type="submit">Continue</button>
      </noscript>
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>`;
}

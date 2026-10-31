import type { FastifyInstance } from "fastify";
import type { TotpValidator } from "../../otp/time-based-one-time-password.ts";
import type { PendingAuthorizationStore } from "../stores/pending-authorization-store.ts";
import { isUuidV4 } from "../utils/uuid.ts";
import { createAuthorizationRedirectUrl } from "./authorization-route.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { UserStore } from "../stores/user-store.ts";
import type { AuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import type { AuthorizationRequestError } from "../types/authorization-request.ts";

type MfaChallengeQueryParams = {
  tx?: string;
};

export function registerMfaChallengeTotpRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  pendingAuthorizationStore: PendingAuthorizationStore,
  authorizationCodeStore: AuthorizationCodeStore,
  userStore: UserStore,
  totpValidator: TotpValidator,
) {
  fastify.get<{
    Querystring: MfaChallengeQueryParams;
  }>("/mfa-challenge-totp", async function (request, reply) {
    return reply.type("text/html; charset=utf-8").send(renderMfaChallengeTotpPage({tx: request.query.tx}));
  });

  fastify.post<{
    Body: {
      tx?: string;
      code?: string;
    };
  }>("/mfa-challenge-totp", async function (request, reply) {
    const { tx } = request.body;
    if (!isUuidV4(tx)) {
      // TODO: Do proper server response
      throw new Error("Invalid tx ID");
    }

    const authRecord = pendingAuthorizationStore.loadPendingAuthorization(tx);
    if (authRecord == null) {
      // TODO: Do proper server response
      throw new Error("Unknown tx ID");
    }

    const { authorizationRequest, subject } = authRecord;
    const user = userStore.loadUserById(subject);
    if (user == null) {
      // TODO: Do proper server response
      // This could happen if the user was deleted between a successful credential entry and completing MFA.
      throw new Error(`User not found, ID: ${subject}`);
    }

    console.log("TOTP code:", request.body.code);
    const { isValid } = await totpValidator.validate(request.body.code);
    console.log("TOTP code valid:", isValid);

    if (!isValid) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(renderMfaChallengeTotpPage({tx, invalidCode: true}));
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

function renderMfaChallengeTotpPage({
  tx,
  invalidCode = false
}: {
  tx: string;
  invalidCode?: boolean;
}): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>TOTP MFA challenge</title>
  </head>
  <body>
    <h1>TOTP MFA challenge</h1>
    ${invalidCode ? `<div>Invalid code</div>` : ''}
    <form method="post" action="/mfa-challenge-totp">
      <input type="hidden" name="tx" value="${escapeHtml(tx ?? "")}">
      <label>
        Authentication code
        <input type="text" name="code" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" required>
      </label>
      <button type="submit">Submit</button>
    </form>
  </body>
</html>`;
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

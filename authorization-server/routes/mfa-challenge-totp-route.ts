import { type FastifyInstance } from "fastify";
import {
  createTimeBasedOneTimePasswordValidator,
  type TotpValidator,
} from "../../otp/time-based-one-time-password.ts";
import type {
  PendingAuthorizationRecord,
  PendingAuthorizationStore,
} from "../stores/pending-authorization-store.ts";
import { isUuidV4 } from "../utils/uuid.ts";
import { createAuthorizationRedirectUrl } from "./authorization-route.ts";
import { type ServerConfig } from "../config/server-config.ts";
import type {
  MfaRegistration,
  UserRecord,
  UserStore,
} from "../stores/user-store.ts";
import type { AuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import { fromBase32 } from "../../util/base-encoding.ts";
import { totpConfig } from "../config/totp-config.ts";

type MfaChallengeQueryParams = {
  tx?: string;
};

export function registerMfaChallengeTotpRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  pendingAuthorizationStore: PendingAuthorizationStore,
  authorizationCodeStore: AuthorizationCodeStore,
  userStore: UserStore,
  /** Function to create a TOTP validator. Mainly exposed for overwriting for test convenience. */
  createTotpValidator: (
    registration: MfaRegistration,
  ) => TotpValidator = createDefaultTotpValidator,
) {
  const userIdToValidator: Record<string, TotpValidator> = {};
  function getUserValidator(user: UserRecord): TotpValidator | undefined {
    if (userIdToValidator[user.userId]) {
      return userIdToValidator[user.userId];
    }

    const totpMfaReg = user.mfaRegistrations?.find(
      (reg) => reg.type === "TOTP",
    );
    if (!totpMfaReg) {
      return undefined;
    }
    const totpValidator = createTotpValidator(totpMfaReg);
    userIdToValidator[user.userId] = totpValidator;
    return totpValidator;
  }

  fastify.get<{
    Querystring: MfaChallengeQueryParams;
  }>("/mfa-challenge-totp", async function (request, reply) {
    // Ensure transaction ID is not leaked.
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
    const { tx } = request.query;
    const validationResult = validateMfaChallengeTransaction(
      tx,
      pendingAuthorizationStore,
    );
    if (validationResult.ok === false) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderMfaChallengeTotpPage({
            errorText: validationResult.errorText,
          }),
        );
    }

    return reply
      .type("text/html; charset=utf-8")
      .send(renderMfaChallengeTotpPage({ tx }));
  });

  fastify.post<{
    Querystring: MfaChallengeQueryParams;
    Body: {
      code?: string;
    };
  }>("/mfa-challenge-totp", async function (request, reply) {
    // Ensure transaction ID is not leaked.
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
    const { tx } = request.query;
    const validationResult = validateMfaChallengeTransaction(
      tx,
      pendingAuthorizationStore,
    );
    if (validationResult.ok === false) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderMfaChallengeTotpPage({
            errorText: validationResult.errorText,
          }),
        );
    }

    const { authorizationRequest, subject } =
      validationResult.pendingAuthorization;
    const user = userStore.loadUserById(subject);
    if (user == null) {
      // This could happen if the user was deleted between a successful credential entry and completing MFA.
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderMfaChallengeTotpPage({
            tx,
            errorText: "User no longer exists",
          }),
        );
    }

    // Get the TOTP validator for this user.
    const totpValidator = getUserValidator(user);
    if (totpValidator == null) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderMfaChallengeTotpPage({
            tx,
            errorText:
              "User is not registered for TOTP multi-factor authentication",
          }),
        );
    }

    // Validate the given code.
    const { isValid } = await totpValidator.validate(request.body.code);

    if (!isValid) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(renderMfaChallengeTotpPage({ tx, errorText: "Invalid code" }));
    }

    // Multiple requests may pass validation concurrently, so only the request
    // that successfully consumes the transaction may complete authorization.
    const deleted = pendingAuthorizationStore.deletePendingAuthorization(tx);
    if (!deleted) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderMfaChallengeTotpPage({
            tx,
            errorText:
              "Login transaction has already been completed or expired.",
          }),
        );
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

type MfaChallengeTotpValidationResult =
  | {
      ok: true;
      pendingAuthorization: PendingAuthorizationRecord;
    }
  | {
      ok: false;
      errorText: string;
    };

function validateMfaChallengeTransaction(
  tx: string | undefined,
  pendingAuthorizationStore: PendingAuthorizationStore,
): MfaChallengeTotpValidationResult {
  if (!isUuidV4(tx)) {
    return {
      ok: false,
      errorText:
        "Login transaction ID not valid, please start your login again.",
    };
  }

  const pendingAuthorization =
    pendingAuthorizationStore.loadPendingAuthorization(tx);
  if (pendingAuthorization == null) {
    return {
      ok: false,
      errorText: "Login transaction not found, please start your login again.",
    };
  }

  return {
    ok: true,
    pendingAuthorization,
  };
}

function renderMfaChallengeTotpPage({
  tx,
  errorText,
}: {
  tx?: string;
  errorText?: string;
}): string {
  const action = tx
    ? `/mfa-challenge-totp?tx=${escapeHtml(encodeURIComponent(tx))}`
    : "/mfa-challenge-totp";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>TOTP MFA challenge</title>
  </head>
  <body>
    <h1>TOTP MFA challenge</h1>
    ${errorText ? `<div role="alert" style="color: red">${errorText}</div>` : ""}
    <form method="post" action="${action}">
      <label>
        Authentication code
        <input type="text" name="code" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" required>
      </label>
      <button type="submit">Submit</button>
    </form>
  </body>
</html>`;
}

function createDefaultTotpValidator(
  registration: MfaRegistration,
): TotpValidator {
  return createTimeBasedOneTimePasswordValidator({
    key: fromBase32(registration.secretBase32),
    codeType: "numeric", // otpauth:// URLs don't support providing alphanumeric as a type
    hashAlgorithm: totpConfig.algorithm,
    codeLength: totpConfig.digits,
    timeStepSeconds: totpConfig.period,
    allowedTimeSteps: totpConfig.allowedTimeSteps,
  });
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

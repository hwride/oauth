import { randomUUID } from "node:crypto";
import {
  getResourceConfig,
  type SupportedResource,
} from "../config/resources-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { AuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import type { UserRecord } from "../stores/user-store.ts";
import type { AuthorizationRequest } from "../types/authorization-request.ts";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import { getAllowedScopesForUser } from "./rbac-utils.ts";

/** These are scopes that are always allowed. */
const unrestrictedScopes = new Set([
  "openid",
  "profile",
  "email",
  "address",
  "phone",
  "offline_access",
]);

/**
 * Create an authorization code and redirect URL after successful authentication.
 *
 * Also filters requested scopes against the user record and any requested resource's allowed scopes before saving the
 * authorization code.
 *
 * See Redirection Endpoint https://www.rfc-editor.org/info/rfc6749/#section-3.1.2
 */
export function issueAuthorizationCodeAndRedirect(
  serverConfig: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore,
  authorizationRequest: AuthorizationRequest,
  user: UserRecord,
  amr: AuthenticationMethodReference[],
) {
  const code = randomUUID();
  authorizationCodeStore.saveAuthorizationCode(code, {
    clientId: authorizationRequest.clientId,
    subject: user.userId,
    amr,
    redirectUri: authorizationRequest.redirectUri,
    // Filter scopes at authorization-code issuance flows use the user record available at the end of authentication.
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

/**
 * Filter the scopes allowed for this authorization request.
 */
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

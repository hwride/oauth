import type { UserRecord } from "../stores/user-store.ts";
import { hasScope, parseScopeStr } from "./oauth-utils.ts";

export const openidScope = "openid" as const;
export const oidcStandardClaimScopes = [
  "profile",
  "email",
  "address",
  "phone",
] as const;
export const oidcScopes = [openidScope, ...oidcStandardClaimScopes] as const;
export type OidcScope = (typeof oidcScopes)[number];
type OidcStandardClaimScope = (typeof oidcStandardClaimScopes)[number];

export const oidcStandardClaims = [
  "name",
  "family_name",
  "given_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "email",
  "email_verified",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "phone_number",
  "phone_number_verified",
  "address",
  "updated_at",
] as const satisfies readonly (keyof UserRecord)[];
export type OidcStandardClaim = (typeof oidcStandardClaims)[number];

export const oidcClaimsByScope: Record<
  OidcStandardClaimScope,
  OidcStandardClaim[]
> = {
  profile: [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
  ],
  email: ["email", "email_verified"],
  address: ["address"],
  phone: ["phone_number", "phone_number_verified"],
};

/**
 * Get the claims that should be returned for this user given an OAuth scope string.
 *
 * @returns An object of claim key/values.
 */
export function getUserClaims(
  user: UserRecord,
  scope: unknown,
): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  const scopes = parseScopeStr(scope);

  for (const oidcScope of oidcStandardClaimScopes) {
    // If an OIDC scope was requested.
    if (scopes.has(oidcScope)) {
      // Check each claim that scope provides, and copy it if the user has a value for that claim.
      for (const claimName of oidcClaimsByScope[oidcScope]) {
        const claimValue = user[claimName];
        if (claimValue !== undefined) {
          claims[claimName] = claimValue;
        }
      }
    }
  }

  return claims;
}

export function hasOpenIdScope(scope: string | undefined) {
  return hasScope(scope, openidScope);
}

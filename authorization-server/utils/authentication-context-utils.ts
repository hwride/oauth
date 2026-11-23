import type { AuthenticationContextClassReference } from "../types/authentication-context-class-reference.ts";

export function getAcrLevel2(
  issuer: string,
): AuthenticationContextClassReference {
  return `${new URL(issuer).origin}/acr/level-2`;
}

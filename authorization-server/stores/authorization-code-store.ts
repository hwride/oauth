import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";

export type AuthorizationCodeRecord = {
  clientId: string;
  subject: string;
  /** When the user authenticated. Unix time in ms */
  authTime: number;
  /** Whether auth_time is a required claim on the token response. */
  requiresAuthTime: boolean;
  amr: AuthenticationMethodReference[];
  redirectUri: string;
  scope?: string;
  nonce?: string;
  resource?: string;
  /** Unix time in ms */
  expiresAt: number;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
};

export type AuthorizationCodeStore = {
  saveAuthorizationCode(code: string, record: AuthorizationCodeRecord): void;
  loadAuthorizationCode(
    code: string | null | undefined,
  ): AuthorizationCodeRecord | undefined;
  hasAuthorizationCode(code: string | null | undefined): boolean;
  deleteAuthorizationCode(code: string | null | undefined): boolean;
  isEmpty(): boolean;
};

export function createAuthorizationCodeStore(): AuthorizationCodeStore {
  const authorizationCodes = new Map<string, AuthorizationCodeRecord>();

  return {
    saveAuthorizationCode(code, record) {
      authorizationCodes.set(code, record);
    },
    loadAuthorizationCode(code) {
      if (code == null) {
        return undefined;
      }
      return authorizationCodes.get(code);
    },
    hasAuthorizationCode(code) {
      if (code == null) {
        return false;
      }
      return authorizationCodes.has(code);
    },
    deleteAuthorizationCode(code) {
      if (code == null) {
        return false;
      }
      return authorizationCodes.delete(code);
    },
    isEmpty() {
      return authorizationCodes.size === 0;
    },
  };
}

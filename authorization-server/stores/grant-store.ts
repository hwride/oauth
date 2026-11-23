import { createHash, randomUUID } from "node:crypto";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import type { AuthenticationContextClassReference } from "../types/authentication-context-class-reference.ts";

export type GrantState = "pending" | "active" | "revoked";

/**
 * Represents what a user granted after a successful authorization request.
 */
export type Grant = {
  grantId: string;
  state: GrantState;
  authorizationCode: {
    hash: string;
    record: AuthorizationCodeRecord;
    usedAt?: number;
  };
  accessTokens: Set<string>;
  refreshToken?: string;
};

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

export type AccessTokenRecord =
  | {
      type: "jwt";
    }
  | {
      type: "opaque";
      clientId: string;
      scope?: string;
      amr?: AuthenticationMethodReference[];
      acr?: AuthenticationContextClassReference;
      /** Unix time in seconds (not ms) */
      authTime?: number;
    };

export type RefreshTokenRecord = {
  clientId: string;
  resource?: string;
  scope?: string;
  subject: string;
  amr?: AuthenticationMethodReference[];
  /** When the user authenticated. Unix time in ms */
  authTime: number;
  /** Whether auth_time is a required claim on the token response. */
  requiresAuthTime: boolean;
  /** Unix time in ms */
  expiresAt: number;
};

export type StoredAuthorizationCodeRecord = AuthorizationCodeRecord & {
  grantId: string;
};

export type StoredRefreshTokenRecord = RefreshTokenRecord & {
  grantId: string;
};

export type GrantStore = {
  createAuthorizationCodeGrant(
    authorizationCode: string,
    record: AuthorizationCodeRecord,
  ): string;
  loadAuthorizationCode(
    code: string | null | undefined,
  ): StoredAuthorizationCodeRecord | undefined;
  hasAuthorizationCode(code: string | null | undefined): boolean;
  consumeAuthorizationCode(
    code: string | null | undefined,
  ): StoredAuthorizationCodeRecord | undefined;

  saveAccessToken(
    token: string,
    grantId: string,
    record: AccessTokenRecord,
  ): void;
  loadAccessToken(
    token: string | null | undefined,
  ): AccessTokenRecord | undefined;
  deleteAccessToken(token: string | null | undefined): boolean;

  generateRefreshToken(
    grantId: string,
    record: Omit<RefreshTokenRecord, "expiresAt">,
    refreshTokenLifetimeSeconds: number,
  ): string;
  hasRefreshToken(token: string): boolean;
  getRefreshToken(token: string): StoredRefreshTokenRecord | undefined;
  deleteRefreshToken(token: string): boolean;

  getGrant(grantId: string): Grant | undefined;
  getGrantByAuthorizationCode(
    code: string | null | undefined,
  ): Grant | undefined;
  revokeGrant(grantId: string): boolean;
};

export function createGrantStore(): GrantStore {
  const grants = new Map<string, Grant>();
  const authorizationCodeGrants = new Map<string, string>();
  const accessTokens = new Map<
    string,
    { grantId: string; record: AccessTokenRecord }
  >();
  const refreshTokens = new Map<string, StoredRefreshTokenRecord>();

  return {
    createAuthorizationCodeGrant(authorizationCode, record) {
      const grantId = randomUUID();
      const authorizationCodeHash = hashToken(authorizationCode);
      grants.set(grantId, {
        grantId,
        state: "pending",
        authorizationCode: {
          hash: authorizationCodeHash,
          record,
        },
        accessTokens: new Set(),
      });
      authorizationCodeGrants.set(authorizationCodeHash, grantId);
      return grantId;
    },

    loadAuthorizationCode(code) {
      if (code == null) {
        return undefined;
      }
      const grant = getGrantByAuthorizationCodeValue(
        grants,
        authorizationCodeGrants,
        code,
      );
      if (
        grant == null ||
        grant.state === "revoked" ||
        grant.authorizationCode.usedAt != null
      ) {
        return undefined;
      }
      return {
        ...grant.authorizationCode.record,
        grantId: grant.grantId,
      };
    },

    hasAuthorizationCode(code) {
      return this.loadAuthorizationCode(code) != null;
    },

    consumeAuthorizationCode(code) {
      if (code == null) {
        return undefined;
      }
      const grant = getGrantByAuthorizationCodeValue(
        grants,
        authorizationCodeGrants,
        code,
      );
      if (
        grant == null ||
        grant.state === "revoked" ||
        grant.authorizationCode.usedAt != null
      ) {
        return undefined;
      }
      const record = {
        ...grant.authorizationCode.record,
        grantId: grant.grantId,
      };
      grant.authorizationCode.usedAt = Date.now();
      return record;
    },

    saveAccessToken(token, grantId, record) {
      const grant = assertGrantExists(grants, grantId);
      accessTokens.set(token, { grantId, record });
      grant.accessTokens.add(token);
      grant.state = "active";
    },

    loadAccessToken(token) {
      if (token == null) {
        return undefined;
      }
      return accessTokens.get(token)?.record;
    },

    deleteAccessToken(token) {
      if (token == null) {
        return false;
      }
      const storedToken = accessTokens.get(token);
      if (storedToken == null) {
        return false;
      }
      accessTokens.delete(token);
      grants.get(storedToken.grantId)?.accessTokens.delete(token);
      return true;
    },

    generateRefreshToken(grantId, record, refreshTokenLifetimeSeconds) {
      const grant = assertGrantExists(grants, grantId);
      const refreshToken = randomUUID();
      refreshTokens.set(refreshToken, {
        ...record,
        grantId,
        expiresAt: Date.now() + refreshTokenLifetimeSeconds * 1000,
      });
      grant.refreshToken = refreshToken;
      grant.state = "active";
      return refreshToken;
    },

    hasRefreshToken(token) {
      return refreshTokens.has(token);
    },

    getRefreshToken(token) {
      return refreshTokens.get(token);
    },

    deleteRefreshToken(token) {
      const storedToken = refreshTokens.get(token);
      if (storedToken == null) {
        return false;
      }
      refreshTokens.delete(token);
      const grant = grants.get(storedToken.grantId);
      if (grant?.refreshToken === token) {
        grant.refreshToken = undefined;
      }
      return true;
    },

    getGrant(grantId) {
      return grants.get(grantId);
    },

    getGrantByAuthorizationCode(code) {
      if (code == null) {
        return undefined;
      }
      return getGrantByAuthorizationCodeValue(
        grants,
        authorizationCodeGrants,
        code,
      );
    },

    revokeGrant(grantId) {
      // We keep grants even after revocation so we can detect auth code re-use.
      // Later we might want to consider removing grants, but keeping only auth codes.
      // Or adding a reasonable max lifetime to auth code re-use detection.
      const grant = grants.get(grantId);
      if (grant == null) {
        return false;
      }

      grant.state = "revoked";
      for (const accessToken of grant.accessTokens) {
        accessTokens.delete(accessToken);
      }
      if (grant.refreshToken != null) {
        refreshTokens.delete(grant.refreshToken);
      }
      grant.accessTokens.clear();
      grant.refreshToken = undefined;
      return true;
    },
  };
}

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("base64url");
}

function getGrantByAuthorizationCodeValue(
  grants: Map<string, Grant>,
  authorizationCodeGrants: Map<string, string>,
  code: string,
) {
  const grantId = authorizationCodeGrants.get(hashToken(code));
  return grantId == null ? undefined : grants.get(grantId);
}

function assertGrantExists(grants: Map<string, Grant>, grantId: string) {
  const grant = grants.get(grantId);
  if (grant == null) {
    throw new Error(`Unknown grant: ${grantId}`);
  }
  return grant;
}

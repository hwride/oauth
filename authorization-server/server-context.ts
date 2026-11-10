import { getServerConfig, type ServerConfig } from "./config/server-config.ts";
import { defaultUsers } from "./default-users.ts";
import {
  createPendingAuthorizationStore,
  type PendingAuthorizationStore,
} from "./stores/pending-authorization-store.ts";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "./stores/authorization-code-store.ts";
import { createTokenStore, type TokenStore } from "./stores/token-store.ts";
import { createUserStore, type UserStore } from "./stores/user-store.ts";
import {
  createRefreshTokenStore,
  type RefreshTokenStore,
} from "./stores/refresh-token-store.ts";
import {
  createSessionStore,
  type SessionStore,
} from "./stores/session-store.ts";

export type ServerContext = {
  serverConfig: ServerConfig;
  pendingAuthorizationStore: PendingAuthorizationStore;
  authorizationCodeStore: AuthorizationCodeStore;
  sessionStore: SessionStore;
  tokenStore: TokenStore;
  userStore: UserStore;
  refreshTokenStore: RefreshTokenStore;
};

export async function createServerContext(
  overrides: Partial<ServerContext> = {},
): Promise<ServerContext> {
  const serverConfig = overrides.serverConfig ?? (await getServerConfig());

  return {
    serverConfig,
    pendingAuthorizationStore:
      overrides.pendingAuthorizationStore ?? createPendingAuthorizationStore(),
    authorizationCodeStore:
      overrides.authorizationCodeStore ?? createAuthorizationCodeStore(),
    sessionStore:
      overrides.sessionStore ??
      createSessionStore({
        sessionLengthSeconds: serverConfig.sessionLengthSeconds,
      }),
    tokenStore: overrides.tokenStore ?? createTokenStore(),
    userStore: overrides.userStore ?? createUserStore(defaultUsers()),
    refreshTokenStore: overrides.refreshTokenStore ?? createRefreshTokenStore(),
  };
}

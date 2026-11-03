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

export type ServerContext = {
  serverConfig: ServerConfig;
  pendingAuthorizationStore: PendingAuthorizationStore;
  authorizationCodeStore: AuthorizationCodeStore;
  tokenStore: TokenStore;
  userStore: UserStore;
  refreshTokenStore: RefreshTokenStore;
};

export async function createServerContext({
  serverConfig,
  pendingAuthorizationStore = createPendingAuthorizationStore(),
  authorizationCodeStore = createAuthorizationCodeStore(),
  tokenStore = createTokenStore(),
  userStore = createUserStore(defaultUsers()),
  refreshTokenStore = createRefreshTokenStore(),
}: Partial<ServerContext> = {}): Promise<ServerContext> {
  return {
    serverConfig: serverConfig ?? (await getServerConfig()),
    pendingAuthorizationStore,
    authorizationCodeStore,
    tokenStore,
    userStore,
    refreshTokenStore,
  };
}

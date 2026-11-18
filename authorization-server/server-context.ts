import { getServerConfig, type ServerConfig } from "./config/server-config.ts";
import { defaultUsers } from "./default-users.ts";
import {
  createPendingAuthorizationStore,
  type PendingAuthorizationStore,
} from "./stores/pending-authorization-store.ts";
import { createGrantStore, type GrantStore } from "./stores/grant-store.ts";
import { createUserStore, type UserStore } from "./stores/user-store.ts";
import {
  createSessionStore,
  type SessionStore,
} from "./stores/session-store.ts";

export type ServerContext = {
  serverConfig: ServerConfig;
  pendingAuthorizationStore: PendingAuthorizationStore;
  grantStore: GrantStore;
  sessionStore: SessionStore;
  userStore: UserStore;
};

export async function createServerContext(
  overrides: Partial<ServerContext> = {},
): Promise<ServerContext> {
  const serverConfig = overrides.serverConfig ?? (await getServerConfig());

  return {
    serverConfig,
    pendingAuthorizationStore:
      overrides.pendingAuthorizationStore ?? createPendingAuthorizationStore(),
    grantStore: overrides.grantStore ?? createGrantStore(),
    sessionStore:
      overrides.sessionStore ??
      createSessionStore({
        sessionLengthSeconds: serverConfig.sessionLengthSeconds,
      }),
    userStore: overrides.userStore ?? createUserStore(defaultUsers()),
  };
}

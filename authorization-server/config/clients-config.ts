export type ClientConfig = {
  clientId: string;
  redirectUris: string[];
  accessTokenType: "opaque" | "jwt";
  accessTokenLifetimeSeconds: number;
  idTokenLifetimeSeconds: number;
  refreshTokenLifetimeSeconds: number;
} & ClientConfigAuth;

type ClientConfigAuth =
  | {
      /**
       * How the client will authenticate with the authorization server.
       * - client_secret_basic: using Basic authentication. For confidential clients.
       * - none: no authentication required. For public clients.
       */
      clientAuthMethod: "client_secret_basic";
      clientSecret: string;
    }
  | {
      /**
       * How the client will authenticate with the authorization server.
       * - client_secret_basic: using Basic authentication. For confidential clients.
       * - none: no authentication required. For public clients.
       */
      clientAuthMethod: "none";
    };

const accessTokenLifetimeSeconds = 60 * 60;
const idTokenLifetimeSeconds = 60 * 60;
const refreshTokenLifetimeSeconds = 60 * 60 * 24 * 2;
const defaultClientBase = "http://localhost:3000";

export const clientsConfig: ClientConfig[] = [
  {
    clientId: "client-id-opaque",
    clientAuthMethod: "client_secret_basic",
    clientSecret: "test-client-secret",
    redirectUris: [
      new URL(
        "/callback",
        process.env.CLIENT_OPAQUE_BASE ?? defaultClientBase,
      ).toString(),
    ],
    accessTokenType: "opaque",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  },
  {
    clientId: "client-id-jwt",
    clientAuthMethod: "client_secret_basic",
    clientSecret: "other-test-client-secret",
    redirectUris: [
      new URL(
        "/callback",
        process.env.CLIENT_JWT_BASE ?? defaultClientBase,
      ).toString(),
    ],
    accessTokenType: "jwt",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  },
  {
    clientId: "client-id-public",
    clientAuthMethod: "none",
    redirectUris: [
      new URL(
        "/callback",
        process.env.CLIENT_PUBLIC_BASE ?? defaultClientBase,
      ).toString(),
    ],
    accessTokenType: "jwt",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  },
];

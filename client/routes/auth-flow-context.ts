export type AuthFlowContext = {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  maxAge?: number;
  isOidcFlow?: boolean;
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  authServerBaseUrl: string;
  issuer: string;
  discoveryUrl?: string;
  redirectUri: string;
  authorizationEndpoint: string;
  jwksUri: string;
  tokenEndpoint: string;
};

export type ClientAuthMethod =
  | "client_secret_basic"
  | "client_secret_post"
  | "none";

export function parseClientAuthMethod(
  value: string | undefined,
): ClientAuthMethod {
  switch (value) {
    case "client_secret_post":
      return "client_secret_post";
    case "none":
      return "none";
    default:
      return "client_secret_basic";
  }
}

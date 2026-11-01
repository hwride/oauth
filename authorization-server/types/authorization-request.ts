import type { SupportedResource } from "../config/resources-config.ts";

export type AuthorizationRequest = {
  clientId: string;
  redirectUri: string;
  responseType: string;
  scope?: string;
  nonce?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
  resource?: SupportedResource;
};

export type AuthorizationRequestError = {
  statusCode: number;
  error: { error: string; error_description?: string };
};

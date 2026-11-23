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
  /** Maximum elapsed time in seconds since the End-User's last active authentication. */
  maxAge?: number;
  /** Space-separated authentication context class references requested by the client. */
  acrValues?: string;
  /** Specifies whether the Authorization Server prompts the End-User for reauthentication and consent. */
  prompt?: Prompt[];
};

export const prompts = ["none", "login", "consent", "select_account"] as const;
export type Prompt = (typeof prompts)[number];

export type AuthorizationRequestError = {
  statusCode: number;
  error: { error: string; error_description?: string };
};

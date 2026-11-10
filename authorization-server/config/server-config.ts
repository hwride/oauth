import { generateKeyPair } from "jose";
import type { GenerateKeyPairResult } from "jose/key/generate/keypair";

export type ServerConfig = {
  jwtSigningAlg: "RS256";
  signingKey: KeyConfig;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  userInfoUri: string;
  mfaTransactionLifetimeSeconds: number;
  mfaMaxAttempts: number;
  authorizationCodeLifetimeSeconds: number;
  /** Length of the auth server session. */
  sessionLengthSeconds: number;
};

export type KeyConfig = {
  kid: string;
  publicKey: GenerateKeyPairResult["publicKey"];
  privateKey: GenerateKeyPairResult["privateKey"];
};

export async function getServerConfig(): Promise<ServerConfig> {
  const issuerEnvVar = process.env.ISSUER;
  if (!issuerEnvVar) {
    throw new Error("Missing ISSUER");
  }

  const issuer = validateIssuer(issuerEnvVar);
  const jwtSigningAlg = "RS256";
  const { publicKey, privateKey } = await generateKeyPair(jwtSigningAlg);

  return {
    jwtSigningAlg,
    signingKey: {
      kid: "1",
      publicKey,
      privateKey,
    },
    issuer,
    authorizationEndpoint:
      process.env.AUTHORIZATION_ENDPOINT ?? `${issuer}/authorize`,
    tokenEndpoint: process.env.TOKEN_ENDPOINT ?? `${issuer}/token`,
    jwksUri: process.env.JWKS_URI ?? `${issuer}/.well-known/jwks.json`,
    userInfoUri: process.env.USER_INFO_URI ?? `${issuer}/userinfo`,
    mfaTransactionLifetimeSeconds: 60 * 10,
    mfaMaxAttempts: 5,
    authorizationCodeLifetimeSeconds: 60 * 10,
    sessionLengthSeconds: 60 * 2,
  };
}

function validateIssuer(issuer: string) {
  const issuerUrl = new URL(issuer);
  if (issuerUrl.search || issuerUrl.hash) {
    throw new Error("ISSUER must not include a query string or fragment");
  }

  return issuer;
}

import type { ServerContext } from "../server-context.ts";
import type { FastifyInstance } from "fastify";

export function registerOpenIdConfigurationRoute(
  fastify: FastifyInstance,
  { serverConfig }: ServerContext,
) {
  // OAuth 2.0 Authorization Server Metadata
  // https://datatracker.ietf.org/doc/html/rfc8414
  // OpenID Connect Discovery 1.0, Section 4.1 (OpenID Provider Configuration Request):
  // https://openid.net/specs/openid-connect-discovery-1_0.html
  fastify.get("/.well-known/openid-configuration", async function (_, reply) {
    return reply.send({
      issuer: serverConfig.issuer,
      authorization_endpoint: serverConfig.authorizationEndpoint,
      token_endpoint: serverConfig.tokenEndpoint,
      jwks_uri: serverConfig.jwksUri,
      userinfo_endpoint: serverConfig.userInfoUri,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256", "plain"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: [serverConfig.jwtSigningAlg],
      userinfo_signing_alg_values_supported: ["none"], // We currently only return plain JSON from /userinfo
      claims_supported: [
        // Shared
        "iss",
        "aud",
        "sub", // Included on ID token and /userinfo endpoint
        "name", // Included on ID token and /userinfo endpoint
        "iat",
        "exp",
        "jti",
        // ID token only
        "amr",
        "nonce",
        // JWT access token only
        "client_id",
        "scope",
      ],
      // Note at the moment we only advertise the OpenID Connect scopes, not any of our custom ones like orders:read.
      scopes_supported: ["openid", "profile", "offline_access"],
    });
  });
}

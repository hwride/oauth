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
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256", "plain"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: [serverConfig.jwtSigningAlg],
    });
  });
}

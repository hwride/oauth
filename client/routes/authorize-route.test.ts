import assert from "node:assert/strict";
import test from "node:test";
import Fastify from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";
import { registerAuthorizeRoute } from "./authorize-route.ts";

const authFlowContext: AuthFlowContext = {
  authServerBaseUrl: "https://issuer.example.test",
  issuer: "https://issuer.example.test",
  redirectUri: "http://localhost:3000/callback",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
};

test("GET /authorize forwards acr_values to the authorization endpoint", async () => {
  const fastify = Fastify();
  const originalClientId = process.env.CLIENT_ID;
  process.env.CLIENT_ID = "client-id";
  registerAuthorizeRoute(fastify, { ...authFlowContext });

  try {
    const response = await fastify.inject({
      method: "GET",
      url: "/authorize?scope=openid&acr_values=%20https%3A%2F%2Fissuer.example.test%2Facr%2Flevel-2%20",
    });

    assert.equal(response.statusCode, 302);
    const location = new URL(response.headers.location!);
    assert.equal(
      location.searchParams.get("acr_values"),
      "https://issuer.example.test/acr/level-2",
    );
  } finally {
    await fastify.close();
    if (originalClientId === undefined) {
      delete process.env.CLIENT_ID;
    } else {
      process.env.CLIENT_ID = originalClientId;
    }
  }
});

test("POST /authorize includes acr_values in the authorization form", async () => {
  const fastify = Fastify();
  const originalClientId = process.env.CLIENT_ID;
  process.env.CLIENT_ID = "client-id";
  registerAuthorizeRoute(fastify, { ...authFlowContext });

  try {
    const response = await fastify.inject({
      method: "GET",
      url: "/authorize?scope=openid&acr_values=https%3A%2F%2Fissuer.example.test%2Facr%2Flevel-2&authorize_request_method=POST",
    });

    assert.equal(response.statusCode, 200);
    assert.match(
      response.body,
      /name="acr_values" value="https:\/\/issuer\.example\.test\/acr\/level-2"/,
    );
  } finally {
    await fastify.close();
    if (originalClientId === undefined) {
      delete process.env.CLIENT_ID;
    } else {
      process.env.CLIENT_ID = originalClientId;
    }
  }
});

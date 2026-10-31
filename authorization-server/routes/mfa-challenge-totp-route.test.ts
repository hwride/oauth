import assert from "node:assert/strict";
import test from "node:test";
import formbody from "@fastify/formbody";
import Fastify from "fastify";
import { registerMfaChallengeTotpRoute } from "./mfa-challenge-totp-route.ts";

test("GET TOTP MFA challenge route renders an OTP form", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  registerMfaChallengeTotpRoute(fastify);

  try {
    const response = await fastify.inject({
      method: "GET",
      url: "/mfa-challenge-totp?tx=transaction-123",
    });

    assert.equal(response.statusCode, 200);
    assert.match(response.headers["content-type"] ?? "", /^text\/html/);
    assert.match(response.body, /<title>TOTP MFA challenge<\/title>/);
    assert.match(
      response.body,
      /<form method="post" action="\/mfa-challenge-totp">/,
    );
    assert.match(
      response.body,
      /name="code" autocomplete="one-time-code"[^>]*pattern="\[0-9\]\{6\}"/,
    );
    assert.match(response.body, /name="tx" value="transaction-123"/);
  } finally {
    await fastify.close();
  }
});

test("POST TOTP MFA challenge route accepts an OTP code", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  registerMfaChallengeTotpRoute(fastify);

  try {
    const response = await fastify.inject({
      method: "POST",
      url: "/mfa-challenge-totp",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: "tx=transaction-123&code=123456",
    });

    assert.equal(response.statusCode, 200);
  } finally {
    await fastify.close();
  }
});

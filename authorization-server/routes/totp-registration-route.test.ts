import assert from "node:assert/strict";
import test from "node:test";
import Fastify from "fastify";
import { getTestServerContext } from "../test/test-utils.ts";
import { registerTotpRegistrationRoute } from "./totp-registration-route.ts";

test("TOTP registration route renders a stable development QR code", async () => {
  const fastify = Fastify();
  registerTotpRegistrationRoute(fastify, await getTestServerContext());

  try {
    const response = await fastify.inject({
      method: "GET",
      url: "/dev/totp-registration",
    });

    assert.equal(response.statusCode, 200);
    assert.match(response.headers["content-type"] ?? "", /^text\/html/);
    assert.match(response.body, /<svg[^>]*width="240"[^>]*height="240"/);
    assert.match(response.body, /otpauth:\/\/totp\/OAuth%20Dev%3Aadmin/);
    assert.match(response.body, /issuer=issuer\.example\.test/);
  } finally {
    await fastify.close();
  }
});

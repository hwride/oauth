import { getTestServerContext } from "../test/test-utils.ts";
import assert from "node:assert/strict";
import test from "node:test";
import formbody from "@fastify/formbody";
import Fastify, { type FastifyInstance } from "fastify";
import { testUserId, defaultUsers } from "../default-users.ts";
import { createAuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import { createPendingAuthorizationStore } from "../stores/pending-authorization-store.ts";
import { createSessionStore } from "../stores/session-store.ts";
import { createUserStore } from "../stores/user-store.ts";
import { getTestServerConfig } from "../test/test-utils.ts";
import { isUuidV4 } from "../utils/uuid.ts";
import { registerMfaChallengeTotpRoute } from "./mfa-challenge-totp-route.ts";

let transactionId: string;

test("GET TOTP MFA challenge route renders an OTP form", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await fastify.inject({
      method: "GET",
      url: `/mfa-challenge-totp?tx=${transactionId}`,
    });

    assert.equal(response.statusCode, 200);
    assert.match(response.headers["content-type"] ?? "", /^text\/html/);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.headers["referrer-policy"], "no-referrer");
    assert.match(response.body, /<title>TOTP MFA challenge<\/title>/);
    assert.match(
      response.body,
      new RegExp(
        `<form method="post" action="/mfa-challenge-totp\\?tx=${transactionId}">`,
      ),
    );
    assert.match(
      response.body,
      /name="code" autocomplete="one-time-code"[^>]*pattern="\[0-9\]\{6\}"/,
    );
    assert.doesNotMatch(response.body, /name="tx"/);
  } finally {
    await fastify.close();
  }
});

test("GET TOTP MFA challenge route does not echo an invalid transaction ID", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await fastify.inject({
      method: "GET",
      url: `/mfa-challenge-totp?tx=${encodeURIComponent('" onmouseover="alert(1)')}`,
    });

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /Login transaction ID not valid/);
    assert.doesNotMatch(response.body, /onmouseover/);
    assert.match(
      response.body,
      /<form method="post" action="\/mfa-challenge-totp">/,
    );
  } finally {
    await fastify.close();
  }
});

test("POST TOTP MFA challenge route accepts an OTP code", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const beforeSubmit = Date.now();
    const response = await submitCode(fastify, transactionId, "123456");

    assert.equal(response.statusCode, 302);

    // Check session cookie is set correctly.
    const sessionCookie = response.headers["set-cookie"] as string;
    assert.ok(sessionCookie);
    const sessionCookieMatch = sessionCookie.match(
      /__Host-Http-session-id=(?<sessionId>[^;]+); HttpOnly; Secure; SameSite=Lax; Path=\/; Max-Age=600/,
    );
    const sessionId = sessionCookieMatch?.groups?.sessionId;
    assert.ok(sessionCookieMatch, "session cookie should match");
    assert.ok(isUuidV4(sessionId), "cookie should have a UUIDv4 session ID");

    const session = routeDependencies.sessionStore.loadSession(sessionId);
    assert.ok(session);
    assert.equal(session.userId, testUserId);
    assert.deepEqual(session.amr, ["pwd", "otp", "mfa"]);
    assert.ok(session.authTime >= beforeSubmit);
    assert.ok(session.authTime <= Date.now());

    const authorizationCode = new URL(
      response.headers.location as string,
    ).searchParams.get("code");
    assert.ok(authorizationCode);
    const authorizationCodeRecord =
      routeDependencies.authorizationCodeStore.loadAuthorizationCode(
        authorizationCode,
      );
    assert.ok(authorizationCodeRecord);
    assert.equal(authorizationCodeRecord.authTime, session.authTime);
    assert.equal(authorizationCodeRecord.requiresAuthTime, false);

    assert.equal(
      routeDependencies.pendingAuthorizationStore.loadPendingAuthorization(
        transactionId,
      ),
      undefined,
    );
  } finally {
    await fastify.close();
  }
});

test("POST TOTP MFA challenge route rejects an invalid code without consuming the transaction", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await submitCode(fastify, transactionId, "000000");

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /Invalid code/);
    assert.notEqual(
      routeDependencies.pendingAuthorizationStore.loadPendingAuthorization(
        transactionId,
      ),
      undefined,
    );
    assert.equal(routeDependencies.authorizationCodeStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

test("POST TOTP MFA challenge route treats a missing code as invalid", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await submitCode(fastify);

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /Invalid code/);
  } finally {
    await fastify.close();
  }
});

test("POST TOTP MFA challenge route removes a transaction after five invalid attempts", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const responses = [];
    for (let attempt = 0; attempt < 5; attempt++) {
      responses.push(await submitCode(fastify, transactionId, "000000"));
    }

    assert.deepEqual(
      responses.slice(0, 4).map((response) => response.statusCode),
      [401, 401, 401, 401],
    );
    assert.match(responses[4].body, /Too many MFA challenge failures/);
    assert.doesNotMatch(
      responses[4].body,
      new RegExp(`mfa-challenge-totp\\?tx=${transactionId}`),
    );
    assert.equal(
      routeDependencies.pendingAuthorizationStore.loadPendingAuthorization(
        transactionId,
      ),
      undefined,
    );
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route rejects an unknown transaction without echoing it", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);
  const unknownTransactionId = "00000000-0000-4000-8000-000000000002";

  try {
    const response = await submitCode(fastify, unknownTransactionId, "123456");

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /Login transaction not found/);
    assert.doesNotMatch(response.body, new RegExp(unknownTransactionId));
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route rejects a transaction that is not waiting for MFA", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  routeDependencies.pendingAuthorizationStore.updatePendingAuthorization(
    transactionId,
    "mfa",
    () => ({
      authorizationRequest: {
        clientId: "client-id-opaque",
        redirectUri: "http://localhost:3000/callback",
        responseType: "code",
      },
      stage: "login",
      amr: [],
      mfaFailedAttempts: 0,
      expiresAt: Date.now() + 60_000,
      requiresAuthTime: false,
    }),
  );
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await fastify.inject({
      method: "GET",
      url: `/mfa-challenge-totp?tx=${transactionId}`,
    });

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /not waiting for MFA/);
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route rejects an expired transaction", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute(Date.now() - 1);
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await fastify.inject({
      method: "GET",
      url: `/mfa-challenge-totp?tx=${transactionId}`,
    });

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /Login transaction not found/);
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route rejects a deleted user without consuming the transaction", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  routeDependencies.userStore.loadUserById = () => undefined;
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await submitCode(fastify, transactionId, "123456");

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /User no longer exists/);
    assert.notEqual(
      routeDependencies.pendingAuthorizationStore.loadPendingAuthorization(
        transactionId,
      ),
      undefined,
    );
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route does not issue an authorization code when transaction consumption loses a race", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  routeDependencies.pendingAuthorizationStore.deletePendingAuthorization = () =>
    false;
  await registerTestRoute(fastify, routeDependencies);

  try {
    const response = await submitCode(fastify, transactionId, "123456");

    assert.equal(response.statusCode, 401);
    assert.match(response.body, /already been completed or expired/);
    assert.equal(routeDependencies.authorizationCodeStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route rejects replay after successful consumption", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  await registerTestRoute(fastify, routeDependencies);

  try {
    const firstResponse = await submitCode(fastify, transactionId, "123456");
    const secondResponse = await submitCode(fastify, transactionId, "123456");

    assert.equal(firstResponse.statusCode, 302);
    assert.equal(secondResponse.statusCode, 401);
    assert.equal(routeDependencies.authorizationCodeStore.isEmpty(), false);
  } finally {
    await fastify.close();
  }
});

test("MFA challenge route allows only one concurrent request to complete a transaction", async () => {
  const fastify = Fastify();
  await fastify.register(formbody);
  const routeDependencies = setupRoute();
  routeDependencies.totpValidator.validate = async () => {
    await new Promise((resolve) => setTimeout(resolve, 10));
    return { isValid: true };
  };
  await registerTestRoute(fastify, routeDependencies);

  try {
    const responses = await Promise.all([
      submitCode(fastify, transactionId, "123456"),
      submitCode(fastify, transactionId, "123456"),
    ]);

    assert.deepEqual(
      responses.map((response) => response.statusCode).sort(),
      [302, 401],
    );
    assert.equal(routeDependencies.authorizationCodeStore.isEmpty(), false);
  } finally {
    await fastify.close();
  }
});

function setupRoute(expiresAt = Date.now() + 60_000) {
  const pendingAuthorizationStore = createPendingAuthorizationStore();
  transactionId = pendingAuthorizationStore.newPendingAuthorization({
    authorizationRequest: {
      clientId: "client-id-opaque",
      redirectUri: "http://localhost:3000/callback",
      responseType: "code",
    },
    stage: "mfa",
    userId: testUserId,
    amr: ["pwd"],
    mfaFailedAttempts: 0,
    expiresAt,
    requiresAuthTime: false,
  });

  const authorizationCodeStore = createAuthorizationCodeStore();
  const sessionStore = createSessionStore({ sessionLengthSeconds: 600 });
  const userStore = createUserStore(defaultUsers());
  const totpValidator = {
    validate: async (code: string) => ({ isValid: code === "123456" }),
  };

  return {
    pendingAuthorizationStore,
    authorizationCodeStore,
    sessionStore,
    userStore,
    totpValidator,
  };
}

async function registerTestRoute(
  fastify: FastifyInstance,
  routeDependencies: ReturnType<typeof setupRoute>,
) {
  registerMfaChallengeTotpRoute(
    fastify,
    await getTestServerContext({
      serverConfig: getTestServerConfig(),
      pendingAuthorizationStore: routeDependencies.pendingAuthorizationStore,
      authorizationCodeStore: routeDependencies.authorizationCodeStore,
      sessionStore: routeDependencies.sessionStore,
      userStore: routeDependencies.userStore,
    }),
    () => routeDependencies.totpValidator,
  );
}

function submitCode(
  fastify: FastifyInstance,
  tx: string = transactionId,
  code?: string,
) {
  return fastify.inject({
    method: "POST",
    url: `/mfa-challenge-totp?tx=${encodeURIComponent(tx)}`,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    payload: code == null ? "" : `code=${encodeURIComponent(code)}`,
  });
}

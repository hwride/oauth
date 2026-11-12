import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { createAuthorizationCodeStore } from "./stores/authorization-code-store.ts";
import { createServer } from "./server.ts";
import { defaultUsers, janeUserId, testUserId } from "./default-users.ts";
import { getTestServerConfig } from "./test/test-utils.ts";
import { createTokenStore } from "./stores/token-store.ts";
import { createUserStore } from "./stores/user-store.ts";
import { isUuidV4 } from "./utils/uuid.ts";
import { clientsConfig } from "./config/clients-config.ts";
import { totpConfig } from "./config/totp-config.ts";
import { fromBase32 } from "../util/base-encoding.ts";
import { timeBasedOneTimePasswordCode } from "../otp/time-based-one-time-password.ts";
import { createPendingAuthorizationStore } from "./stores/pending-authorization-store.ts";

/*
  This test file is for testing more end to end flows of the authorization server.
 */

const defaultServerConfig = getTestServerConfig();

test("MFA authorization flow completes TOTP challenge and preserves the transaction request", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const pendingAuthorizationStore = createPendingAuthorizationStore();
  const clientConfig = clientsConfig.find(
    (client) => client.clientId === "client-id-opaque",
  );
  assert.ok(clientConfig);
  const testUser = defaultUsers().find((user) => user.userId === testUserId);
  assert.ok(testUser);
  const totpMfaRegistration = testUser.mfaRegistrations?.find(
    (registration) => registration.type === "TOTP",
  );
  assert.ok(totpMfaRegistration);
  const codeVerifier = "mfa-code-verifier";

  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    pendingAuthorizationStore,
    authorizationCodeStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      clientConfig.clientId,
      {
        credentials: {
          username: "user",
          password: "password",
        },
        authorizationRequest: {
          scope: "openid",
          state: "state-value-123",
          nonce: "nonce-value-123",
          max_age: "0",
          code_challenge: createS256CodeChallenge(codeVerifier),
          code_challenge_method: "S256",
        },
      },
    );
    assert.equal(authorizationResponse.status, 302);

    const challengeLocation = authorizationResponse.headers.get("location");
    assert.notEqual(challengeLocation, null);
    const challengeUrl = new URL(challengeLocation, address);
    assert.equal(challengeUrl.pathname, "/mfa-challenge-totp");
    const transactionId = challengeUrl.searchParams.get("tx");
    assert.ok(transactionId);
    assert.equal(isUuidV4(transactionId), true);

    const { code } = await timeBasedOneTimePasswordCode({
      key: fromBase32(totpMfaRegistration.secretBase32),
      hashAlgorithm: totpConfig.algorithm,
      codeType: "numeric",
      codeLength: totpConfig.digits,
      timeStepSeconds: totpConfig.period,
    });
    const mfaResponse = await fetch(
      `${address}${challengeUrl.pathname}${challengeUrl.search}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ code }).toString(),
        redirect: "manual",
      },
    );

    assert.equal(mfaResponse.status, 302);
    const callbackUrl = getRedirectUrl(mfaResponse);
    assert.equal(callbackUrl.origin, "http://localhost:3000");
    assert.equal(callbackUrl.pathname, "/callback");
    assert.equal(callbackUrl.searchParams.get("state"), "state-value-123");

    const authorizationCode = callbackUrl.searchParams.get("code");
    assert.notEqual(authorizationCode, null);
    assert.equal(
      pendingAuthorizationStore.loadPendingAuthorization(transactionId),
      undefined,
    );
    const authorizationCodeRecord =
      authorizationCodeStore.loadAuthorizationCode(authorizationCode);
    assert.notEqual(authorizationCodeRecord, undefined);
    assert.equal(authorizationCodeRecord.clientId, clientConfig.clientId);
    assert.equal(authorizationCodeRecord.subject, testUserId);
    assert.deepEqual(authorizationCodeRecord.amr, ["pwd", "otp", "mfa"]);
    assert.equal(authorizationCodeRecord.requiresAuthTime, true);
    assert.equal(typeof authorizationCodeRecord.authTime, "number");
    assert.equal(
      authorizationCodeRecord.redirectUri,
      "http://localhost:3000/callback",
    );
    assert.equal(authorizationCodeRecord.scope, "openid");
    assert.equal(authorizationCodeRecord.nonce, "nonce-value-123");
    assert.equal(
      authorizationCodeRecord.codeChallenge,
      createS256CodeChallenge(codeVerifier),
    );
    assert.equal(authorizationCodeRecord.codeChallengeMethod, "S256");
    assert.ok(authorizationCodeRecord.expiresAt > Date.now());

    const tokenResponse = await fetchTokenEndpoint(
      address,
      authorizationCode,
      clientConfig.clientId,
      "test-client-secret",
      { code_verifier: codeVerifier },
    );
    assert.equal(tokenResponse.status, 200);
    const tokenResponseBody = (await tokenResponse.json()) as {
      id_token: string;
    };
    const verifiedIdToken = await jwtVerify(
      tokenResponseBody.id_token,
      defaultServerConfig.signingKey.publicKey,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: clientConfig.clientId,
      },
    );
    assert.deepEqual(verifiedIdToken.payload.amr, ["pwd", "otp", "mfa"]);
    assert.equal(
      verifiedIdToken.payload.auth_time,
      Math.floor(authorizationCodeRecord.authTime / 1000),
    );
    assert.equal(
      authorizationCodeStore.hasAuthorizationCode(authorizationCode),
      false,
    );
  } finally {
    await fastify.close();
  }
});

test("authorization server reuses a session without requiring credentials", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
    .pathname;
  const authorizationUrl = `${address}${authorizationPath}?${new URLSearchParams(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
  )}`;

  try {
    const loginPageResponse = await fetch(authorizationUrl, {
      redirect: "manual",
    });
    assert.equal(loginPageResponse.status, 200);
    const loginAction = (await loginPageResponse.text()).match(
      /<form method="post" action="([^"]+)"/,
    )?.[1];
    assert.ok(loginAction);

    const loginResponse = await fetch(address + loginAction, {
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body: new URLSearchParams({
        username: "jane",
        password: "password",
      }).toString(),
      redirect: "manual",
    });
    assert.equal(loginResponse.status, 302);
    const setCookies = loginResponse.headers.getSetCookie();
    assert.strictEqual(setCookies.length, 1);
    const sessionCookie = setCookies[0].split(";", 1)[0];

    const reusedSessionResponse = await fetch(authorizationUrl, {
      headers: {
        cookie: sessionCookie,
      },
      redirect: "manual",
    });
    assert.equal(reusedSessionResponse.status, 302);

    const redirectUrl = getRedirectUrl(reusedSessionResponse);
    const authorizationCode = redirectUrl.searchParams.get("code");
    assert.ok(authorizationCode);
    const authorizationCodeRecord =
      authorizationCodeStore.loadAuthorizationCode(authorizationCode);
    assert.ok(authorizationCodeRecord);
    assert.deepEqual(
      {
        clientId: authorizationCodeRecord.clientId,
        subject: authorizationCodeRecord.subject,
        amr: authorizationCodeRecord.amr,
        redirectUri: authorizationCodeRecord.redirectUri,
      },
      {
        clientId: "client-id-opaque",
        subject: janeUserId,
        amr: ["pwd"],
        redirectUri: "http://localhost:3000/callback",
      },
    );
    assert.ok(authorizationCodeRecord.expiresAt > Date.now());
  } finally {
    await fastify.close();
  }
});

test("authorization server requires credentials for prompt=login with an existing session", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const initialLoginResponse = await authorizeClient(
      address,
      "client-id-opaque",
    );
    assert.equal(initialLoginResponse.status, 302);
    const sessionCookie = initialLoginResponse.headers
      .getSetCookie()[0]
      .split(";", 1)[0];

    const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
      .pathname;
    const authorizationUrl = new URL(`${address}${authorizationPath}`);
    authorizationUrl.search = new URLSearchParams({
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      prompt: "login",
    }).toString();

    const loginPageResponse = await fetch(authorizationUrl, {
      headers: { cookie: sessionCookie },
      redirect: "manual",
    });
    assert.equal(loginPageResponse.status, 200);
    const loginAction = (await loginPageResponse.text()).match(
      /<form method="post" action="([^"]+)"/,
    )?.[1];
    assert.ok(loginAction);

    const reauthenticationResponse = await fetch(address + loginAction, {
      headers: {
        cookie: sessionCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body: new URLSearchParams({
        username: "jane",
        password: "password",
      }).toString(),
      redirect: "manual",
    });
    assert.equal(reauthenticationResponse.status, 302);
    assert.equal(reauthenticationResponse.headers.getSetCookie().length, 1);

    const callbackUrl = getRedirectUrl(reauthenticationResponse);
    assert.equal(callbackUrl.pathname, "/callback");
    const code = callbackUrl.searchParams.get("code");
    assert.ok(code);
    assert.equal(
      authorizationCodeStore.loadAuthorizationCode(code).subject,
      janeUserId,
    );
  } finally {
    await fastify.close();
  }
});

test("max_age includes auth_time on initial and refreshed tokens", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
      {
        authorizationRequest: {
          scope: "openid offline_access",
          max_age: "0",
        },
      },
    );
    assert.equal(authorizationResponse.status, 302);

    const authorizationCode = getRedirectUrl(authorizationResponse).searchParams.get(
      "code",
    );
    assert.notEqual(authorizationCode, null);
    const authorizationCodeRecord =
      authorizationCodeStore.loadAuthorizationCode(authorizationCode);
    assert.notEqual(authorizationCodeRecord, undefined);
    assert.equal(authorizationCodeRecord.requiresAuthTime, true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      authorizationCode,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(tokenResponse.status, 200);
    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      id_token: string;
      refresh_token: string;
    };

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verifiedInitialIdToken = await jwtVerify(
      tokenResponseBody.id_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: "client-id-jwt",
      },
    );
    assert.equal(typeof verifiedInitialIdToken.payload.auth_time, "number");
    assert.equal(
      verifiedInitialIdToken.payload.auth_time,
      Math.floor(authorizationCodeRecord.authTime / 1000),
    );

    const verifiedInitialAccessToken = await jwtVerify(
      tokenResponseBody.access_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: defaultServerConfig.issuer,
      },
    );
    assert.deepEqual(verifiedInitialAccessToken.payload.amr, ["pwd"]);
    assert.equal(
      verifiedInitialAccessToken.payload.auth_time,
      verifiedInitialIdToken.payload.auth_time,
    );

    const refreshResponse = await fetchRefreshTokenEndpoint(
      address,
      tokenResponseBody.refresh_token,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(refreshResponse.status, 200);
    const refreshResponseBody = (await refreshResponse.json()) as {
      access_token: string;
      id_token: string;
    };
    const verifiedRefreshIdToken = await jwtVerify(
      refreshResponseBody.id_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: "client-id-jwt",
      },
    );
    assert.equal(
      verifiedRefreshIdToken.payload.auth_time,
      verifiedInitialIdToken.payload.auth_time,
    );

    const verifiedRefreshAccessToken = await jwtVerify(
      refreshResponseBody.access_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: defaultServerConfig.issuer,
      },
    );
    assert.deepEqual(verifiedRefreshAccessToken.payload.amr, ["pwd"]);
    assert.equal(
      verifiedRefreshAccessToken.payload.auth_time,
      verifiedInitialAccessToken.payload.auth_time,
    );
  } finally {
    await fastify.close();
  }
});

test("authorization code can be issued and exchanged for an opaque access token", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-opaque",
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.equal(
      redirectUrl.toString(),
      `http://localhost:3000/callback?code=${code}`,
    );
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-opaque",
      "test-client-secret",
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    // Check auth code was removed.
    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), false);
    // Check new access token is in the token store, for this client.
    assert.deepEqual(
      tokenStore.loadAccessToken(tokenResponseBody.access_token),
      {
        clientId: "client-id-opaque",
        amr: ["pwd"],
      },
    );
  } finally {
    await fastify.close();
  }
});

test("authorization code can be issued and exchanged for a jwt access token verified via the auth server jwks url", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.equal(
      redirectUrl.toString(),
      `http://localhost:3000/callback?code=${code}`,
    );
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verified = await jwtVerify(tokenResponseBody.access_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    });

    assert.equal(verified.protectedHeader.alg, "RS256");
    assert.equal(verified.protectedHeader.typ, "at+jwt");
    assert.equal(verified.payload.iss, defaultServerConfig.issuer);
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
    assert.equal(verified.payload.sub, janeUserId);
    assert.equal(verified.payload.client_id, "client-id-jwt");
    assert.equal(typeof verified.payload.jti, "string");
    assert.notEqual(verified.payload.jti.length, 0);
    assert.equal(typeof verified.payload.iat, "number");
    assert.equal(typeof verified.payload.exp, "number");
    assert.ok(verified.payload.exp > verified.payload.iat);

    // Check auth code was removed.
    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), false);
    // JWT access tokens are self-contained and are not stored server-side.
    assert.equal(tokenStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

test("authorization code flow supports PKCE and state together", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  const codeVerifier = "pkce-verifier-1234567890abcdefghijklmnopqrstuvwxyz";
  const codeChallenge = createS256CodeChallenge(codeVerifier);
  const state = "state-value-123";

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
      {
        authorizationRequest: {
          state,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
        },
      },
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.notEqual(code, null);
    assert.equal(redirectUrl.origin, "http://localhost:3000");
    assert.equal(redirectUrl.pathname, "/callback");
    assert.equal(redirectUrl.searchParams.get("state"), state);

    const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
    assert.notEqual(codeRecord, undefined);
    assert.equal(codeRecord.codeChallenge, codeChallenge);
    assert.equal(codeRecord.codeChallengeMethod, "S256");

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
      {
        code_verifier: codeVerifier,
      },
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verified = await jwtVerify(tokenResponseBody.access_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    });

    assert.equal(verified.protectedHeader.alg, "RS256");
    assert.equal(verified.protectedHeader.typ, "at+jwt");
    assert.equal(verified.payload.iss, defaultServerConfig.issuer);
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
    assert.equal(verified.payload.sub, janeUserId);
    assert.equal(verified.payload.client_id, "client-id-jwt");

    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), false);
    assert.equal(tokenStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

test("OIDC authorization code flow with nonce", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  const nonce = "nonce-value-123";

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
      {
        authorizationRequest: {
          scope: "openid profile",
          nonce,
        },
      },
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), true);

    const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
    assert.notEqual(codeRecord, undefined);
    assert.equal(codeRecord.scope, "openid profile");
    assert.equal(codeRecord.nonce, nonce);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      id_token: string;
      scope: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(tokenResponseBody.scope, "openid profile");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);
    assert.equal(typeof tokenResponseBody.id_token, "string");
    assert.notEqual(tokenResponseBody.id_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verifiedAccessToken = await jwtVerify(
      tokenResponseBody.access_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: defaultServerConfig.issuer,
      },
    );
    assert.equal(verifiedAccessToken.protectedHeader.alg, "RS256");
    assert.equal(verifiedAccessToken.protectedHeader.typ, "at+jwt");
    assert.equal(verifiedAccessToken.payload.iss, defaultServerConfig.issuer);
    assert.equal(verifiedAccessToken.payload.aud, defaultServerConfig.issuer);
    assert.equal(verifiedAccessToken.payload.sub, janeUserId);
    assert.equal(verifiedAccessToken.payload.client_id, "client-id-jwt");
    assert.equal(verifiedAccessToken.payload.scope, "openid profile");
    assert.equal(typeof verifiedAccessToken.payload.jti, "string");
    assert.notEqual(verifiedAccessToken.payload.jti.length, 0);
    assert.equal(typeof verifiedAccessToken.payload.iat, "number");
    assert.equal(typeof verifiedAccessToken.payload.exp, "number");
    assert.ok(
      verifiedAccessToken.payload.exp > verifiedAccessToken.payload.iat,
    );

    const verifiedIdToken = await jwtVerify(tokenResponseBody.id_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: "client-id-jwt",
    });

    assert.equal(verifiedIdToken.protectedHeader.alg, "RS256");
    assert.equal(verifiedIdToken.payload.iss, defaultServerConfig.issuer);
    assert.equal(verifiedIdToken.payload.aud, "client-id-jwt");
    assert.equal(verifiedIdToken.payload.sub, janeUserId);
    assert.equal(verifiedIdToken.payload.name, "Jane Smith");
    assert.equal(verifiedIdToken.payload.nonce, nonce);
    // auth_time is omitted when max_age was not requested.
    assert.equal(verifiedIdToken.payload.auth_time, undefined);
    assert.equal(typeof verifiedIdToken.payload.jti, "string");
    assert.notEqual(verifiedIdToken.payload.jti.length, 0);
    assert.equal(typeof verifiedIdToken.payload.iat, "number");
    assert.equal(typeof verifiedIdToken.payload.exp, "number");
    assert.ok(verifiedIdToken.payload.exp > verifiedIdToken.payload.iat);

    const userinfoResponse = await fetchUserinfoEndpoint(
      address,
      tokenResponseBody.access_token,
    );
    assert.equal(userinfoResponse.status, 200);
    assert.deepEqual(await userinfoResponse.json(), {
      sub: janeUserId,
      name: "Jane Smith",
    });

    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), false);
    assert.equal(tokenStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

test("OIDC refresh token flow returns new access and ID tokens", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
      {
        authorizationRequest: {
          scope: "openid offline_access email",
        },
      },
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      id_token: string;
      refresh_token: string;
      scope: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(tokenResponseBody.scope, "openid offline_access email");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);
    assert.equal(typeof tokenResponseBody.id_token, "string");
    assert.notEqual(tokenResponseBody.id_token.length, 0);
    assert.equal(typeof tokenResponseBody.refresh_token, "string");
    assert.notEqual(tokenResponseBody.refresh_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verifiedInitialIdToken = await jwtVerify(
      tokenResponseBody.id_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: "client-id-jwt",
      },
    );
    assert.deepEqual(verifiedInitialIdToken.payload.amr, ["pwd"]);
    assert.equal(typeof verifiedInitialIdToken.payload.iat, "number");

    // Sleep long enough that iat will change for ID tokens.
    await sleep(1100);

    const refreshResponse = await fetchRefreshTokenEndpoint(
      address,
      tokenResponseBody.refresh_token,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(refreshResponse.status, 200);

    const refreshResponseBody = (await refreshResponse.json()) as {
      access_token: string;
      id_token: string;
      scope: string;
      token_type: string;
    };

    assert.equal(refreshResponseBody.token_type, "Bearer");
    assert.equal(refreshResponseBody.scope, "openid offline_access email");
    assert.equal(typeof refreshResponseBody.access_token, "string");
    assert.notEqual(refreshResponseBody.access_token.length, 0);
    assert.notEqual(
      refreshResponseBody.access_token,
      tokenResponseBody.access_token,
    );
    assert.equal(typeof refreshResponseBody.id_token, "string");
    assert.notEqual(refreshResponseBody.id_token.length, 0);

    const verifiedRefreshIdToken = await jwtVerify(
      refreshResponseBody.id_token,
      jwks,
      {
        algorithms: ["RS256"],
        issuer: defaultServerConfig.issuer,
        audience: "client-id-jwt",
      },
    );

    assert.deepEqual(verifiedRefreshIdToken.payload.amr, ["pwd"]);
    assert.equal(typeof verifiedRefreshIdToken.payload.iat, "number");
    assert.ok(
      verifiedRefreshIdToken.payload.iat > verifiedInitialIdToken.payload.iat,
    );
    assert.equal(tokenStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

test("signup route preserves prompt and creates a user who can then log in and receive a valid jwt access token", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const userStore = createUserStore([]);
  const fastify = await createServer({
    serverConfig: defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
    userStore,
  });
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const signupResponse = await submitSignupForm(address, {
      client_id: "client-id-jwt",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      prompt: "login",
      username: "new-user",
      name: "New User",
      password: "new-password",
    });

    assert.equal(signupResponse.status, 302);
    const signupLocation = signupResponse.headers.get("location");
    assert.ok(signupLocation);
    const signupRedirect = new URL(signupLocation, address);
    assert.equal(signupRedirect.pathname, "/authorize");
    assert.equal(signupRedirect.searchParams.get("prompt"), "login");
    const newUser = userStore.loadUserByUsername("new-user");
    assert.notEqual(newUser, undefined);
    assert.equal(isUuidV4(newUser.userId), true);
    assert.equal(newUser.password, "new-password");
    assert.equal(newUser.name, "New User");

    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
      {
        credentials: {
          username: "new-user",
          password: "new-password",
        },
      },
    );

    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
    );

    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    // Check JWT is valid according to our published JWKS public keys.
    const verified = await jwtVerify(tokenResponseBody.access_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    });

    assert.equal(verified.protectedHeader.alg, "RS256");
    assert.equal(verified.protectedHeader.typ, "at+jwt");
    assert.equal(verified.payload.iss, defaultServerConfig.issuer);
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
    assert.equal(verified.payload.sub, newUser.userId);
    assert.notEqual(verified.payload.sub, newUser.username);
    assert.equal(verified.payload.client_id, "client-id-jwt");
    assert.equal(typeof verified.payload.jti, "string");
    assert.notEqual(verified.payload.jti.length, 0);
    assert.equal(typeof verified.payload.iat, "number");
    assert.equal(typeof verified.payload.exp, "number");
    assert.ok(verified.payload.exp > verified.payload.iat);

    assert.equal(authorizationCodeStore.hasAuthorizationCode(code), false);
    assert.equal(tokenStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

async function authorizeClient(
  address: string,
  clientId: string,
  {
    credentials = {
      username: "jane",
      password: "password",
    },
    authorizationRequest = {},
  }: {
    credentials?: {
      username: string;
      password: string;
    };
    authorizationRequest?: Record<string, string>;
  } = {
    credentials: {
      username: "jane",
      password: "password",
    },
  },
) {
  const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
    .pathname;
  const requestParams = {
    client_id: clientId,
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    ...authorizationRequest,
  };

  // Fetch the authorization request.
  const queryString = new URLSearchParams(requestParams).toString();
  const loginPageResponse = await fetch(
    `${address}${authorizationPath}?${queryString}`,
    {
      redirect: "manual",
    },
  );
  assert.equal(loginPageResponse.status, 200);

  // Submit the login form.
  const action = (await loginPageResponse.text()).match(
    /<form method="post" action="([^"]+)"/,
  )[1];
  const loginRequestBody = new URLSearchParams({
    username: credentials.username,
    password: credentials.password,
  }).toString();
  return await fetch(address + action, {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: loginRequestBody,
    redirect: "manual",
  });
}

async function fetchTokenEndpoint(
  address: string,
  code: string,
  clientId: string,
  clientSecret: string,
  tokenRequestBody: Record<string, string> = {},
) {
  const tokenPath = new URL(defaultServerConfig.tokenEndpoint).pathname;
  const requestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:3000/callback",
    ...tokenRequestBody,
  }).toString();

  return await fetch(`${address}${tokenPath}`, {
    headers: {
      authorization: createBasicAuthHeader(clientId, clientSecret),
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
  });
}

async function fetchRefreshTokenEndpoint(
  address: string,
  refreshToken: string,
  clientId: string,
  clientSecret: string,
) {
  const tokenPath = new URL(defaultServerConfig.tokenEndpoint).pathname;
  const requestBody = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  }).toString();

  return await fetch(`${address}${tokenPath}`, {
    headers: {
      authorization: createBasicAuthHeader(clientId, clientSecret),
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
  });
}

async function fetchUserinfoEndpoint(address: string, accessToken: string) {
  return await fetch(`${address}/userinfo`, {
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });
}

async function submitSignupForm(
  address: string,
  formData: Record<string, string>,
) {
  const requestBody = new URLSearchParams(formData).toString();

  return await fetch(`${address}/signup`, {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
    redirect: "manual",
  });
}

function getRedirectUrl(response: Response) {
  const location = response.headers.get("location");
  assert.notEqual(location, null);
  return new URL(location);
}

function createBasicAuthHeader(clientId: string, clientSecret: string) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );
  return `Basic ${basicAuth}`;
}

function createS256CodeChallenge(codeVerifier: string) {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}

async function sleep(ms: number) {
  await new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

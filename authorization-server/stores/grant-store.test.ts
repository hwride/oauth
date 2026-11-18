import assert from "node:assert/strict";
import test from "node:test";
import {
  createGrantStore,
  type AuthorizationCodeRecord,
} from "./grant-store.ts";

const authorizationCodeRecord: AuthorizationCodeRecord = {
  clientId: "client-id",
  subject: "user-id",
  authTime: 0,
  requiresAuthTime: false,
  amr: ["pwd"],
  redirectUri: "http://localhost:3000/callback",
  expiresAt: Date.now() + 60_000,
};

test("grant store retains and consumes an authorization code", () => {
  const grantStore = createGrantStore();
  const grantId = grantStore.createAuthorizationCodeGrant(
    "auth-code",
    authorizationCodeRecord,
  );

  assert.deepEqual(grantStore.loadAuthorizationCode("auth-code"), {
    ...authorizationCodeRecord,
    grantId,
  });

  const consumed = grantStore.consumeAuthorizationCode("auth-code");
  assert.deepEqual(consumed, { ...authorizationCodeRecord, grantId });
  assert.equal(grantStore.loadAuthorizationCode("auth-code"), undefined);
  assert.equal(grantStore.consumeAuthorizationCode("auth-code"), undefined);

  const grant = grantStore.getGrantByAuthorizationCode("auth-code");
  assert.ok(grant);
  assert.equal(grant.authorizationCode.record, authorizationCodeRecord);
  assert.equal(typeof grant.authorizationCode.usedAt, "number");
  assert.equal(grant.state, "pending");
});

test("grant store associates access and refresh tokens with a grant", () => {
  const grantStore = createGrantStore();
  const grantId = grantStore.createAuthorizationCodeGrant(
    "auth-code",
    authorizationCodeRecord,
  );

  grantStore.saveAccessToken("access-token", grantId, {
    type: "opaque",
    clientId: "client-id",
  });
  const refreshToken = grantStore.generateRefreshToken(
    grantId,
    {
      clientId: "client-id",
      subject: "user-id",
      authTime: 0,
      requiresAuthTime: false,
    },
    60,
  );

  assert.deepEqual(grantStore.loadAccessToken("access-token"), {
    type: "opaque",
    clientId: "client-id",
  });
  assert.equal(grantStore.getRefreshToken(refreshToken)?.grantId, grantId);
  assert.equal(grantStore.getGrant(grantId)?.state, "active");
  assert.deepEqual(
    grantStore.getGrant(grantId)?.accessTokens,
    new Set(["access-token"]),
  );
  assert.equal(grantStore.getGrant(grantId)?.refreshToken, refreshToken);
});

test("revoking a grant removes its tokens but retains its authorization code record", () => {
  const grantStore = createGrantStore();
  const grantId = grantStore.createAuthorizationCodeGrant(
    "auth-code",
    authorizationCodeRecord,
  );
  grantStore.saveAccessToken("access-token", grantId, { type: "jwt" });
  const refreshToken = grantStore.generateRefreshToken(
    grantId,
    {
      clientId: "client-id",
      subject: "user-id",
      authTime: 0,
      requiresAuthTime: false,
    },
    60,
  );

  assert.equal(grantStore.revokeGrant(grantId), true);
  assert.equal(grantStore.getGrant(grantId)?.state, "revoked");
  assert.equal(grantStore.loadAccessToken("access-token"), undefined);
  assert.equal(grantStore.getRefreshToken(refreshToken), undefined);
  assert.equal(grantStore.loadAuthorizationCode("auth-code"), undefined);
  assert.equal(grantStore.consumeAuthorizationCode("auth-code"), undefined);
  assert.deepEqual(grantStore.getGrant(grantId)?.accessTokens, new Set());
  assert.equal(grantStore.getGrant(grantId)?.refreshToken, undefined);
  assert.deepEqual(
    grantStore.getGrantByAuthorizationCode("auth-code")?.authorizationCode
      .record,
    authorizationCodeRecord,
  );
});

test("grant store rejects unknown token and grant lookups", () => {
  const grantStore = createGrantStore();

  assert.equal(grantStore.loadAuthorizationCode(undefined), undefined);
  assert.equal(grantStore.consumeAuthorizationCode(null), undefined);
  assert.equal(grantStore.loadAccessToken(undefined), undefined);
  assert.equal(grantStore.deleteAccessToken("missing"), false);
  assert.equal(grantStore.deleteRefreshToken("missing"), false);
  assert.equal(grantStore.revokeGrant("missing"), false);
});

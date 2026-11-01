import assert from "node:assert/strict";
import test from "node:test";
import { createPendingAuthorizationStore } from "./pending-authorization-store.ts";

const transactionId = "00000000-0000-4000-8000-000000000001";

test("pending authorization store saves and loads records", () => {
  const store = createPendingAuthorizationStore();
  const record = createRecord();

  store.savePendingAuthorization(transactionId, record);

  assert.equal(store.isEmpty(), false);
  assert.deepEqual(store.loadPendingAuthorization(transactionId), record);
});

test("pending authorization store returns undefined for missing records", () => {
  const store = createPendingAuthorizationStore();

  assert.equal(store.isEmpty(), true);
  assert.equal(store.loadPendingAuthorization(transactionId), undefined);
  assert.equal(store.loadPendingAuthorization(undefined), undefined);
  assert.equal(store.loadPendingAuthorization(null), undefined);
});

test("pending authorization store removes expired records when loading", () => {
  const store = createPendingAuthorizationStore();
  store.savePendingAuthorization(transactionId, createRecord(Date.now() - 1));

  assert.equal(store.loadPendingAuthorization(transactionId), undefined);
  assert.equal(store.isEmpty(), true);
});

test("pending authorization store deletes records and reports whether one existed", () => {
  const store = createPendingAuthorizationStore();
  store.savePendingAuthorization(transactionId, createRecord());

  assert.equal(store.deletePendingAuthorization(transactionId), true);
  assert.equal(store.deletePendingAuthorization(transactionId), false);
  assert.equal(store.isEmpty(), true);
});

// We don't just return true here because it's useful to know this record was already delete, i.e. uesd.
// Provides us some extra protection against race conditions - if this was already used deny the transaction.
test("pending authorization store refuses to consume an expired record", () => {
  const store = createPendingAuthorizationStore();
  store.savePendingAuthorization(transactionId, createRecord(Date.now() - 1));

  assert.equal(store.deletePendingAuthorization(transactionId), false);
  assert.equal(store.isEmpty(), true);
});

test("pending authorization store returns false when deleting a missing transaction ID", () => {
  const store = createPendingAuthorizationStore();

  assert.equal(store.deletePendingAuthorization(undefined), false);
  assert.equal(store.deletePendingAuthorization(null), false);
});

test("pending authorization store removes a transaction after the maximum failed MFA attempts", () => {
  const store = createPendingAuthorizationStore();
  store.savePendingAuthorization(transactionId, createRecord());

  assert.equal(store.recordFailedMfaAttempt(transactionId, 5), "recorded");
  assert.equal(store.recordFailedMfaAttempt(transactionId, 5), "recorded");
  assert.equal(store.recordFailedMfaAttempt(transactionId, 5), "recorded");
  assert.equal(store.recordFailedMfaAttempt(transactionId, 5), "recorded");
  assert.equal(store.recordFailedMfaAttempt(transactionId, 5), "exhausted");
  assert.equal(store.loadPendingAuthorization(transactionId), undefined);
  assert.equal(store.recordFailedMfaAttempt(transactionId, 5), "not_found");
});

function createRecord(expiresAt = Date.now() + 60_000) {
  return {
    authorizationRequest: {
      clientId: "client-id-opaque",
      redirectUri: "http://localhost:3000/callback",
      responseType: "code",
    },
    subject: "test-user",
    mfaFailedAttempts: 0,
    expiresAt,
  };
}

import assert from "node:assert/strict";
import test from "node:test";
import {
  createPendingAuthorizationStore,
  type PendingAuthorizationRecord,
} from "./pending-authorization-store.ts";

test("pending authorization store saves and loads records", () => {
  const store = createPendingAuthorizationStore();
  const record = createRecord();

  const transactionId = store.newPendingAuthorization(record);

  assert.equal(store.isEmpty(), false);
  assert.deepEqual(store.loadPendingAuthorization(transactionId), record);
});

test("pending authorization store updates a record when its stage matches", () => {
  const store = createPendingAuthorizationStore();
  const loginRecord = {
    ...createRecord(),
    stage: "login" as const,
    userId: undefined,
    amr: [],
  };
  const transactionId = store.newPendingAuthorization(loginRecord);
  const updatedRecord = {
    ...createRecord(),
    stage: "mfa" as const,
    userId: "test-user",
  };

  assert.equal(
    store.updatePendingAuthorization(
      transactionId,
      "login",
      () => updatedRecord,
    ),
    "updated",
  );
  assert.deepEqual(
    store.loadPendingAuthorization(transactionId),
    updatedRecord,
  );
  assert.equal(
    store.updatePendingAuthorization(transactionId, "mfa", () => "delete"),
    "deleted",
  );
  assert.equal(store.loadPendingAuthorization(transactionId), undefined);
});

test("pending authorization store refuses updates for missing, expired, or wrong-stage records", () => {
  const store = createPendingAuthorizationStore();
  const updatedRecord = {
    ...createRecord(),
    stage: "mfa" as const,
    userId: "test-user",
  };

  assert.equal(
    store.updatePendingAuthorization(
      "00000000-0000-4000-8000-000000000001",
      "mfa",
      () => updatedRecord,
    ),
    "not_found",
  );

  const transactionId = store.newPendingAuthorization({
    ...createRecord(),
    stage: "login",
    userId: undefined,
    amr: [],
  });
  assert.equal(
    store.updatePendingAuthorization(transactionId, "mfa", () => updatedRecord),
    "invalid_stage",
  );
  assert.equal(store.loadPendingAuthorization(transactionId).stage, "login");

  const expiredTransactionId = store.newPendingAuthorization({
    ...createRecord(Date.now() - 1),
    stage: "login",
    userId: undefined,
    amr: [],
  });
  assert.equal(
    store.updatePendingAuthorization(
      expiredTransactionId,
      "login",
      () => updatedRecord,
    ),
    "not_found",
  );
  assert.equal(store.loadPendingAuthorization(expiredTransactionId), undefined);
});

test("pending authorization store returns undefined for missing records", () => {
  const store = createPendingAuthorizationStore();

  assert.equal(store.isEmpty(), true);
  assert.equal(
    store.loadPendingAuthorization("00000000-0000-4000-8000-000000000001"),
    undefined,
  );
  assert.equal(store.loadPendingAuthorization(undefined), undefined);
  assert.equal(store.loadPendingAuthorization(null), undefined);
});

test("pending authorization store removes expired records when loading", () => {
  const store = createPendingAuthorizationStore();
  const transactionId = store.newPendingAuthorization(
    createRecord(Date.now() - 1),
  );

  assert.equal(store.loadPendingAuthorization(transactionId), undefined);
  assert.equal(store.isEmpty(), true);
});

test("pending authorization store deletes records and reports whether one existed", () => {
  const store = createPendingAuthorizationStore();
  const transactionId = store.newPendingAuthorization(createRecord());

  assert.equal(store.deletePendingAuthorization(transactionId), true);
  assert.equal(store.deletePendingAuthorization(transactionId), false);
  assert.equal(store.isEmpty(), true);
});

// We don't just return true here because it's useful to know this record was already delete, i.e. uesd.
// Provides us some extra protection against race conditions - if this was already used deny the transaction.
test("pending authorization store refuses to consume an expired record", () => {
  const store = createPendingAuthorizationStore();
  const transactionId = store.newPendingAuthorization(
    createRecord(Date.now() - 1),
  );

  assert.equal(store.deletePendingAuthorization(transactionId), false);
  assert.equal(store.isEmpty(), true);
});

test("pending authorization store returns false when deleting a missing transaction ID", () => {
  const store = createPendingAuthorizationStore();

  assert.equal(store.deletePendingAuthorization(undefined), false);
  assert.equal(store.deletePendingAuthorization(null), false);
});

function createRecord(
  expiresAt = Date.now() + 60_000,
): PendingAuthorizationRecord {
  return {
    authorizationRequest: {
      clientId: "client-id-opaque",
      redirectUri: "http://localhost:3000/callback",
      responseType: "code",
    },
    stage: "mfa",
    userId: "test-user",
    amr: ["pwd"],
    mfaFailedAttempts: 0,
    expiresAt,
    requiresAuthTime: false,
  };
}

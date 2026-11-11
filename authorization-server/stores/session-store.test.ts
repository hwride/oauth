import assert from "node:assert/strict";
import test from "node:test";
import {
  createSessionStore,
  type SessionStoreConfig,
} from "./session-store.ts";
import { isUuidV4 } from "../utils/uuid.ts";

const sessionStoreConfig: SessionStoreConfig = {
  sessionLengthSeconds: 10,
};

test("newSession", function () {
  const store = createSessionStore(sessionStoreConfig);

  const session = store.newSession({
    userId: "user1",
    amr: ["pwd"],
    authTime: 0,
  });

  assert.equal(session.userId, "user1");
  assert.ok(isUuidV4(session.sessionId), "session is UUIDv4");
  const createAtDate = new Date(session.createdAt);
  const expiresAtDate = new Date(session.expiresAt);
  const sessionLengthMs = sessionStoreConfig.sessionLengthSeconds * 1000;
  assert.strictEqual(
    expiresAtDate.getTime() - createAtDate.getTime(),
    sessionLengthMs,
    "expiry time is correct",
  );

  assert.deepEqual(store.loadSession(session.sessionId), session);
});

test("session store returns defensive copies", function () {
  const store = createSessionStore(sessionStoreConfig);
  const session = store.newSession({
    userId: "user1",
    amr: ["pwd"],
    authTime: 0,
  });

  session.amr.push("otp");

  assert.deepEqual(store.loadSession(session.sessionId)?.amr, ["pwd"]);

  const loadedSession = store.loadSession(session.sessionId);
  loadedSession?.amr.push("otp");

  assert.deepEqual(store.loadSession(session.sessionId)?.amr, ["pwd"]);
});

test("session store returns undefined for missing sessions", function () {
  const store = createSessionStore(sessionStoreConfig);

  assert.equal(store.loadSession("missing-session"), undefined);
  assert.equal(store.loadSession(undefined), undefined);
  assert.equal(store.loadSession(null), undefined);
});

test("session store removes expired sessions when loading", function () {
  const store = createSessionStore({ sessionLengthSeconds: -1 });
  const session = store.newSession({
    userId: "user1",
    amr: ["pwd"],
    authTime: 0,
  });

  assert.equal(store.loadSession(session.sessionId), undefined);
  assert.equal(store.deleteSession(session.sessionId), false);
});

test("session store deletes sessions and reports whether one existed", function () {
  const store = createSessionStore(sessionStoreConfig);
  const session = store.newSession({
    userId: "user1",
    amr: ["pwd"],
    authTime: 0,
  });

  assert.equal(store.deleteSession(session.sessionId), true);
  assert.equal(store.loadSession(session.sessionId), undefined);
  assert.equal(store.deleteSession(session.sessionId), false);
});

test("session store refuses to delete an expired session", function () {
  const store = createSessionStore({ sessionLengthSeconds: -1 });
  const session = store.newSession({
    userId: "user1",
    amr: ["pwd"],
    authTime: 0,
  });

  assert.equal(store.deleteSession(session.sessionId), false);
  assert.equal(store.loadSession(session.sessionId), undefined);
});

test("session store returns false when deleting a missing session ID", function () {
  const store = createSessionStore(sessionStoreConfig);

  assert.equal(store.deleteSession("missing-session"), false);
  assert.equal(store.deleteSession(undefined), false);
  assert.equal(store.deleteSession(null), false);
});

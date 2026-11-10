import assert from "node:assert/strict";
import test from "node:test";
import type { FastifyRequest } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";
import { createSessionStore, type Session } from "../stores/session-store.ts";
import { createUserStore, type UserRecord } from "../stores/user-store.ts";
import {
  getSessionCookie,
  getSessionCookieClear,
  loadSessionFromCookie,
} from "./session-utils.ts";

test("loadSessionFromCookie loads the session and its user", function () {
  const user = createUser();
  const userStore = createUserStore([user]);
  const sessionStore = createSessionStore({ sessionLengthSeconds: 600 });
  const session = sessionStore.newSession({
    userId: user.userId,
    amr: ["pwd"],
  });

  assert.deepEqual(
    loadSessionFromCookie(
      createRequest(session.sessionId),
      sessionStore,
      userStore,
    ),
    { ok: true, session, user },
  );
});

test("loadSessionFromCookie reports whether a session cookie was present", function () {
  const userStore = createUserStore([createUser()]);
  const sessionStore = createSessionStore({ sessionLengthSeconds: -1 });
  const session = sessionStore.newSession({
    userId: "user-id",
    amr: ["pwd"],
  });

  assert.deepEqual(
    loadSessionFromCookie(createRequest(), sessionStore, userStore),
    { ok: false, error: "session-not-found", sessionIdWasPresent: false },
  );
  assert.deepEqual(
    loadSessionFromCookie(
      createRequest("missing-session"),
      sessionStore,
      userStore,
    ),
    { ok: false, error: "session-not-found", sessionIdWasPresent: true },
  );
  assert.deepEqual(
    loadSessionFromCookie(
      createRequest(session.sessionId),
      sessionStore,
      userStore,
    ),
    { ok: false, error: "session-not-found", sessionIdWasPresent: true },
  );
});

test("loadSessionFromCookie deletes sessions whose user no longer exists", function () {
  const sessionStore = createSessionStore({ sessionLengthSeconds: 600 });
  const session = sessionStore.newSession({
    userId: "deleted-user",
    amr: ["pwd"],
  });

  assert.deepEqual(
    loadSessionFromCookie(
      createRequest(session.sessionId),
      sessionStore,
      createUserStore(),
    ),
    { ok: false, error: "user-not-found", sessionIdWasPresent: true },
  );
  assert.equal(sessionStore.loadSession(session.sessionId), undefined);
});

test("getSessionCookie serializes the session cookie attributes", function () {
  const session: Session = {
    sessionId: "session-id",
    userId: "user-id",
    createdAt: 0,
    expiresAt: 600_000,
    amr: ["pwd"],
  };

  assert.equal(
    getSessionCookie(session, { sessionLengthSeconds: 600 } as ServerConfig),
    "__Host-Http-session-id=session-id; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600",
  );
});

test("getSessionCookieClear expires the session cookie", function () {
  assert.equal(
    getSessionCookieClear(),
    '__Host-Http-session-id=""; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
  );
});

function createRequest(sessionId?: string): FastifyRequest {
  return {
    cookies: sessionId ? { "__Host-Http-session-id": sessionId } : {},
  } as FastifyRequest;
}

function createUser(): UserRecord {
  return {
    userId: "user-id",
    username: "user",
    password: "password",
    name: "Test User",
  };
}

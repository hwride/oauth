import type { FastifyRequest } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";
import type { Session, SessionStore } from "../stores/session-store.ts";
import type { UserRecord, UserStore } from "../stores/user-store.ts";

export const sessionCookieName = "__Host-Http-session-id";
const commonCookieAttrs = ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"];

/**
 * Will perform a session lookup for the session ID cookie on the given request.
 */
export function loadSessionFromCookie(
  request: FastifyRequest,
  sessionStore: SessionStore,
  userStore: UserStore,
):
  | { ok: true; session: Session; user: UserRecord }
  | { ok: false; error: "session-not-found"; sessionIdWasPresent: boolean }
  | { ok: false; error: "user-not-found"; sessionIdWasPresent: boolean } {
  const sessionId = request.cookies[sessionCookieName];
  const sessionIdWasPresent = sessionId != null;
  const session = sessionId ? sessionStore.loadSession(sessionId) : undefined;
  if (session == null) {
    return { ok: false, error: "session-not-found", sessionIdWasPresent };
  }

  const user = userStore.loadUserById(session.userId);
  if (user == null) {
    sessionStore.deleteSession(sessionId); // Clear the invalid session.
    return { ok: false, error: "user-not-found", sessionIdWasPresent };
  }

  return { ok: true, session, user };
}

/**
 * Get the value for session cookie. Note expiry is relative not absolute.
 */
export function getSessionCookie(session: Session, serverConfig: ServerConfig) {
  const parts = [
    `${sessionCookieName}=${session.sessionId}`,
    ...commonCookieAttrs,
    `Max-Age=${serverConfig.sessionLengthSeconds}`,
  ];
  return parts.join("; ");
}

/**
 * Get the value for a session cookie you want to clear.
 */
export function getSessionCookieClear() {
  const parts = [`${sessionCookieName}=""`, ...commonCookieAttrs, "Max-Age=0"];
  return parts.join("; ");
}

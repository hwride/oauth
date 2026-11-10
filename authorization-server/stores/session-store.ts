import { randomUUID } from "node:crypto";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";

/**
 * An active authentication session for a user of this authorization server/OpenID Provider.
 */
export type Session = {
  /** Session ID. */
  sessionId: string;
  /** User ID who owns this session. */
  userId: string;
  /** When the session was created. Unix time in ms */
  createdAt: number;
  /** When the session expires. Unix time in ms */
  expiresAt: number;
  /**
   * What authentication methods were used to create this session.
   */
  amr: AuthenticationMethodReference[];
};

export type SessionStoreConfig = {
  sessionLengthSeconds: number;
};

/**
 * This is a store for saving authenticated sessions for this authorization server.
 */
export type SessionStore = {
  /**
   * Create a new session.
   */
  newSession(opts: Pick<Session, "userId" | "amr">): Session;

  /**
   * Load a pending authorization session.
   *
   * If the session has expired will be removed and return undefined.
   *
   * @param sessionId Session ID to load.
   */
  loadSession(sessionId: string): Session | undefined;

  /**
   * Delete a session.
   *
   * @param sessionId Session ID to delete.
   * @returns True if the delete was successful. Note it does not count as a successful delete if the session no longer
   * exists or was expired. This gives you another chance to guard against race conditions.
   */
  deleteSession(sessionId: string): boolean;
};

export function createSessionStore({
  sessionLengthSeconds,
}: SessionStoreConfig): SessionStore {
  /** Map of session ID to session. */
  const sessions = new Map<string, Session>();

  return {
    newSession(opts) {
      let sessionId: string;
      do {
        sessionId = randomUUID();
      } while (sessions.has(sessionId));

      const createdAt = new Date().getTime();
      const sessionLengthMs = sessionLengthSeconds * 1000;
      const session: Session = {
        ...opts,
        amr: [...opts.amr],
        sessionId,
        createdAt,
        expiresAt: createdAt + sessionLengthMs,
      };
      sessions.set(sessionId, session);

      return structuredClone(session);
    },

    loadSession(sessionId) {
      if (sessionId == null) {
        return undefined;
      }

      const session = sessions.get(sessionId);
      if (!session) {
        return undefined;
      }

      // Expired entries are cleaned up lazily when they are accessed.
      if (session.expiresAt <= Date.now()) {
        sessions.delete(sessionId);
        return undefined;
      }

      return structuredClone(session);
    },

    deleteSession(sessionId) {
      if (sessionId == null) {
        return false;
      }

      const session = sessions.get(sessionId);
      if (!session) {
        return false;
      }

      // Re-check expiry before delete. It's important so can inform the consumer if this was still an active session
      // before their request to delete.
      if (session.expiresAt <= Date.now()) {
        sessions.delete(sessionId);
        return false;
      }

      return sessions.delete(sessionId);
    },
  };
}

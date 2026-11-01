import type { AuthorizationRequest } from "../types/authorization-request.ts";

export type PendingAuthorizationRecord = {
  authorizationRequest: AuthorizationRequest;
  subject: string;
  /** Unix time in ms */
  expiresAt: number;
  mfaFailedAttempts: number;
};

export type RecordMfaAttemptResult = "recorded" | "exhausted" | "not_found";

/**
 * This is a store for saving the state of pending authorization requests. I.e. authorization requests that
 * have started but not yet completed, because they may be pending on something like MFA.
 */
export type PendingAuthorizationStore = {
  savePendingAuthorization(
    transactionId: string,
    record: PendingAuthorizationRecord,
  ): void;
  loadPendingAuthorization(
    transactionId: string | null | undefined,
  ): PendingAuthorizationRecord | undefined;
  deletePendingAuthorization(transactionId: string | null | undefined): boolean;
  recordFailedMfaAttempt(
    transactionId: string | null | undefined,
    maxAttempts: number,
  ): RecordMfaAttemptResult;
  isEmpty(): boolean;
};

export function createPendingAuthorizationStore(): PendingAuthorizationStore {
  const pendingAuthorizations = new Map<string, PendingAuthorizationRecord>();

  return {
    savePendingAuthorization(transactionId, record) {
      pendingAuthorizations.set(transactionId, record);
    },

    loadPendingAuthorization(transactionId) {
      if (transactionId == null) {
        return undefined;
      }

      const record = pendingAuthorizations.get(transactionId);
      if (!record) {
        return undefined;
      }

      if (record.expiresAt <= Date.now()) {
        pendingAuthorizations.delete(transactionId);
        return undefined;
      }

      return record;
    },

    deletePendingAuthorization(transactionId) {
      if (transactionId == null) {
        return false;
      }

      const record = pendingAuthorizations.get(transactionId);
      if (!record) {
        return false;
      }

      // Re-check expiry at the consume point, since the transaction may have
      // expired after an earlier load but before MFA validation completed.
      if (record.expiresAt <= Date.now()) {
        pendingAuthorizations.delete(transactionId);
        return false;
      }

      return pendingAuthorizations.delete(transactionId);
    },

    recordFailedMfaAttempt(transactionId, maxAttempts) {
      if (transactionId == null) {
        return "not_found";
      }

      const record = pendingAuthorizations.get(transactionId);
      if (!record) {
        return "not_found";
      }

      // Re-check expiry before recording the attempt, since the transaction may
      // have expired after the route initially loaded it.
      if (record.expiresAt <= Date.now()) {
        pendingAuthorizations.delete(transactionId);
        return "not_found";
      }

      const failedAttempts = record.mfaFailedAttempts + 1;
      if (failedAttempts >= maxAttempts) {
        // Incrementing and deleting are synchronous so the final attempt cannot
        // race with another request in this process and leave the transaction usable.
        pendingAuthorizations.delete(transactionId);
        return "exhausted";
      }

      record.mfaFailedAttempts = failedAttempts;
      return "recorded";
    },

    isEmpty() {
      return pendingAuthorizations.size === 0;
    },
  };
}

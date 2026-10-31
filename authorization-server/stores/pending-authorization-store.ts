import type { AuthorizationRequest } from "../types/authorization-request.ts";

export type PendingAuthorizationRecord = {
  authorizationRequest: AuthorizationRequest;
  subject: string;
  /** Unix time in ms */
  expiresAt: number;
};

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
      return pendingAuthorizations.delete(transactionId);
    },

    isEmpty() {
      return pendingAuthorizations.size === 0;
    },
  };
}

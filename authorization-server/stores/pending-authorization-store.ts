import type { AuthorizationRequest } from "../types/authorization-request.ts";
import type { AuthenticationMethodReference } from "../types/authentication-method-reference.ts";
import { randomUUID } from "node:crypto";

export type PendingAuthorizationRecord = {
  /**
   * Stage authorization is on.
   */
  stage: "login" | "mfa";
  /**
   * Original authorization reques submitted.
   */
  authorizationRequest: AuthorizationRequest;
  /**
   * User ID associated with the pending authorization. May be empty before we learn the user.
   */
  userId?: string;
  /**
   * What authentication methods were used as part of this authorization request. Can be added
   * to as the transaction progresses.
   */
  amr: AuthenticationMethodReference[];
  /**
   * Unix time in ms
   */
  expiresAt: number;
  /**
   * The number of times an MFA attempt has failed for this pending authorization.
   */
  mfaFailedAttempts: number;
  /**
   * Whether auth_time is a required claim on the token response.
   */
  requiresAuthTime: boolean;
};

/**
 * Result of applying an atomic pending-authorization update:
 * - `updated`: the callback returned a replacement record and it was saved.
 * - `deleted`: the callback requested that the transaction be removed.
 * - `not_found`: the transaction is missing or expired.
 * - `invalid_stage`: the transaction exists but is not in the expected stage.
 */
export type UpdatePendingAuthorizationResult =
  | "updated"
  | "deleted"
  | "not_found"
  | "invalid_stage";

/**
 * This is a store for saving the state of pending authorization requests. I.e. authorization requests that
 * have started but not yet completed, e.g. waiting for login or MFA.
 */
export type PendingAuthorizationStore = {
  /**
   * Create a new pending authorization record.
   *
   * @returns The transaction ID this record corresponds to.
   */
  newPendingAuthorization(record: PendingAuthorizationRecord): string;

  /**
   * Load a pending authorization record.
   * If the record has expired will be removed and return undefined.
   *
   * @param transactionId Transaction ID of the record to load.
   */
  loadPendingAuthorization(
    transactionId: string | null | undefined,
  ): PendingAuthorizationRecord | undefined;

  /**
   * Delete a pending authorization record.
   *
   * @param transactionId Transaction ID of the record to delete.
   * @returns True if the delete was successful. Note if a record expired it does not count as a successful delete
   * if the record no longer exists or was expired. This is important, because it gives you a final change to deny
   * a request due to a missing authorization record, which may have been consumed by another request, preventing
   * race conditions allowing a transaction to be used twice.
   */
  deletePendingAuthorization(transactionId: string | null | undefined): boolean;

  /**
   * Atomically updates a pending authorization record.
   *
   * @param transactionId Transaction ID to update.
   * @param expectedStage Expected current stage; the update is rejected when it does not match.
   * @param update Callback to update the record. Note this must be synchronous to ensure an atomic update.
   * Return a new PendingAuthorizationRecord if updating, or "delete" if the record should be deleted.
   * @returns
   * - `"updated"`: The record was successfully updated.
   * - `"deleted"`: The record was successfully removed.
   * - `"not_found"`: The transaction is missing or expired.
   * - `"invalid_stage"`: The transaction stage does not match.
   */
  updatePendingAuthorization(
    transactionId: string | null | undefined,
    expectedStage: PendingAuthorizationRecord["stage"],
    update: (
      record: Readonly<PendingAuthorizationRecord>,
    ) => PendingAuthorizationRecord | "delete",
  ): UpdatePendingAuthorizationResult;

  /**
   * Returns true if there are no pending authorization records.
   */
  isEmpty(): boolean;
};

export function createPendingAuthorizationStore(): PendingAuthorizationStore {
  const pendingAuthorizations = new Map<string, PendingAuthorizationRecord>();

  return {
    newPendingAuthorization(record) {
      let transactionId: string;
      do {
        transactionId = randomUUID();
      } while (pendingAuthorizations.has(transactionId));

      pendingAuthorizations.set(transactionId, record);
      return transactionId;
    },

    updatePendingAuthorization(transactionId, expectedStage, update) {
      if (transactionId == null) {
        return "not_found";
      }

      const currentRecord = pendingAuthorizations.get(transactionId);
      if (!currentRecord) {
        return "not_found";
      }

      if (currentRecord.expiresAt <= Date.now()) {
        pendingAuthorizations.delete(transactionId);
        return "not_found";
      }

      if (currentRecord.stage !== expectedStage) {
        return "invalid_stage";
      }

      const updatedRecord = update(currentRecord);
      if (updatedRecord === "delete") {
        pendingAuthorizations.delete(transactionId);
        return "deleted";
      }

      pendingAuthorizations.set(transactionId, updatedRecord);
      return "updated";
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

    isEmpty() {
      return pendingAuthorizations.size === 0;
    },
  };
}

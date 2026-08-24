/** Explicit outcome handling and durable recovery with the Auths local agent. */

import { connect } from "@auths-dev/sdk";
import { Stripe } from "@auths-dev/profile-stripe";

/**
 * Secret store that durably copies and atomically replaces encoded handles
 * before `save` resolves, and deletes them only after a terminal outcome.
 * @typedef {{ save(operationId: string, encoded: ReturnType<import("@auths-dev/sdk").RecoveryHandle["toBytes"]>): Promise<void>, delete(operationId: string): Promise<void> }} RecoveryStore
 */

/**
 * Create one refund. Keep `refundRequestId` stable only across retries of that
 * one intended refund, and supply a deployment secret store for recovery data.
 *
 * @param {RecoveryStore} recoveryStore
 * @param {string} refundRequestId
 */
export async function createRefund(recoveryStore, refundRequestId) {
  const session = await connect();
  try {
    const refunds = new Stripe(session, { connection: "billing" }).refunds;
    let outcome = await refunds.createOutcome(
      {
        paymentIntent: "pi_123",
        amount: 2_000,
        currency: "usd",
      },
      { idempotencyKey: refundRequestId },
    );

    let pendingRecoveryOperation = null;
    if (outcome.kind === "recovery-required") {
      await saveRecovery(recoveryStore, outcome.operationId, outcome.recovery);
      pendingRecoveryOperation = outcome.operationId;
      outcome = await refunds.recoverOutcome(outcome.recovery);
    }

    switch (outcome.kind) {
      case "completed":
        if (pendingRecoveryOperation !== null) {
          await recoveryStore.delete(pendingRecoveryOperation);
        }
        console.log("refund", outcome.value.id);
        console.log(
          "operation",
          outcome.value.auths.operationId,
          outcome.value.auths.completion,
        );
        console.log("receipts", ...outcome.value.auths.receiptIds);
        return;
      case "recovery-required":
        await saveRecovery(recoveryStore, outcome.operationId, outcome.recovery);
        console.log("recovery queued", outcome.operationId, ...outcome.receiptIds);
        return;
      case "receipt-integrity-failed":
        console.error(
          "receipt integrity failure; contact the Auths operator/support",
          outcome.operationId,
          outcome.state,
          outcome.effect,
          outcome.terminal,
          outcome.issue.code,
        );
        return;
      case "conflict":
        await saveRecovery(recoveryStore, outcome.operationId, outcome.recovery);
        throw new Error(
          `refund conflict for original operation ${outcome.operationId}: ${outcome.issue.code}`,
        );
      case "denied":
        if (pendingRecoveryOperation !== null) {
          await recoveryStore.delete(pendingRecoveryOperation);
        }
        throw new Error(
          `refund denied for operation ${outcome.operationId}: ${outcome.issue.code}`,
        );
      case "unavailable":
        throw new Error(
          `refund unavailable before effect (operation=${outcome.operationId}): ${outcome.issue.code}`,
        );
      case "not-applied":
        if (pendingRecoveryOperation !== null) {
          await recoveryStore.delete(pendingRecoveryOperation);
        }
        throw new Error(
          `refund proven not applied for operation ${outcome.operationId} (${outcome.completion}): ${outcome.issue.code}`,
        );
      case "partial":
        if (pendingRecoveryOperation !== null) {
          await recoveryStore.delete(pendingRecoveryOperation);
        }
        throw new Error(
          `refund partially applied for operation ${outcome.operationId} (${outcome.completion}): ${outcome.issue.code}`,
        );
      default:
        throw new Error("unrecognized Auths outcome");
    }
  } finally {
    await session.close();
  }
}

async function saveRecovery(store, operationId, recovery) {
  const encoded = recovery.toBytes();
  try {
    await store.save(operationId, encoded);
  } finally {
    encoded.fill(0);
  }
}

// The application bootstrap calls createRefund with its deployment secret store.

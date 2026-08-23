/** Installed-package consumer proving cross-language replay and conflict safety. */

import { readFile } from "node:fs/promises";
import { connect } from "@auths-dev/sdk";
import { pinnedReceiptTrust, createVerifier } from "@auths-dev/sdk/verify";
import { Stripe } from "@auths-dev/profile-stripe";

const [readyPath, expectedPath] = process.argv.slice(2);
if (readyPath === undefined || expectedPath === undefined) {
  throw new TypeError("usage: typescript_consumer.mjs READY EXPECTED");
}
const ready = JSON.parse(await readFile(readyPath, "utf8"));
const expected = JSON.parse(await readFile(expectedPath, "utf8"));
const anchors = ready.receiptTrustAnchors.map((row) => Object.freeze({
  role: row.role,
  principal: row.principal,
  verificationMethod: row.verificationMethod,
  suite: row.suite,
  publicKey: new Uint8Array(Buffer.from(row.publicKeyBase64Url, "base64url")),
}));
const trust = await pinnedReceiptTrust({
  anchors,
  allowedProfiles: [{ id: "auths.stripe.refund", version: 1 }],
});
const verifier = await createVerifier();
const session = await connect({ agentSocket: ready.agentSocket });
try {
const pending = await session.operations.pending();
if (pending.length !== 0) throw new Error("fresh testkit state reported pending operations");
const stripe = new Stripe(session, { connection: ready.connection });
const options = Object.freeze({ idempotencyKey: "testkit.stripe-refund.v1" });
const replay = await stripe.refunds.createOutcome({
  paymentIntent: "pi_testkit_123",
  amount: 2_000,
  currency: "usd",
}, options);
if (replay.kind !== "completed" || replay.value.auths.completion !== "replayed") {
  throw new Error(`expected replayed completion, got ${replay.kind}`);
}
const projection = {
  refundId: replay.value.id,
  operationId: replay.value.auths.operationId,
  receiptIds: [...replay.value.auths.receiptIds],
};
if (projection.refundId !== expected.refundId ||
    projection.operationId !== expected.operationId ||
    JSON.stringify(projection.receiptIds) !== JSON.stringify(expected.receiptIds)) {
  throw new Error("cross-language replay changed the terminal result");
}
const receipts = await session.operations.receipts(projection.operationId);
if (receipts.length !== 2 || receipts.some((receipt, index) => receipt.id !== projection.receiptIds[index])) {
  throw new Error("receipt IDs differ from generated success metadata");
}
for (const receipt of receipts) {
  if (verifier.verifyReceipt({ receipt, trust }).kind !== "verified") {
    throw new Error("portable receipt did not verify");
  }
}

const conflict = await stripe.refunds.createOutcome({
  paymentIntent: "pi_testkit_123",
  amount: 2_001,
  currency: "usd",
}, options);
if (conflict.kind !== "conflict" ||
    conflict.operationId !== projection.operationId ||
    conflict.issue.effect !== "possible" ||
    JSON.stringify(conflict.receiptIds) !== JSON.stringify(projection.receiptIds)) {
  throw new Error("same-key changed-input conflict lost the original effect state");
}
console.log(JSON.stringify({ language: "typescript", mode: "replay-and-conflict", ...projection }));
} finally {
  await session.close();
}

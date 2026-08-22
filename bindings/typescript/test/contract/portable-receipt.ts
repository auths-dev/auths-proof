import type { Receipt } from "../../src/index.js";
import type { ReceiptTrustPolicy, ReceiptVerificationInput } from "../../src/verify.js";

declare const receipt: Receipt;
declare const trust: ReceiptTrustPolicy;

const standalone: ReceiptVerificationInput = { receipt, trust };
void standalone;

const legacyLinkedInput: ReceiptVerificationInput = {
  receipt,
  trust,
  // @ts-expect-error auths.portable-receipt/1 embeds its linked decision
  linkedDecisionReceipt: receipt,
};
void legacyLinkedInput;

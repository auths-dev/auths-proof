export type SigningObjectKind = "grant" | "action" | "principal-status" | "grant-status";
export type CustodyLifecycle = "durable" | "ephemeral";
export type CustodyKind = "webauthn" | "workload" | "kms" | "hsm" | "pkcs11";
export type CustodyKeyState = "enrolled" | "ready" | "rotation-pending" | "active-current" | "retiring-previous" | "revoked" | "disabled" | "unavailable" | "indeterminate";
export type CustodyFailure = "denied" | "cancelled" | "throttled" | "unavailable" | "revoked-key" | "disabled-key" | "provider-unknown" | "invalid-provider-response";

export interface CustodySignatureDescriptor { readonly principalMethod: string; readonly verificationMethod: string; readonly suite: string }
export interface CustodyDescriptor {
  readonly contract: "signer-custody/2";
  readonly kind: CustodyKind;
  readonly adapterId: string;
  readonly principal: string;
  readonly signature: CustodySignatureDescriptor;
  readonly keyVersion: string;
  readonly keyState: CustodyKeyState;
  readonly lifecycle: CustodyLifecycle;
}
export interface ReviewField { readonly label: string; readonly value: string }
export interface PublicControlEvidence { readonly type: string; readonly mediaType: string; readonly bytes: Uint8Array }
export interface SigningRequest {
  readonly requestId: string;
  readonly objectKind: SigningObjectKind;
  readonly objectId: Uint8Array;
  readonly descriptor: CustodyDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signingPreimage: Uint8Array;
  readonly expiresAtUnixSeconds: bigint;
  readonly display: readonly ReviewField[];
  readonly signal: AbortSignal;
}
export interface SigningResponse {
  readonly requestId: string;
  readonly objectId: Uint8Array;
  readonly principal: string;
  readonly descriptor: CustodySignatureDescriptor;
  readonly providerKeyVersion: string;
  readonly transactionDigest: Uint8Array;
  readonly signature: Uint8Array;
  readonly evidence: readonly PublicControlEvidence[];
}
export type CustodySignResult =
  | Readonly<{ kind: "signed"; response: SigningResponse }>
  | Readonly<{ kind: "rejected"; failure: Extract<CustodyFailure, "denied" | "cancelled" | "revoked-key" | "disabled-key"> }>
  | Readonly<{ kind: "indeterminate"; failure: Extract<CustodyFailure, "throttled" | "unavailable" | "provider-unknown" | "invalid-provider-response"> }>;
export interface CustodySigner extends AsyncDisposable {
  readonly descriptor: CustodyDescriptor;
  sign(request: SigningRequest): Promise<CustodySignResult>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export interface ReservationRecord { readonly key: string; readonly commitment: Uint8Array; readonly value: Uint8Array }
export type ReservationDecision = "acquired" | "exact-replay" | "conflict";
export interface ReservationStore extends AsyncDisposable {
  readonly contract: "atomic-reservation-store/2";
  readonly kind: string;
  readonly durability: "ephemeral" | "single-machine-durable";
  reserve(record: ReservationRecord, options: Readonly<{ signal: AbortSignal }>): Promise<ReservationDecision>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

import {
  AuthsWorkflowError,
  ProviderOperationError,
  type ApprovalConfiguration,
  type ApprovalPolicyReference,
  type ControlEvidence,
  type PrincipalDescriptor,
  type ReviewField,
  type Signer,
  type SigningObjectKind,
  type WorkflowWasmEngine,
  bytesEqual,
  boundedIdentifier,
  copyPolicy,
  copyPrincipal,
  policiesEqual,
} from "../workflow.js";

const MAX_DISPLAY_FIELDS = 32;
const MAX_DISPLAY_FIELD_BYTES = 4 * 1024;
const MAX_DISPLAY_BYTES = 64 * 1024;
const MAX_SIGNATURE_BYTES = 512;
const MAX_EVIDENCE = 32;
const MAX_EVIDENCE_BYTES = 64 * 1024;
const MAX_AUTHORING_BYTES = 16 * 1024 * 1024;

export interface NativeSigningRequest {
  readonly objectKind: string;
  readonly objectId: Uint8Array;
  readonly signingPreimage: Uint8Array;
  free?(): void;
}

export interface NativeSigningAdapter {
  prepare(
    objectKind: SigningObjectKind,
    unsignedObject: Uint8Array,
    principal: PrincipalDescriptor,
  ): NativeSigningRequest;
  complete(
    objectKind: SigningObjectKind,
    unsignedObject: Uint8Array,
    principal: PrincipalDescriptor,
    signature: Uint8Array,
  ): Uint8Array;
}

export class WasmSigningAdapter implements NativeSigningAdapter {
  readonly #engine: WorkflowWasmEngine;

  constructor(engine: WorkflowWasmEngine) {
    this.#engine = engine;
  }

  prepare(
    objectKind: SigningObjectKind,
    unsignedObject: Uint8Array,
    principal: PrincipalDescriptor,
  ): NativeSigningRequest {
    const argumentsTail = [
      principal.principalMethod,
      principal.verificationMethod,
      principal.suite,
    ] as const;
    switch (objectKind) {
      case "grant":
        return this.#engine.prepareGrantSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
      case "action":
        return this.#engine.prepareActionSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
      case "principal-status":
        return this.#engine.preparePrincipalStatusSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
      case "grant-status":
        return this.#engine.prepareGrantStatusSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
    }
  }

  complete(
    objectKind: SigningObjectKind,
    unsignedObject: Uint8Array,
    principal: PrincipalDescriptor,
    signature: Uint8Array,
  ): Uint8Array {
    const argumentsTail = [
      principal.principalMethod,
      principal.verificationMethod,
      principal.suite,
      signature,
    ] as const;
    switch (objectKind) {
      case "grant":
        return this.#engine.completeGrantSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
      case "action":
        return this.#engine.completeActionSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
      case "principal-status":
        return this.#engine.completePrincipalStatusSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
      case "grant-status":
        return this.#engine.completeGrantStatusSigningV1(
          unsignedObject,
          ...argumentsTail,
        );
    }
  }
}

export interface SigningTransactionOptions {
  readonly objectKind: SigningObjectKind;
  readonly unsignedObject: Uint8Array;
  readonly principal: PrincipalDescriptor;
  readonly signer: Signer;
  readonly approval: ApprovalConfiguration;
  readonly requiredApproval: ApprovalPolicyReference;
  readonly expiresAt: bigint;
  readonly display: readonly ReviewField[];
}

export interface SignedTransaction {
  readonly signedObject: Uint8Array;
  readonly transactionDigest: Uint8Array;
  readonly evidence: readonly ControlEvidence[];
}

export class SigningCoordinator {
  #consumed = false;
  readonly #adapter: NativeSigningAdapter;
  readonly #now: () => bigint;

  constructor(
    adapter: NativeSigningAdapter,
    now: () => bigint = () => BigInt(Math.floor(Date.now() / 1000)),
  ) {
    this.#adapter = adapter;
    this.#now = now;
  }

  async execute(
    options: SigningTransactionOptions,
  ): Promise<SignedTransaction> {
    if (this.#consumed) {
      throw new AuthsWorkflowError(
        "transaction-consumed",
        "signing transaction has already reached a terminal state",
      );
    }
    this.#consumed = true;
    if (this.#now() > options.expiresAt) {
      throw new AuthsWorkflowError(
        "transaction-expired",
        "signing transaction expired before provider use",
      );
    }

    const unsignedObject = boundedBytes(options.unsignedObject, "unsigned object");
    const principal = copyPrincipal(options.principal);
    const display = copyDisplay(options.display);
    const requiredApproval = copyPolicy(options.requiredApproval);
    const executedApproval = copyPolicy(options.approval.policy);
    if (
      !["grant-only", "risk-based", "every-action", "plan-once", "headless", "custom"].includes(
        options.approval.mode,
      ) ||
      typeof options.approval.provider?.approve !== "function"
    ) {
      throw new AuthsWorkflowError(
        "invalid-provider",
        "approval configuration does not implement a supported mode",
      );
    }
    if (!policiesEqual(requiredApproval, executedApproval)) {
      throw new AuthsWorkflowError(
        "approval-policy-mismatch",
        "executed approval policy does not match the committed requirement",
      );
    }

    let native: NativeSigningRequest;
    try {
      native = this.#adapter.prepare(
        options.objectKind,
        unsignedObject.slice(),
        principal,
      );
    } catch {
      throw new AuthsWorkflowError(
        "invalid-provider",
        "native authoring rejected the signing transaction",
      );
    }

    try {
      if (native.objectKind !== options.objectKind) {
        throw new AuthsWorkflowError(
          "signer-response-mismatch",
          "native authoring returned a different object kind",
        );
      }
      const objectId = copyExactObjectId(native.objectId);
      const signingPreimage = boundedBytes(
        native.signingPreimage,
        "signing preimage",
      );
      const transactionDigest = new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new Uint8Array(signingPreimage).buffer,
        ),
      );
      const requestId = `${options.objectKind}:${hex(objectId)}:${hex(transactionDigest)}`;

      await approveExact(
        options,
        requiredApproval,
        requestId,
        transactionDigest,
        display,
        this.#now,
      );
      if (this.#now() > options.expiresAt) {
        throw new AuthsWorkflowError(
          "transaction-expired",
          "signing transaction expired before signer use",
        );
      }

      const response = await callSigner(options.signer, {
        requestId,
        objectKind: options.objectKind,
        objectId: objectId.slice(),
        principal: copyPrincipal(principal),
        transactionDigest: transactionDigest.slice(),
        signingPreimage: signingPreimage.slice(),
        expiresAt: options.expiresAt,
        display: copyDisplay(display),
      });
      const { signature, evidence } = consumeSigningResponse(
        response,
        requestId,
        principal,
        transactionDigest,
      );
      let signedObject: Uint8Array;
      try {
        signedObject = boundedBytes(
          this.#adapter.complete(
            options.objectKind,
            unsignedObject.slice(),
            principal,
            signature.slice(),
          ),
          "signed object",
        );
      } catch {
        throw new AuthsWorkflowError(
          "invalid-provider",
          "native authoring rejected signing completion",
        );
      }
      return Object.freeze({
        signedObject,
        transactionDigest: transactionDigest.slice(),
        evidence,
      });
    } finally {
      native.free?.();
    }
  }
}

async function approveExact(
  options: SigningTransactionOptions,
  policy: ApprovalPolicyReference,
  requestId: string,
  transactionDigest: Uint8Array,
  display: readonly ReviewField[],
  now: () => bigint,
): Promise<void> {
  let response;
  try {
    response = await options.approval.provider.approve({
      requestId,
      objectKind: options.objectKind,
      transactionDigest: transactionDigest.slice(),
      policy: copyPolicy(policy),
      expiresAt: options.expiresAt,
      display: copyDisplay(display),
    });
  } catch (error) {
    if (error instanceof ProviderOperationError) {
      const code =
        error.kind === "rejected" ? "approval-rejected" :
        error.kind === "cancelled" ? "approval-cancelled" :
        error.kind === "timeout" ? "approval-timeout" :
        error.kind === "unsupported" ? "approval-unsupported" :
        "approval-failed";
      throw new AuthsWorkflowError(code, "approval provider failed");
    }
    throw new AuthsWorkflowError(
      "approval-failed",
      "approval provider failed",
    );
  }
  if (now() > options.expiresAt) {
    throw new AuthsWorkflowError(
      "transaction-expired",
      "signing transaction expired during approval",
    );
  }
  try {
    if (
      response !== null &&
      typeof response === "object" &&
      response.decision === "rejected"
    ) {
      throw new AuthsWorkflowError(
        "approval-rejected",
        "approval provider rejected the signing transaction",
      );
    }
    if (
      response === null ||
      typeof response !== "object" ||
      response.decision !== "approved" ||
      response.requestId !== requestId ||
      !bytesEqual(response.transactionDigest, transactionDigest) ||
      !policiesEqual(response.policy, policy)
    ) {
      throw new Error("approval mismatch");
    }
  } catch (error) {
    if (
      error instanceof AuthsWorkflowError &&
      error.code === "approval-rejected"
    ) {
      throw error;
    }
    throw new AuthsWorkflowError(
      "approval-response-mismatch",
      "approval response is not bound to the exact transaction",
    );
  }
}

async function callSigner(
  signer: Signer,
  request: Parameters<Signer["sign"]>[0],
): Promise<Awaited<ReturnType<Signer["sign"]>>> {
  try {
    return await signer.sign(request);
  } catch (error) {
    if (error instanceof ProviderOperationError) {
      const code =
        error.kind === "rejected" ? "signer-rejected" :
        error.kind === "cancelled" ? "signer-cancelled" :
        error.kind === "timeout" ? "signer-timeout" :
        error.kind === "unsupported" ? "signer-unsupported" :
        "signer-failed";
      throw new AuthsWorkflowError(code, "signer provider failed");
    }
    throw new AuthsWorkflowError("signer-failed", "signer provider failed");
  }
}

function validateSigningResponse(
  response: Awaited<ReturnType<Signer["sign"]>>,
  requestId: string,
  principal: PrincipalDescriptor,
  transactionDigest: Uint8Array,
): void {
  if (
    response === null ||
    typeof response !== "object" ||
    response.requestId !== requestId ||
    !(response.transactionDigest instanceof Uint8Array) ||
    !bytesEqual(response.transactionDigest, transactionDigest)
  ) {
    throw new AuthsWorkflowError(
      "signer-response-mismatch",
      "signer response is not bound to the exact transaction",
    );
  }
  try {
    if (!principalsEqual(copyPrincipal(response.principal), principal)) {
      throw new Error("principal mismatch");
    }
  } catch {
    throw new AuthsWorkflowError(
      "signer-response-mismatch",
      "signer response is not bound to the exact transaction",
    );
  }
}

function consumeSigningResponse(
  response: Awaited<ReturnType<Signer["sign"]>>,
  requestId: string,
  principal: PrincipalDescriptor,
  transactionDigest: Uint8Array,
): { signature: Uint8Array; evidence: readonly ControlEvidence[] } {
  try {
    validateSigningResponse(
      response,
      requestId,
      principal,
      transactionDigest,
    );
    return {
      signature: boundedSignature(response.signature),
      evidence: copyEvidence(response.evidence ?? []),
    };
  } catch (error) {
    if (
      error instanceof AuthsWorkflowError &&
      error.code === "signer-response-mismatch"
    ) {
      throw error;
    }
    throw new AuthsWorkflowError(
      "signer-response-mismatch",
      "signer response is not bound to the exact transaction",
    );
  }
}

function principalsEqual(
  left: PrincipalDescriptor,
  right: PrincipalDescriptor,
): boolean {
  return (
    left.principal === right.principal &&
    left.principalMethod === right.principalMethod &&
    left.verificationMethod === right.verificationMethod &&
    left.suite === right.suite
  );
}

function boundedBytes(value: Uint8Array, label: string): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > MAX_AUTHORING_BYTES
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} must be a non-empty byte array`,
    );
  }
  return value.slice();
}

function copyExactObjectId(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "native authoring returned an invalid object identifier",
    );
  }
  return value.slice();
}

function boundedSignature(value: Uint8Array): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > MAX_SIGNATURE_BYTES
  ) {
    throw new AuthsWorkflowError(
      "signer-response-mismatch",
      "signer returned an invalid signature length",
    );
  }
  return value.slice();
}

function copyEvidence(
  value: readonly ControlEvidence[],
): readonly ControlEvidence[] {
  if (!Array.isArray(value) || value.length > MAX_EVIDENCE) {
    throw new AuthsWorkflowError(
      "signer-response-mismatch",
      "signer evidence exceeds the supported count",
    );
  }
  let total = 0;
  const result = value.map((item) => {
    if (
      item === null ||
      typeof item !== "object" ||
      !(item.bytes instanceof Uint8Array) ||
      item.bytes.length === 0
    ) {
      throw new AuthsWorkflowError(
        "signer-response-mismatch",
        "signer evidence contains an invalid item",
      );
    }
    total += item.bytes.length;
    return Object.freeze({
      evidenceType: boundedIdentifier(item.evidenceType, "evidence type"),
      mediaType: boundedIdentifier(item.mediaType, "evidence media type"),
      bytes: item.bytes.slice(),
    });
  });
  if (total > MAX_EVIDENCE_BYTES) {
    throw new AuthsWorkflowError(
      "signer-response-mismatch",
      "signer evidence exceeds the supported byte bound",
    );
  }
  return Object.freeze(result);
}

function copyDisplay(value: readonly ReviewField[]): readonly ReviewField[] {
  if (!Array.isArray(value) || value.length > MAX_DISPLAY_FIELDS) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval display exceeds the supported field count",
    );
  }
  let aggregate = 0;
  const display = value.map((field) => {
    if (field === null || typeof field !== "object") {
      throw new AuthsWorkflowError(
        "invalid-provider",
        "approval display contains an invalid field",
      );
    }
    const label = boundedDisplay(field.label, "approval display label");
    const fieldValue = boundedDisplay(field.value, "approval display value");
    aggregate += new TextEncoder().encode(label).length;
    aggregate += new TextEncoder().encode(fieldValue).length;
    return Object.freeze({ label, value: fieldValue });
  });
  if (aggregate > MAX_DISPLAY_BYTES) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval display exceeds the supported byte bound",
    );
  }
  return Object.freeze(display);
}

function boundedDisplay(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > MAX_DISPLAY_FIELD_BYTES
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} is outside the supported byte bound`,
    );
  }
  return value;
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

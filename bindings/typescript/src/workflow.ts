const MAX_IDENTIFIER_BYTES = 128;
const DIGEST_BYTES = 32;

export type SignerLifecycle = "durable" | "ephemeral";
export type SigningObjectKind =
  | "grant"
  | "action"
  | "principal-status"
  | "grant-status";
export type ApprovalMode =
  | "grant-only"
  | "risk-based"
  | "every-action"
  | "custom";

export interface PrincipalDescriptor {
  readonly principal: string;
  readonly principalMethod: string;
  readonly verificationMethod: string;
  readonly suite: string;
}

export interface ReviewField {
  readonly label: string;
  readonly value: string;
}

export interface SigningRequest {
  readonly requestId: string;
  readonly objectKind: SigningObjectKind;
  readonly objectId: Uint8Array;
  readonly principal: PrincipalDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signingPreimage: Uint8Array;
  readonly expiresAt: bigint;
  readonly display: readonly ReviewField[];
}

export interface SigningResponse {
  readonly requestId: string;
  readonly principal: PrincipalDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signature: Uint8Array;
  readonly evidence?: readonly Uint8Array[];
}

export interface Signer {
  readonly kind: string;
  readonly lifecycle: SignerLifecycle;
  publicIdentity(): Promise<PrincipalDescriptor>;
  sign(request: SigningRequest): Promise<SigningResponse>;
  dispose?(): Promise<void>;
}

export interface ApprovalPolicyReference {
  readonly policyId: string;
  readonly evaluatorVersion: string;
  readonly configurationDigest: Uint8Array;
}

export interface ApprovalRequest {
  readonly requestId: string;
  readonly objectKind: SigningObjectKind;
  readonly transactionDigest: Uint8Array;
  readonly policy: ApprovalPolicyReference;
  readonly expiresAt: bigint;
  readonly display: readonly ReviewField[];
}

export interface ApprovalResponse {
  readonly requestId: string;
  readonly transactionDigest: Uint8Array;
  readonly policy: ApprovalPolicyReference;
  readonly decision: "approved" | "rejected";
}

export interface ApprovalProvider {
  approve(request: ApprovalRequest): Promise<ApprovalResponse>;
}

export interface ApprovalConfiguration {
  readonly mode: ApprovalMode;
  readonly policy: ApprovalPolicyReference;
  readonly provider: ApprovalProvider;
}

export interface TrustedAuthority {
  readonly authorityId: string;
  readonly verifierConfiguration: Uint8Array;
  readonly requiredApproval: ApprovalPolicyReference;
}

export interface AgentIdentity {
  readonly principal: PrincipalDescriptor;
  readonly signerKind: string;
  readonly signerLifecycle: SignerLifecycle;
}

export interface TrustedAuthoritySnapshot {
  readonly authorityId: string;
  readonly verifierConfiguration: Uint8Array;
  readonly requiredApproval: ApprovalPolicyReference;
}

export type WorkflowErrorCode =
  | "disposed"
  | "invalid-provider"
  | "invalid-principal"
  | "configuration-mismatch"
  | "approval-policy-mismatch"
  | "approval-failed"
  | "approval-cancelled"
  | "approval-timeout"
  | "approval-unsupported"
  | "approval-rejected"
  | "approval-response-mismatch"
  | "signer-failed"
  | "signer-rejected"
  | "signer-cancelled"
  | "signer-timeout"
  | "signer-unsupported"
  | "signer-response-mismatch"
  | "transaction-expired"
  | "transaction-consumed";

export class AuthsWorkflowError extends Error {
  readonly code: WorkflowErrorCode;

  constructor(code: WorkflowErrorCode, message: string) {
    super(message);
    this.name = "AuthsWorkflowError";
    this.code = code;
  }
}

export type ProviderFailureKind =
  | "unavailable"
  | "rejected"
  | "cancelled"
  | "timeout"
  | "unsupported";

export class ProviderOperationError extends Error {
  readonly kind: ProviderFailureKind;

  constructor(kind: ProviderFailureKind) {
    super("external provider operation failed");
    this.name = "ProviderOperationError";
    this.kind = kind;
  }
}

export interface WorkflowWasmEngine {
  authoringAbiVersionV1(): number;
  canonicalPrincipalV1(principal: string): string;
  configurationV1(): Uint8Array;
  prepareGrantSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  prepareActionSigningV1(
    action: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  preparePrincipalStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  prepareGrantStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  completeGrantSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
  completeActionSigningV1(
    action: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
  completePrincipalStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
  completeGrantStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
}

export interface WorkflowNativeSigningRequest {
  readonly objectKind: string;
  readonly objectId: Uint8Array;
  readonly signingPreimage: Uint8Array;
  free?(): void;
}

interface ClientResources {
  readonly signer: Signer;
  readonly engine: WorkflowWasmEngine;
  readonly identity: AgentIdentity;
  readonly trustedAuthority: TrustedAuthoritySnapshot;
}

const clientResources = new WeakMap<AuthsClient, ClientResources>();
const CLIENT_TOKEN: unique symbol = Symbol("auths-workflow-client");

export class AuthsClient implements AsyncDisposable {
  readonly #identity: AgentIdentity;
  readonly #trustedAuthority: TrustedAuthoritySnapshot;
  #disposed = false;

  private constructor(
    token: typeof CLIENT_TOKEN,
    identity: AgentIdentity,
    trustedAuthority: TrustedAuthoritySnapshot,
    signer: Signer,
    engine: WorkflowWasmEngine,
  ) {
    if (token !== CLIENT_TOKEN) {
      throw new TypeError("sealed Auths workflow client");
    }
    this.#identity = identity;
    this.#trustedAuthority = trustedAuthority;
    clientResources.set(this, {
      signer,
      engine,
      identity,
      trustedAuthority,
    });
  }

  static create(
    token: typeof CLIENT_TOKEN,
    identity: AgentIdentity,
    trustedAuthority: TrustedAuthoritySnapshot,
    signer: Signer,
    engine: WorkflowWasmEngine,
  ): AuthsClient {
    if (token !== CLIENT_TOKEN) {
      throw new TypeError("sealed Auths workflow client");
    }
    return new AuthsClient(
      token,
      identity,
      trustedAuthority,
      signer,
      engine,
    );
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  get identity(): AgentIdentity {
    return this.#identity;
  }

  get trustedAuthority(): TrustedAuthoritySnapshot {
    return copyTrustedAuthority(this.#trustedAuthority);
  }

  assertActive(): void {
    if (this.#disposed) {
      throw new AuthsWorkflowError("disposed", "Auths client is disposed");
    }
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    const resources = clientResources.get(this);
    clientResources.delete(this);
    if (resources?.signer.dispose !== undefined) {
      try {
        await resources.signer.dispose();
      } catch {
        throw new AuthsWorkflowError(
          "signer-failed",
          "signer provider cleanup failed",
        );
      }
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose();
  }
}

export interface LoadWorkflowOptions {
  readonly signer: Signer;
  readonly trustedAuthority: TrustedAuthority;
}

export async function createWorkflowClient(
  options: LoadWorkflowOptions,
  engine: WorkflowWasmEngine,
): Promise<AuthsClient> {
  validateSignerShape(options.signer);
  let trustedAuthority: TrustedAuthoritySnapshot;
  try {
    trustedAuthority = copyTrustedAuthority(options.trustedAuthority);
    if (engine.authoringAbiVersionV1() !== 1) {
      throw new AuthsWorkflowError(
        "invalid-provider",
        "Auths WASM authoring ABI is unsupported",
      );
    }
    const engineConfiguration = copyExactBytes(
      engine.configurationV1(),
      DIGEST_BYTES,
      "verifier configuration",
    );
    if (
      !bytesEqual(
        engineConfiguration,
        trustedAuthority.verifierConfiguration,
      )
    ) {
      throw new AuthsWorkflowError(
        "configuration-mismatch",
        "trusted authority requires a different verifier configuration",
      );
    }
  } catch (error) {
    await cleanupAfterFailedLoad(options.signer);
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError(
      "invalid-provider",
      "trusted authority or packaged WASM configuration is invalid",
    );
  }

  try {
    let descriptor = copyPrincipal(await options.signer.publicIdentity());
    descriptor = {
      ...descriptor,
      principal: engine.canonicalPrincipalV1(descriptor.principal),
    };

    const identity = Object.freeze({
      principal: Object.freeze(descriptor),
      signerKind: options.signer.kind,
      signerLifecycle: options.signer.lifecycle,
    });
    return AuthsClient.create(
      CLIENT_TOKEN,
      identity,
      trustedAuthority,
      options.signer,
      engine,
    );
  } catch (error) {
    await cleanupAfterFailedLoad(options.signer);
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError(
      "invalid-principal",
      "signer returned an invalid principal descriptor",
    );
  }
}

export function signerForClient(client: AuthsClient): Signer {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.signer;
}

export function engineForClient(client: AuthsClient): WorkflowWasmEngine {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.engine;
}

export function identityForClient(client: AuthsClient): AgentIdentity {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.identity;
}

export function trustedAuthorityForClient(
  client: AuthsClient,
): TrustedAuthoritySnapshot {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.trustedAuthority;
}

export function copyPrincipal(value: PrincipalDescriptor): PrincipalDescriptor {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-principal",
      "principal descriptor is missing",
    );
  }
  return {
    principal: boundedIdentifier(value.principal, "principal"),
    principalMethod: boundedIdentifier(
      value.principalMethod,
      "principal method",
    ),
    verificationMethod: boundedIdentifier(
      value.verificationMethod,
      "verification method",
    ),
    suite: boundedIdentifier(value.suite, "signature suite"),
  };
}

export function copyPolicy(
  value: ApprovalPolicyReference,
): ApprovalPolicyReference {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval policy is missing",
    );
  }
  return Object.freeze({
    policyId: boundedIdentifier(value.policyId, "approval policy"),
    evaluatorVersion: boundedIdentifier(
      value.evaluatorVersion,
      "approval evaluator version",
    ),
    configurationDigest: copyExactBytes(
      value.configurationDigest,
      DIGEST_BYTES,
      "approval configuration digest",
    ),
  });
}

export function policiesEqual(
  left: ApprovalPolicyReference,
  right: ApprovalPolicyReference,
): boolean {
  if (
    left === null ||
    right === null ||
    typeof left !== "object" ||
    typeof right !== "object" ||
    !(left.configurationDigest instanceof Uint8Array) ||
    !(right.configurationDigest instanceof Uint8Array)
  ) {
    return false;
  }
  return (
    left.policyId === right.policyId &&
    left.evaluatorVersion === right.evaluatorVersion &&
    bytesEqual(left.configurationDigest, right.configurationDigest)
  );
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) {
    return false;
  }
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function copyExactBytes(
  value: Uint8Array,
  length: number,
  label: string,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} must contain exactly ${length} bytes`,
    );
  }
  return value.slice();
}

export function boundedIdentifier(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > MAX_IDENTIFIER_BYTES ||
    !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} is outside the supported identifier bound`,
    );
  }
  return value;
}

function copyTrustedAuthority(
  value: TrustedAuthority,
): TrustedAuthoritySnapshot {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "trusted authority is missing",
    );
  }
  return Object.freeze({
    authorityId: boundedIdentifier(value.authorityId, "trusted authority"),
    verifierConfiguration: copyExactBytes(
      value.verifierConfiguration,
      DIGEST_BYTES,
      "verifier configuration",
    ),
    requiredApproval: copyPolicy(value.requiredApproval),
  });
}

function validateSignerShape(signer: Signer): void {
  if (
    signer === null ||
    typeof signer !== "object" ||
    typeof signer.publicIdentity !== "function" ||
    typeof signer.sign !== "function" ||
    !["durable", "ephemeral"].includes(signer.lifecycle)
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "signer does not implement the Auths signer port",
    );
  }
  boundedIdentifier(signer.kind, "signer kind");
}

async function cleanupAfterFailedLoad(signer: Signer): Promise<void> {
  if (signer.dispose === undefined) return;
  try {
    await signer.dispose();
  } catch {
    // Preserve the fail-closed construction error and do not expose provider data.
  }
}

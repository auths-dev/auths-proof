import { SigningCoordinator, WasmSigningAdapter } from "./internal/signing.js";
import { registerStatusSnapshot } from "./internal/lifecycle-resources.js";
import { AuthsWorkflowError } from "./workflow/errors.js";
import type {
  ApprovalConfiguration,
  ApprovalPolicyReference,
  Signer,
  WorkflowWasmEngine,
} from "./workflow.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

const DIGEST_TOKEN = Symbol("auths-protocol-digest");
const SIGNED_STATUS_TOKEN = Symbol("auths-signed-status");
const SNAPSHOT_TOKEN = Symbol("auths-status-snapshot");
const LIFECYCLE_TOKEN = Symbol("auths-lifecycle");

export type LifecycleState = "active" | "revoked" | "superseded";

export class ProtocolDigest<Kind extends string> {
  declare private readonly __kind: Kind;

  private constructor(token: typeof DIGEST_TOKEN, bytes: Uint8Array) {
    if (token !== DIGEST_TOKEN) throw new TypeError("sealed Auths protocol digest");
    protocolDigests.set(this, bytes);
    Object.freeze(this);
  }

  static parse<Kind extends string>(kind: Kind, value: string): ProtocolDigest<Kind> {
    if (!/^[0-9a-f]{64}$/.test(value)) {
      throw new AuthsWorkflowError("invalid-authority", `${kind} must be 64 lowercase hex characters`);
    }
    return new ProtocolDigest(DIGEST_TOKEN, Uint8Array.from(
      { length: 32 },
      (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
    ));
  }

}

const protocolDigests = new WeakMap<ProtocolDigest<string>, Uint8Array>();

function protocolDigestBytes(value: ProtocolDigest<string>): Uint8Array {
  const bytes = protocolDigests.get(value);
  if (bytes === undefined) throw new AuthsWorkflowError("invalid-authority", "protocol digest is forged");
  return bytes.slice();
}

export type GrantId = ProtocolDigest<"grant-id">;
export type StatusSnapshotId = ProtocolDigest<"status-snapshot-id">;
export type EvidenceId = ProtocolDigest<"evidence-id">;

export const grantId = (value: string): GrantId => ProtocolDigest.parse("grant-id", value);
export const statusSnapshotId = (value: string): StatusSnapshotId =>
  ProtocolDigest.parse("status-snapshot-id", value);
export const evidenceId = (value: string): EvidenceId => ProtocolDigest.parse("evidence-id", value);

export interface CriticalExtensionInput {
  readonly id: string;
  readonly bytes: Uint8Array;
}

export interface PrincipalStatusRequest {
  readonly method: string;
  readonly principal: string;
  readonly purpose: string;
  readonly state: LifecycleState;
  readonly sequence: bigint;
  readonly observedAt: bigint;
  readonly validUntil: bigint;
  readonly issuer: string;
  readonly extensions?: readonly CriticalExtensionInput[];
}

export interface GrantStatusRequest {
  readonly method: string;
  readonly grantId: GrantId;
  readonly state: LifecycleState;
  readonly sequence: bigint;
  readonly observedAt: bigint;
  readonly validUntil: bigint;
  readonly issuer: string;
  readonly extensions?: readonly CriticalExtensionInput[];
}

export interface LifecycleSigningOptions {
  readonly signer: Signer;
  readonly approval: ApprovalConfiguration;
  readonly requiredApproval: ApprovalPolicyReference;
  readonly expiresAt?: bigint;
}

interface SignedStatusResources {
  readonly bytes: Uint8Array;
}

const signedStatusResources = new WeakMap<object, SignedStatusResources>();

export class SignedPrincipalStatus {
  declare private readonly __principalStatus: void;

  private constructor(token: typeof SIGNED_STATUS_TOKEN, bytes: Uint8Array) {
    if (token !== SIGNED_STATUS_TOKEN) throw new TypeError("sealed Auths principal status");
    signedStatusResources.set(this, { bytes });
    Object.freeze(this);
  }

  static create(token: typeof SIGNED_STATUS_TOKEN, bytes: Uint8Array): SignedPrincipalStatus {
    return new SignedPrincipalStatus(token, bytes);
  }
}

export class SignedGrantStatus {
  declare private readonly __grantStatus: void;

  private constructor(token: typeof SIGNED_STATUS_TOKEN, bytes: Uint8Array) {
    if (token !== SIGNED_STATUS_TOKEN) throw new TypeError("sealed Auths grant status");
    signedStatusResources.set(this, { bytes });
    Object.freeze(this);
  }

  static create(token: typeof SIGNED_STATUS_TOKEN, bytes: Uint8Array): SignedGrantStatus {
    return new SignedGrantStatus(token, bytes);
  }
}

export interface StatusTrustRule {
  readonly method: string;
  readonly issuer: string;
  readonly sequenceFloor: bigint;
}

export interface PrincipalStatusSnapshotRequest {
  readonly id: StatusSnapshotId;
  readonly observedAt: bigint;
  readonly validUntil: bigint;
  readonly statements: readonly SignedPrincipalStatus[];
  readonly checkpoints?: readonly EvidenceId[];
  readonly trust?: readonly StatusTrustRule[];
}

export interface GrantStatusSnapshotRequest {
  readonly id: StatusSnapshotId;
  readonly observedAt: bigint;
  readonly validUntil: bigint;
  readonly statements: readonly SignedGrantStatus[];
  readonly checkpoints?: readonly EvidenceId[];
  readonly trust?: readonly StatusTrustRule[];
}

export class PrincipalStatusSnapshot {
  declare private readonly __principalSnapshot: void;
  readonly id: StatusSnapshotId;
  readonly statementCount: number;

  private constructor(
    token: typeof SNAPSHOT_TOKEN,
    id: StatusSnapshotId,
    statementCount: number,
    cbor: Uint8Array,
  ) {
    if (token !== SNAPSHOT_TOKEN) throw new TypeError("sealed Auths principal status snapshot");
    this.id = id;
    this.statementCount = statementCount;
    registerStatusSnapshot(this, cbor);
    Object.freeze(this);
  }

  static create(
    token: typeof SNAPSHOT_TOKEN,
    id: StatusSnapshotId,
    statementCount: number,
    cbor: Uint8Array,
  ): PrincipalStatusSnapshot {
    return new PrincipalStatusSnapshot(token, id, statementCount, cbor);
  }
}

export class GrantStatusSnapshot {
  declare private readonly __grantSnapshot: void;
  readonly id: StatusSnapshotId;
  readonly statementCount: number;

  private constructor(
    token: typeof SNAPSHOT_TOKEN,
    id: StatusSnapshotId,
    statementCount: number,
    cbor: Uint8Array,
  ) {
    if (token !== SNAPSHOT_TOKEN) throw new TypeError("sealed Auths grant status snapshot");
    this.id = id;
    this.statementCount = statementCount;
    registerStatusSnapshot(this, cbor);
    Object.freeze(this);
  }

  static create(
    token: typeof SNAPSHOT_TOKEN,
    id: StatusSnapshotId,
    statementCount: number,
    cbor: Uint8Array,
  ): GrantStatusSnapshot {
    return new GrantStatusSnapshot(token, id, statementCount, cbor);
  }
}

export class LifecycleAuthor {
  readonly #engine: WorkflowWasmEngine;
  #active = true;

  private constructor(token: typeof LIFECYCLE_TOKEN, engine: WorkflowWasmEngine) {
    if (token !== LIFECYCLE_TOKEN) throw new TypeError("sealed Auths lifecycle author");
    this.#engine = engine;
  }

  static create(token: typeof LIFECYCLE_TOKEN, engine: WorkflowWasmEngine): LifecycleAuthor {
    return new LifecycleAuthor(token, engine);
  }

  async authorPrincipalStatus(
    request: PrincipalStatusRequest,
    options: LifecycleSigningOptions,
  ): Promise<SignedPrincipalStatus> {
    this.#assertActive();
    const unsigned = this.#engine.encodePrincipalStatusStatementV1(
      request.method,
      request.principal,
      request.purpose,
      request.state,
      request.sequence,
      request.observedAt,
      request.validUntil,
      request.issuer,
      copyExtensions(request.extensions),
    );
    const bytes = await this.#sign("principal-status", request.issuer, request.validUntil, unsigned, options);
    return SignedPrincipalStatus.create(SIGNED_STATUS_TOKEN, bytes);
  }

  async authorGrantStatus(
    request: GrantStatusRequest,
    options: LifecycleSigningOptions,
  ): Promise<SignedGrantStatus> {
    this.#assertActive();
    const unsigned = this.#engine.encodeGrantStatusStatementV1(
      request.method,
      protocolDigestBytes(request.grantId),
      request.state,
      request.sequence,
      request.observedAt,
      request.validUntil,
      request.issuer,
      copyExtensions(request.extensions),
    );
    const bytes = await this.#sign("grant-status", request.issuer, request.validUntil, unsigned, options);
    return SignedGrantStatus.create(SIGNED_STATUS_TOKEN, bytes);
  }

  principalSnapshot(request: PrincipalStatusSnapshotRequest): PrincipalStatusSnapshot {
    this.#assertActive();
    const native = this.#engine.parsePrincipalStatusSnapshotV1(snapshotInput(request));
    try {
      return PrincipalStatusSnapshot.create(
        SNAPSHOT_TOKEN,
        request.id,
        native.statementCount,
        new Uint8Array(native.cbor),
      );
    } finally {
      native.free?.();
    }
  }

  grantSnapshot(request: GrantStatusSnapshotRequest): GrantStatusSnapshot {
    this.#assertActive();
    const native = this.#engine.parseGrantStatusSnapshotV1(snapshotInput(request));
    try {
      return GrantStatusSnapshot.create(
        SNAPSHOT_TOKEN,
        request.id,
        native.statementCount,
        new Uint8Array(native.cbor),
      );
    } finally {
      native.free?.();
    }
  }

  dispose(): void {
    this.#active = false;
  }

  async #sign(
    objectKind: "principal-status" | "grant-status",
    issuer: string,
    validUntil: bigint,
    unsignedObject: Uint8Array,
    options: LifecycleSigningOptions,
  ): Promise<Uint8Array> {
    const principal = await options.signer.publicIdentity();
    if (principal.principal !== issuer) {
      throw new AuthsWorkflowError("signer-response-mismatch", "status issuer does not match signer principal");
    }
    const coordinator = new SigningCoordinator(new WasmSigningAdapter(this.#engine));
    const signed = await coordinator.execute({
      objectKind,
      unsignedObject,
      principal,
      signer: options.signer,
      approval: options.approval,
      requiredApproval: options.requiredApproval,
      expiresAt: options.expiresAt ?? validUntil,
      display: Object.freeze([
        Object.freeze({ label: "Object", value: objectKind }),
        Object.freeze({ label: "Issuer", value: issuer }),
      ]),
    });
    return signed.signedObject.slice();
  }

  #assertActive(): void {
    if (!this.#active) throw new AuthsWorkflowError("disposed", "lifecycle author is disposed");
  }
}

export async function loadLifecycleAuthor(): Promise<LifecycleAuthor> {
  return LifecycleAuthor.create(LIFECYCLE_TOKEN, await loadPackagedWorkflowEngine());
}

function copyExtensions(value: readonly CriticalExtensionInput[] | undefined): readonly object[] {
  return Object.freeze((value ?? []).map((extension) => Object.freeze({
    id: extension.id,
    bytes: extension.bytes.slice(),
  })));
}

function snapshotInput(
  request: PrincipalStatusSnapshotRequest | GrantStatusSnapshotRequest,
): object {
  return Object.freeze({
    id: protocolDigestBytes(request.id),
    observedAt: request.observedAt,
    validUntil: request.validUntil,
    statements: Object.freeze(request.statements.map((statement) => {
      const resources = signedStatusResources.get(statement);
      if (resources === undefined) {
        throw new AuthsWorkflowError("invalid-authority", "status statement is forged");
      }
      return resources.bytes.slice();
    })),
    checkpoints: Object.freeze((request.checkpoints ?? []).map(protocolDigestBytes)),
    trust: Object.freeze((request.trust ?? []).map((rule) => Object.freeze({ ...rule }))),
  });
}

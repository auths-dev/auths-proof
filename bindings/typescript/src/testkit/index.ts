import {
  ProviderOperationError,
  type ApprovalPolicy,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type PrincipalDescriptor,
  type Signer,
  type SigningRequest,
  type SigningResponse,
} from "../workflow.js";
import { loadPackagedWorkflowEngine } from "../verifier/wasm.js";
import type {
  ApplicationExecutionStore,
  ApplicationOutcome,
  ApplicationReservation,
  ApplicationReceiptAttestor,
  ApplicationReceiptSigner,
  AttestedApplicationReceipt,
} from "../profiles/application/index.js";
export { profileConformance } from "./profile-conformance.js";
export {
  adapterConformance,
  type AdapterConformanceCase,
  type AdapterConformanceOptions,
  type AdapterConformanceReport,
  type AdapterKind,
  type AdapterMetadata,
} from "./adapter-conformance.js";
export {
  custodyConformance,
  type CustodyConformanceCase,
  type CustodyConformanceOptions,
  type CustodyConformanceReport,
  type CustodyConformanceResult,
} from "./custody-conformance.js";
export {
  productWaistConformance,
  type ProductWaistConformanceCase,
  type ProductWaistConformanceReport,
  type ProductWaistExpected,
} from "./product-waist-conformance.js";
export {
  InMemoryBudgetPort,
  InMemoryChallengePort,
  InMemoryExecutionStatePort,
  InMemoryReceiptPort,
  InMemoryReplayPort,
} from "./runtime.js";

class DevelopmentEd25519Key {
  readonly #privateKey: CryptoKey;
  readonly #descriptor: PrincipalDescriptor;
  readonly #evidence: Uint8Array;
  readonly #evidenceType: string;
  readonly #mediaType: string;
  #disposed = false;

  private constructor(
    privateKey: CryptoKey,
    descriptor: PrincipalDescriptor,
    evidence: Uint8Array,
    evidenceType: string,
    mediaType: string,
  ) {
    this.#privateKey = privateKey;
    this.#descriptor = Object.freeze({ ...descriptor });
    this.#evidence = evidence.slice();
    this.#evidenceType = evidenceType;
    this.#mediaType = mediaType;
  }

  static async generate(): Promise<DevelopmentEd25519Key> {
    const keys = await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    const engine = await loadPackagedWorkflowEngine();
    let identity;
    try {
      identity = engine.deriveEd25519RawKeyIdentityV1(publicKey);
      return new DevelopmentEd25519Key(
        keys.privateKey,
        {
          principal: identity.principal,
          principalMethod: identity.principalMethod,
          verificationMethod: identity.verificationMethod,
          suite: identity.suite,
        },
        identity.evidence,
        identity.principalMethod,
        identity.mediaType,
      );
    } catch {
      throw new TypeError("native raw-key profile rejected the development Ed25519 key");
    } finally {
      identity?.free?.();
    }
  }

  descriptor(): PrincipalDescriptor {
    this.assertActive();
    return { ...this.#descriptor };
  }

  evidence(): Uint8Array {
    this.assertActive();
    return this.#evidence.slice();
  }

  async sign(preimage: Uint8Array): Promise<Uint8Array> {
    this.assertActive();
    return new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        this.#privateKey,
        preimage.slice().buffer,
      ),
    );
  }

  evidenceType(): string {
    return this.#evidenceType;
  }

  mediaType(): string {
    return this.#mediaType;
  }

  dispose(): void {
    this.#disposed = true;
    this.#evidence.fill(0);
  }

  private assertActive(): void {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
  }
}

class DevelopmentEd25519Signer implements Signer {
  readonly kind = "auths-development-ed25519";
  readonly lifecycle = "ephemeral" as const;
  readonly #key: DevelopmentEd25519Key;

  private constructor(key: DevelopmentEd25519Key) {
    this.#key = key;
  }

  static async generate(): Promise<DevelopmentEd25519Signer> {
    return new DevelopmentEd25519Signer(await DevelopmentEd25519Key.generate());
  }

  async publicIdentity(): Promise<PrincipalDescriptor> {
    return this.#key.descriptor();
  }

  async sign(request: SigningRequest): Promise<SigningResponse> {
    const signature = await this.#key.sign(request.signingPreimage);
    return Object.freeze({
      requestId: request.requestId,
      principal: { ...request.principal },
      transactionDigest: request.transactionDigest.slice(),
      signature,
      evidence: Object.freeze([
        Object.freeze({
          evidenceType: this.#key.evidenceType(),
          mediaType: this.#key.mediaType(),
          bytes: this.#key.evidence(),
        }),
      ]),
    });
  }

  async dispose(): Promise<void> {
    this.#key.dispose();
  }
}

class DevelopmentReceiptAttestor implements ApplicationReceiptAttestor {
  readonly signer: ApplicationReceiptSigner;
  readonly #key: DevelopmentEd25519Key;

  private constructor(key: DevelopmentEd25519Key) {
    this.#key = key;
    const descriptor = key.descriptor();
    this.signer = Object.freeze({
      principal: descriptor.principal,
      verificationMethod: descriptor.verificationMethod,
      suite: descriptor.suite,
      evidence: key.evidence(),
    });
  }

  static async generate(): Promise<DevelopmentReceiptAttestor> {
    return new DevelopmentReceiptAttestor(await DevelopmentEd25519Key.generate());
  }

  sign(preimage: Uint8Array): Promise<Uint8Array> {
    return this.#key.sign(preimage);
  }

  dispose(): void {
    this.#key.dispose();
  }
}

class DevelopmentApprovalProvider implements ApprovalProvider {
  readonly #decision: "approved" | "rejected";

  constructor(decision: "approved" | "rejected") {
    this.#decision = decision;
  }

  async approve(request: ApprovalRequest): Promise<ApprovalResponse> {
    return Object.freeze({
      requestId: request.requestId,
      transactionDigest: request.transactionDigest.slice(),
      policy: Object.freeze({
        ...request.policy,
        configurationDigest: request.policy.configurationDigest.slice(),
      }),
      decision: this.#decision,
    });
  }
}

export class InMemoryApplicationExecutionStore implements ApplicationExecutionStore {
  readonly #records = new Map<string, {
    readonly reservation: ApplicationReservation;
    stage: "reserved" | "credential" | "provider" | "finished";
    outcome?: ApplicationOutcome;
  }>();

  async reserve(reservation: ApplicationReservation) {
    const current = this.#records.get(reservation.idempotencyKey);
    if (current !== undefined) {
      return equalReservation(current.reservation, reservation) ? "exact-replay" as const : "conflict" as const;
    }
    this.#records.set(reservation.idempotencyKey, {
      reservation: copyReservation(reservation),
      stage: "reserved",
    });
    return "reserved" as const;
  }

  async authorizeCredential(idempotencyKey: string) {
    const current = this.#records.get(idempotencyKey);
    if (current === undefined || current.stage !== "reserved") return "conflict" as const;
    current.stage = "credential";
    return "authorized" as const;
  }

  async enterProvider(idempotencyKey: string) {
    const current = this.#records.get(idempotencyKey);
    if (current === undefined || current.stage !== "credential") return "conflict" as const;
    current.stage = "provider";
    return "entered" as const;
  }

  async finish(
    idempotencyKey: string,
    outcome: ApplicationOutcome,
    _decisionReceipt: AttestedApplicationReceipt,
    _executionReceipt?: AttestedApplicationReceipt,
  ) {
    const current = this.#records.get(idempotencyKey);
    if (current === undefined || current.stage === "finished") return "conflict" as const;
    current.stage = "finished";
    current.outcome = outcome;
    return "stored" as const;
  }
}

function copyReservation(value: ApplicationReservation): ApplicationReservation {
  return Object.freeze({
    ...value,
    commandCommitment: value.commandCommitment.slice(),
    authorityCommitment: value.authorityCommitment.slice(),
    contextCommitment: value.contextCommitment.slice(),
    ...(value.planCommitment === undefined ? {} : { planCommitment: value.planCommitment.slice() }),
  });
}

function equalReservation(left: ApplicationReservation, right: ApplicationReservation): boolean {
  return left.idempotencyKey === right.idempotencyKey &&
    equalBytes(left.commandCommitment, right.commandCommitment) &&
    equalBytes(left.authorityCommitment, right.authorityCommitment) &&
    equalBytes(left.contextCommitment, right.contextCommitment) &&
    ((left.planCommitment === undefined && right.planCommitment === undefined) ||
      (left.planCommitment !== undefined && right.planCommitment !== undefined &&
        equalBytes(left.planCommitment, right.planCommitment))) &&
    left.memberIndex === right.memberIndex && left.memberCount === right.memberCount;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

/** Explicitly non-production development and test fixtures. */
export const development = Object.freeze({
  async ephemeralSigner(): Promise<Signer> {
    return DevelopmentEd25519Signer.generate();
  },
  async receiptAttestor(): Promise<ApplicationReceiptAttestor> {
    return DevelopmentReceiptAttestor.generate();
  },
  approve(): ApprovalProvider {
    return new DevelopmentApprovalProvider("approved");
  },
  reject(): ApprovalProvider {
    return new DevelopmentApprovalProvider("rejected");
  },
  approval(
    policy: ApprovalPolicy,
    decision: "approved" | "rejected" = "approved",
  ) {
    return Object.freeze({
      policy,
      provider: new DevelopmentApprovalProvider(decision),
    });
  },
});

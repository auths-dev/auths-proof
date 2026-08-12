import {
  type ApprovalPolicy,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type PrincipalDescriptor,
  type Signer,
  type SigningRequest,
  type SigningResponse,
} from "../workflow.js";
import {
  DevelopmentEd25519Signer,
  DevelopmentReceiptAttestor,
} from "../internal/development.js";
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
  CONFORMANCE_CATALOG,
  certifyAtomicStore,
  certifyByteTransport,
  certifyMcpProvider,
  certifySigner,
  type AtomicReservationStoreCandidate,
  type ByteTransportCandidate,
  type ByteTransportFactory,
  type ConformanceCaseResult,
  type ConformanceMetadata,
  type ConformanceReport,
  type McpProviderFactory,
} from "./conformance.js";
export type { AtomicReservationRecord } from "../internal/mechanisms.js";
export {
  InMemoryBudgetPort,
  InMemoryChallengePort,
  InMemoryExecutionStatePort,
  InMemoryReceiptPort,
  InMemoryReplayPort,
} from "./runtime.js";

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

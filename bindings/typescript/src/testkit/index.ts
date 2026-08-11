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
  InMemoryBudgetPort,
  InMemoryChallengePort,
  InMemoryExecutionStatePort,
  InMemoryReceiptPort,
  InMemoryReplayPort,
} from "./runtime.js";

class DevelopmentEd25519Signer implements Signer {
  readonly kind = "auths-development-ed25519";
  readonly lifecycle = "ephemeral" as const;
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

  static async generate(): Promise<DevelopmentEd25519Signer> {
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
      return new DevelopmentEd25519Signer(
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

  async publicIdentity(): Promise<PrincipalDescriptor> {
    this.assertActive();
    return { ...this.#descriptor };
  }

  async sign(request: SigningRequest): Promise<SigningResponse> {
    this.assertActive();
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        this.#privateKey,
        new Uint8Array(request.signingPreimage).buffer,
      ),
    );
    return Object.freeze({
      requestId: request.requestId,
      principal: { ...request.principal },
      transactionDigest: request.transactionDigest.slice(),
      signature,
      evidence: Object.freeze([
        Object.freeze({
          evidenceType: this.#evidenceType,
          mediaType: this.#mediaType,
          bytes: this.#evidence.slice(),
        }),
      ]),
    });
  }

  async dispose(): Promise<void> {
    this.#disposed = true;
    this.#evidence.fill(0);
  }

  private assertActive(): void {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
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

/** Explicitly non-production development and test fixtures. */
export const development = Object.freeze({
  async ephemeralSigner(): Promise<Signer> {
    return DevelopmentEd25519Signer.generate();
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

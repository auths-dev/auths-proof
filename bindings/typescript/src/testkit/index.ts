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
export { profileConformance } from "./profile-conformance.js";

const RAW_KEY_DOMAIN = new TextEncoder().encode("AUTHS-RAW-KEY\0\x01");
const RAW_KEY_EVIDENCE = "raw-key-v1";
const RAW_KEY_MEDIA_TYPE = "application/vnd.auths.raw-key.v1";

class DevelopmentEd25519Signer implements Signer {
  readonly kind = "auths-development-ed25519";
  readonly lifecycle = "ephemeral" as const;
  readonly #privateKey: CryptoKey;
  readonly #descriptor: PrincipalDescriptor;
  readonly #evidence: Uint8Array;
  #disposed = false;

  private constructor(
    privateKey: CryptoKey,
    descriptor: PrincipalDescriptor,
    evidence: Uint8Array,
  ) {
    this.#privateKey = privateKey;
    this.#descriptor = Object.freeze({ ...descriptor });
    this.#evidence = evidence.slice();
  }

  static async generate(): Promise<DevelopmentEd25519Signer> {
    const keys = await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    if (publicKey.length !== 32) throw new TypeError("development Ed25519 key has invalid length");
    const evidence = new Uint8Array(RAW_KEY_DOMAIN.length + 3 + publicKey.length);
    evidence.set(RAW_KEY_DOMAIN, 0);
    evidence[RAW_KEY_DOMAIN.length] = 1;
    new DataView(evidence.buffer).setUint16(RAW_KEY_DOMAIN.length + 1, 32, false);
    evidence.set(publicKey, RAW_KEY_DOMAIN.length + 3);
    // Raw-key principals commit directly to the descriptor bytes, without the
    // SDK commitment envelope. Compute that protocol digest explicitly here.
    const protocolDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", evidence));
    const principal = `key:sha256:${base64Url(protocolDigest)}`;
    return new DevelopmentEd25519Signer(
      keys.privateKey,
      {
        principal,
        principalMethod: RAW_KEY_EVIDENCE,
        verificationMethod: principal,
        suite: "ed25519-v1",
      },
      evidence,
    );
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
          evidenceType: RAW_KEY_EVIDENCE,
          mediaType: RAW_KEY_MEDIA_TYPE,
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

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

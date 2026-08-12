import {
  ProviderOperationError,
  type PrincipalDescriptor,
  type Signer,
  type SigningRequest,
  type SigningResponse,
} from "../workflow.js";
import type {
  ApplicationReceiptAttestor,
  ApplicationReceiptSigner,
} from "../profiles/application/index.js";
import { loadPackagedWorkflowEngine } from "../verifier/wasm.js";

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
    return DevelopmentEd25519Key.create(keys.privateKey, publicKey);
  }

  static async fromSeed(seed: Uint8Array): Promise<DevelopmentEd25519Key> {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) {
      throw new TypeError("development Ed25519 seed must contain 32 bytes");
    }
    const engine = await loadPackagedWorkflowEngine();
    const publicKey = engine.developmentEd25519PublicKeyV1(seed.slice());
    const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
    const encoded = new Uint8Array(prefix.length + seed.length);
    encoded.set(prefix);
    encoded.set(seed, prefix.length);
    const privateKey = await crypto.subtle.importKey("pkcs8", encoded, { name: "Ed25519" }, false, ["sign"]);
    return DevelopmentEd25519Key.create(privateKey, publicKey);
  }

  private static async create(privateKey: CryptoKey, publicKey: Uint8Array): Promise<DevelopmentEd25519Key> {
    const engine = await loadPackagedWorkflowEngine();
    let identity;
    try {
      identity = engine.deriveEd25519RawKeyIdentityV1(publicKey);
      return new DevelopmentEd25519Key(
        privateKey,
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
    this.#assertActive();
    return { ...this.#descriptor };
  }

  evidence(): Uint8Array {
    this.#assertActive();
    return this.#evidence.slice();
  }

  async sign(preimage: Uint8Array): Promise<Uint8Array> {
    this.#assertActive();
    return new Uint8Array(await crypto.subtle.sign("Ed25519", this.#privateKey, preimage.slice().buffer));
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

  #assertActive(): void {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
  }
}

export class DevelopmentEd25519Signer implements Signer {
  readonly kind = "auths-development-ed25519";
  readonly lifecycle = "ephemeral" as const;
  readonly #key: DevelopmentEd25519Key;

  private constructor(key: DevelopmentEd25519Key) {
    this.#key = key;
  }

  static async generate(): Promise<DevelopmentEd25519Signer> {
    return new DevelopmentEd25519Signer(await DevelopmentEd25519Key.generate());
  }

  static async fromSeed(seed: Uint8Array): Promise<DevelopmentEd25519Signer> {
    return new DevelopmentEd25519Signer(await DevelopmentEd25519Key.fromSeed(seed));
  }

  async publicIdentity(): Promise<PrincipalDescriptor> {
    return this.#key.descriptor();
  }

  async sign(request: SigningRequest): Promise<SigningResponse> {
    return Object.freeze({
      requestId: request.requestId,
      principal: { ...request.principal },
      transactionDigest: request.transactionDigest.slice(),
      signature: await this.#key.sign(request.signingPreimage),
      evidence: Object.freeze([Object.freeze({
        evidenceType: this.#key.evidenceType(),
        mediaType: this.#key.mediaType(),
        bytes: this.#key.evidence(),
      })]),
    });
  }

  async dispose(): Promise<void> {
    this.#key.dispose();
  }
}

export class DevelopmentReceiptAttestor implements ApplicationReceiptAttestor {
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

  static async fromSeed(seed: Uint8Array): Promise<DevelopmentReceiptAttestor> {
    return new DevelopmentReceiptAttestor(await DevelopmentEd25519Key.fromSeed(seed));
  }

  sign(preimage: Uint8Array): Promise<Uint8Array> {
    return this.#key.sign(preimage);
  }

  dispose(): void {
    this.#key.dispose();
  }
}

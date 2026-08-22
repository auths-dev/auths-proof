import type { AuthsIssue } from "./index.js";
import { issue } from "./internal/issues.js";
import { loadIdentityEngine } from "./internal/identity-engine.js";

declare const decodedIdentityBrand: unique symbol;
declare const resolvedIdentityBrand: unique symbol;
declare const validatedIdentityBrand: unique symbol;
declare const authenticatedIdentityBrand: unique symbol;

export interface DecodedIdentity {
  readonly [decodedIdentityBrand]: true;
  readonly validation: "decoded";
  readonly methodId: string;
  readonly identityId: string;
  readonly methodMaterial: Uint8Array;
  readonly relationships: readonly string[];
  toBytes(): Uint8Array;
}
export interface ResolvedIdentity {
  readonly [resolvedIdentityBrand]: true;
  readonly validation: "resolved";
  readonly methodId: string;
  readonly identityId: string;
  readonly evidence: Readonly<{ source: string; observedAtUnixSeconds: bigint; expiresAtUnixSeconds: bigint; provenance: readonly string[] }>;
}
export interface ValidatedIdentity {
  readonly [validatedIdentityBrand]: true;
  readonly validation: "validated";
  readonly methodId: string;
  readonly identityId: string;
  readonly relationships: readonly string[];
  toBytes(): Uint8Array;
}
export interface AuthenticatedIdentityMessage {
  readonly [authenticatedIdentityBrand]: true;
  readonly identity: ValidatedIdentity;
  readonly relationshipId: string;
  readonly message: Uint8Array;
}
export interface IdentityOperationOptions { readonly timeoutMs?: number; readonly signal?: AbortSignal }
export type IdentityResult<Value> =
  | Readonly<{ kind: "ok"; value: Value }>
  | Readonly<{ kind: "rejected"; issue: AuthsIssue & Readonly<{ effect: "not-applied" }> }>
  | Readonly<{ kind: "indeterminate"; issue: AuthsIssue & Readonly<{ effect: "not-applied" }> }>;
export interface IdentityClient extends AsyncDisposable {
  decode(packet: Uint8Array): IdentityResult<DecodedIdentity>;
  resolve(identity: DecodedIdentity, options?: IdentityOperationOptions): Promise<IdentityResult<ResolvedIdentity>>;
  validate(identity: ResolvedIdentity, options?: IdentityOperationOptions): Promise<IdentityResult<ValidatedIdentity>>;
  authenticate(input: Readonly<{ identity: ValidatedIdentity; relationshipId?: string; message: Uint8Array; signature: Uint8Array; timeoutMs?: number; signal?: AbortSignal }>): Promise<IdentityResult<AuthenticatedIdentityMessage>>;
  authenticateMessage(input: Readonly<{ identityPacket: Uint8Array; relationshipId?: string; message: Uint8Array; signature: Uint8Array; timeoutMs?: number; signal?: AbortSignal }>): Promise<IdentityResult<AuthenticatedIdentityMessage>>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface WasmFields {
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
  free(): void;
}
interface WasmAuthenticated extends WasmFields { readonly message: Uint8Array }
interface IdentityEngine {
  decodePublicIdentityV2(packet: Uint8Array): WasmFields;
  validateRawKeyPublicIdentityV2(packet: Uint8Array): WasmFields;
  encodeSignedIdentityMessageV2(packet: Uint8Array, message: Uint8Array, signature: Uint8Array): Uint8Array;
  verifyEd25519IdentityMessageV2(packet: Uint8Array): WasmAuthenticated;
}
interface IdentityRecord { readonly packet: Uint8Array; readonly suiteId: string; readonly publicKey: Uint8Array }
const decodedRecords = new WeakMap<object, IdentityRecord>();
const resolvedRecords = new WeakMap<object, IdentityRecord>();
const validatedRecords = new WeakMap<object, IdentityRecord>();

export async function createRawKeyEd25519IdentityClient(): Promise<IdentityClient> {
  return new RawKeyIdentityClient(await loadIdentityEngine() as unknown as IdentityEngine);
}

class RawKeyIdentityClient implements IdentityClient {
  readonly #engine: IdentityEngine;
  #state: "open" | "closing" | "closed" = "open";
  constructor(engine: IdentityEngine) { this.#engine = engine; }

  decode(packet: Uint8Array): IdentityResult<DecodedIdentity> {
    this.#assertOpen();
    if (!(packet instanceof Uint8Array) || packet.length === 0 || packet.length > 328_483) return rejected("identity.packet-malformed");
    try {
      const fields = this.#engine.decodePublicIdentityV2(packet.slice());
      try {
        const record = { packet: packet.slice(), suiteId: fields.suiteId, publicKey: new Uint8Array(fields.publicKey) };
        const value = Object.freeze({
          validation: "decoded" as const,
          methodId: fields.methodId,
          identityId: fields.identityId,
          methodMaterial: record.publicKey.slice(),
          relationships: Object.freeze(["default-signing"]),
          toBytes: () => record.packet.slice(),
        }) as DecodedIdentity;
        decodedRecords.set(value, record);
        return Object.freeze({ kind: "ok", value });
      } finally { fields.free(); }
    } catch { return rejected("identity.packet-malformed"); }
  }

  async resolve(identity: DecodedIdentity, options: IdentityOperationOptions = {}): Promise<IdentityResult<ResolvedIdentity>> {
    this.#assertOpen();
    checkOptions(options);
    options.signal?.throwIfAborted();
    const record = decodedRecords.get(identity as object);
    if (record === undefined) return rejected("identity.resolution-rejected");
    if (identity.methodId !== "raw-key-v2") return rejected("identity.method-unsupported");
    const now = BigInt(Math.floor(Date.now() / 1000));
    const value = Object.freeze({
      validation: "resolved" as const,
      methodId: identity.methodId,
      identityId: identity.identityId,
      evidence: Object.freeze({ source: "raw-key-v2", observedAtUnixSeconds: now, expiresAtUnixSeconds: now + 300n, provenance: Object.freeze(["embedded-key"]) }),
    }) as ResolvedIdentity;
    resolvedRecords.set(value, record);
    return Object.freeze({ kind: "ok", value });
  }

  async validate(identity: ResolvedIdentity, options: IdentityOperationOptions = {}): Promise<IdentityResult<ValidatedIdentity>> {
    this.#assertOpen();
    checkOptions(options);
    options.signal?.throwIfAborted();
    const record = resolvedRecords.get(identity as object);
    if (record === undefined) return rejected("identity.validation-rejected");
    try {
      const fields = this.#engine.validateRawKeyPublicIdentityV2(record.packet.slice());
      try {
        const value = Object.freeze({
          validation: "validated" as const,
          methodId: fields.methodId,
          identityId: fields.identityId,
          relationships: Object.freeze(["default-signing"]),
          toBytes: () => record.packet.slice(),
        }) as ValidatedIdentity;
        validatedRecords.set(value, record);
        return Object.freeze({ kind: "ok", value });
      } finally { fields.free(); }
    } catch { return rejected("identity.validation-rejected"); }
  }

  async authenticate(input: Readonly<{ identity: ValidatedIdentity; relationshipId?: string; message: Uint8Array; signature: Uint8Array; timeoutMs?: number; signal?: AbortSignal }>): Promise<IdentityResult<AuthenticatedIdentityMessage>> {
    this.#assertOpen();
    checkOptions(input);
    input.signal?.throwIfAborted();
    const relationshipId = input.relationshipId ?? "default-signing";
    const record = validatedRecords.get(input.identity as object);
    if (record === undefined || relationshipId !== "default-signing") return rejected("identity.relationship-denied");
    try {
      const signed = this.#engine.encodeSignedIdentityMessageV2(record.packet.slice(), input.message.slice(), input.signature.slice());
      const verified = this.#engine.verifyEd25519IdentityMessageV2(signed);
      try {
        const value = Object.freeze({ identity: input.identity, relationshipId, message: new Uint8Array(verified.message) }) as AuthenticatedIdentityMessage;
        return Object.freeze({ kind: "ok", value });
      } finally { verified.free(); }
    } catch { return rejected("identity.signature-invalid"); }
  }

  async authenticateMessage(input: Readonly<{ identityPacket: Uint8Array; relationshipId?: string; message: Uint8Array; signature: Uint8Array; timeoutMs?: number; signal?: AbortSignal }>): Promise<IdentityResult<AuthenticatedIdentityMessage>> {
    const decoded = this.decode(input.identityPacket);
    if (decoded.kind !== "ok") return decoded;
    const resolved = await this.resolve(decoded.value, input);
    if (resolved.kind !== "ok") return resolved;
    const validated = await this.validate(resolved.value, input);
    if (validated.kind !== "ok") return validated;
    return this.authenticate({ identity: validated.value, message: input.message, signature: input.signature, ...(input.relationshipId === undefined ? {} : { relationshipId: input.relationshipId }), ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }), ...(input.signal === undefined ? {} : { signal: input.signal }) });
  }

  async close(): Promise<void> { if (this.#state === "closed") return; this.#state = "closing"; this.#state = "closed"; }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
  #assertOpen(): void { if (this.#state !== "open") throw new TypeError("Auths identity client is not open"); }
}

function rejected(code: "identity.packet-malformed" | "identity.method-unsupported" | "identity.resolution-rejected" | "identity.validation-rejected" | "identity.relationship-denied" | "identity.signature-invalid"): IdentityResult<never> {
  const value = issue(code);
  if (value.effect !== "not-applied") throw new TypeError("invalid identity issue axis");
  return Object.freeze({ kind: "rejected", issue: value as AuthsIssue & Readonly<{ effect: "not-applied" }> });
}
function checkOptions(options: IdentityOperationOptions): void {
  const timeout = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300_000) throw new RangeError("identity timeout is outside bounds");
}

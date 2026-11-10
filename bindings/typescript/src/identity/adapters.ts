import { ResourceLifecycle, openResource, type LifecycleWaitOptions } from "../internal/resource-lifecycle.js";
import type { AuthsIssue } from "../index.js";
import type { AuthenticatedIdentityMessage, DecodedIdentity, IdentityClient, IdentityOperationOptions, IdentityResult, ResolvedIdentity, ValidatedIdentity } from "../identity.js";
import { issue } from "../internal/issues.js";
import { loadPackagedWorkflowEngine } from "../verifier/wasm.js";

export interface VerificationMaterial { readonly id: string; readonly bytes: Uint8Array }
export interface VerificationRelationship { readonly id: string; readonly purpose: string; readonly suiteId: string; readonly verificationMaterial: readonly VerificationMaterial[] }
export interface DecodedIdentityRecord { readonly methodId: string; readonly identityId: string; readonly methodMaterial: Uint8Array; readonly relationships: readonly VerificationRelationship[] }
export interface ResolutionEvidence { readonly source: string; readonly observedAtUnixSeconds: bigint; readonly expiresAtUnixSeconds: bigint; readonly provenance: readonly string[]; readonly history: readonly string[] }
export interface ResolvedIdentityRecord extends DecodedIdentityRecord { readonly evidence: ResolutionEvidence }
export interface IdentityResolver extends AsyncDisposable {
  /** A failed close may only be repeated when explicitly declared safe. */
  readonly cleanupRetry?: "idempotent";
  resolve(input: Readonly<{ descriptor: DecodedIdentityRecord; maximumBytes: number; signal: AbortSignal }>): Promise<IdentityAdapterResult<ResolvedIdentityRecord>>;
  close(options?: LifecycleWaitOptions): Promise<void>;
  retryCleanup?(options?: LifecycleWaitOptions): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export type IdentityAdapterRejection = "not-found" | "malformed" | "not-permitted" | "expired" | "invalid-signature";
export type IdentityAdapterUncertainty = "cancelled" | "timeout" | "unavailable" | "invalid-response";
export type IdentityAdapterResult<Value> = Readonly<{ kind: "ok"; value: Value }> | Readonly<{ kind: "rejected"; reason: IdentityAdapterRejection }> | Readonly<{ kind: "indeterminate"; reason: IdentityAdapterUncertainty }>;
export interface IdentityMethod extends AsyncDisposable {
  /** A failed close may only be repeated when explicitly declared safe. */
  readonly cleanupRetry?: "idempotent";
  readonly id: string;
  readonly version: number;
  resolve(descriptor: DecodedIdentityRecord, context: Readonly<{ signal: AbortSignal }>): Promise<IdentityAdapterResult<ResolvedIdentityRecord>>;
  validate(record: ResolvedIdentityRecord, context: Readonly<{ signal: AbortSignal }>): Promise<IdentityAdapterResult<undefined>>;
  close(options?: LifecycleWaitOptions): Promise<void>;
  retryCleanup?(options?: LifecycleWaitOptions): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export interface MessageAuthenticator extends AsyncDisposable {
  /** A failed close may only be repeated when explicitly declared safe. */
  readonly cleanupRetry?: "idempotent";
  readonly suiteId: string;
  readonly version: number;
  verify(input: Readonly<{ relationship: VerificationRelationship; preimage: Uint8Array; signature: Uint8Array; signal: AbortSignal }>): Promise<IdentityAdapterResult<undefined>>;
  close(options?: LifecycleWaitOptions): Promise<void>;
  retryCleanup?(options?: LifecycleWaitOptions): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface DescriptorEngine {
  decodeIdentityDescriptorV1(packet: Uint8Array): Readonly<{ methodId: string; identityId: string; methodMaterial: Uint8Array; relationships: readonly Readonly<{ relationshipId: string; purpose: string; suiteId: string; verificationMaterial: readonly Readonly<{ materialId: string; bytes: Uint8Array }>[] }>[] }>;
  encodeIdentityDescriptorV1(value: unknown): Uint8Array;
  identityDescriptorSigningPreimageV1(packet: Uint8Array, relationshipId: string, message: Uint8Array): Uint8Array;
}
interface StageRecord { readonly packet: Uint8Array; readonly descriptor: DecodedIdentityRecord; readonly resolved?: ResolvedIdentityRecord; readonly method: IdentityMethod }

export function createIdentityClient(options: Readonly<{ methods: readonly IdentityMethod[]; authenticators: readonly MessageAuthenticator[]; adapterOwnership?: "borrowed" | "owned"; signal?: AbortSignal; timeoutMs?: number }>): Promise<IdentityClient> {
  if (options.methods.length < 1 || options.methods.length > 32 || options.authenticators.length < 1 || options.authenticators.length > 32) throw new RangeError("identity adapter count is outside bounds");
  const snapshot = { ...options, methods: [...options.methods], authenticators: [...options.authenticators] };
  return openResource(async (owner) => {
    if (snapshot.adapterOwnership === "owned") for (const adapter of [...snapshot.authenticators, ...snapshot.methods].reverse()) {
      owner.own(adapter, (retry) => retry && adapter.retryCleanup !== undefined ? adapter.retryCleanup() : adapter.close(), adapter.cleanupRetry ?? "unsafe");
    }
    return new AdapterIdentityClient(await loadPackagedWorkflowEngine() as unknown as DescriptorEngine, snapshot, owner);
  }, options);
}

export function resolverIdentityMethod(options: Readonly<{ id: string; version: number; resolver: IdentityResolver; resolverOwnership?: "borrowed" | "owned"; maximumBytes?: number }>): IdentityMethod {
  const maximumBytes = options.maximumBytes ?? 128 * 1024;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 8 * 1024 * 1024) throw new RangeError("resolver maximum bytes is outside bounds");
  const lifecycle = new ResourceLifecycle();
  const resolver = options.resolver;
  if (options.resolverOwnership === "owned") lifecycle.own(resolver, (retry) => retry && resolver.retryCleanup !== undefined ? resolver.retryCleanup() : resolver.close(), resolver.cleanupRetry ?? "unsafe");
  return Object.freeze({
    id: parseToken(options.id), version: parseVersion(options.version), cleanupRetry: "idempotent" as const,
    async resolve(descriptor: DecodedIdentityRecord, context: Readonly<{ signal: AbortSignal }>) { const snapshot = copyDescriptor(descriptor); return lifecycle.run(() => resolver.resolve({ descriptor: snapshot, maximumBytes, signal: context.signal })); },
    async validate() { lifecycle.assertOpen(); return Object.freeze({ kind: "ok", value: undefined }); },
    close(options: LifecycleWaitOptions = {}) { return lifecycle.close(options); },
    retryCleanup(options: LifecycleWaitOptions = {}) { return lifecycle.retryCleanup(options); },
    async [Symbol.asyncDispose]() { await this.close(); },
  });
}

class AdapterIdentityClient implements IdentityClient {
  readonly #engine: DescriptorEngine;
  readonly #methods: Map<string, IdentityMethod>;
  readonly #authenticators: Map<string, MessageAuthenticator>;
  readonly #lifecycle: ResourceLifecycle;
  readonly #decoded = new WeakMap<object, StageRecord>();
  readonly #resolved = new WeakMap<object, StageRecord>();
  readonly #validated = new WeakMap<object, StageRecord>();
  constructor(engine: DescriptorEngine, options: Readonly<{ methods: readonly IdentityMethod[]; authenticators: readonly MessageAuthenticator[]; adapterOwnership?: "borrowed" | "owned" }>, lifecycle: ResourceLifecycle) {
    this.#engine = engine; this.#lifecycle = lifecycle;
    this.#methods = uniqueMap(options.methods, (value) => `${parseToken(value.id)}/${parseVersion(value.version)}`.split("/")[0]!);
    this.#authenticators = uniqueMap(options.authenticators, (value) => `${parseToken(value.suiteId)}/${parseVersion(value.version)}`.split("/")[0]!);
  }
  decode(packet: Uint8Array): IdentityResult<DecodedIdentity> {
    this.#assertOpen();
    try {
      const raw = this.#engine.decodeIdentityDescriptorV1(packet.slice());
      const descriptor = descriptorFromEngine(raw);
      const method = this.#methods.get(descriptor.methodId);
      if (method === undefined) return negative("rejected", "identity.method-unsupported");
      const record = { packet: packet.slice(), descriptor, method };
      const value = Object.freeze({ validation: "decoded" as const, methodId: descriptor.methodId, identityId: descriptor.identityId, methodMaterial: descriptor.methodMaterial.slice(), relationships: Object.freeze(descriptor.relationships.map((item) => item.id)), toBytes: () => record.packet.slice() }) as DecodedIdentity;
      this.#decoded.set(value, record); return Object.freeze({ kind: "ok", value });
    } catch { return negative("rejected", "identity.packet-malformed"); }
  }
  async resolve(identity: DecodedIdentity, options: IdentityOperationOptions = {}): Promise<IdentityResult<ResolvedIdentity>> {
    this.#assertOpen(); const record = this.#decoded.get(identity as object); if (record === undefined) return negative("rejected", "identity.resolution-rejected");
    return withAdapter(this.#lifecycle, options, "identity.resolution-indeterminate", async (signal) => {
      const outcome = await record.method.resolve(copyDescriptor(record.descriptor), { signal });
      if (outcome.kind !== "ok") return mapAdapter(outcome, "identity.resolution-rejected", "identity.resolution-indeterminate");
      const resolved = copyResolved(outcome.value);
      if (resolved.methodId !== record.descriptor.methodId || resolved.identityId !== record.descriptor.identityId) return negative("indeterminate", "identity.resolution-indeterminate", ["invalid-response"]);
      const value = Object.freeze({ validation: "resolved" as const, methodId: resolved.methodId, identityId: resolved.identityId, evidence: Object.freeze({ source: resolved.evidence.source, observedAtUnixSeconds: resolved.evidence.observedAtUnixSeconds, expiresAtUnixSeconds: resolved.evidence.expiresAtUnixSeconds, provenance: Object.freeze([...resolved.evidence.provenance]) }) }) as ResolvedIdentity;
      this.#resolved.set(value, { ...record, resolved }); return Object.freeze({ kind: "ok", value });
    });
  }
  async validate(identity: ResolvedIdentity, options: IdentityOperationOptions = {}): Promise<IdentityResult<ValidatedIdentity>> {
    this.#assertOpen(); const record = this.#resolved.get(identity as object); if (record?.resolved === undefined) return negative("rejected", "identity.validation-rejected");
    return withAdapter(this.#lifecycle, options, "identity.validation-indeterminate", async (signal) => {
      const outcome = await record.method.validate(copyResolved(record.resolved!), { signal });
      if (outcome.kind !== "ok") return mapAdapter(outcome, outcome.kind === "rejected" && outcome.reason === "expired" ? "identity.evidence-expired" : "identity.validation-rejected", "identity.validation-indeterminate");
      const value = Object.freeze({ validation: "validated" as const, methodId: record.descriptor.methodId, identityId: record.descriptor.identityId, relationships: Object.freeze(record.descriptor.relationships.map((item) => item.id)), toBytes: () => record.packet.slice() }) as ValidatedIdentity;
      this.#validated.set(value, record); return Object.freeze({ kind: "ok", value });
    });
  }
  async authenticate(input: Readonly<{ identity: ValidatedIdentity; relationshipId?: string; message: Uint8Array; signature: Uint8Array; timeoutMs?: number; signal?: AbortSignal }>): Promise<IdentityResult<AuthenticatedIdentityMessage>> {
    input = { ...input, message: input.message.slice(), signature: input.signature.slice() };
    this.#assertOpen(); const record = this.#validated.get(input.identity as object); if (record === undefined) return negative("rejected", "identity.relationship-denied");
    const relationshipId = input.relationshipId ?? "default-signing"; const relationship = record.descriptor.relationships.find((item) => item.id === relationshipId);
    if (relationship === undefined) return negative("rejected", "identity.relationship-denied"); const authenticator = this.#authenticators.get(relationship.suiteId);
    if (authenticator === undefined) return negative("indeterminate", "identity.authentication-indeterminate", ["unavailable"]);
    return withAdapter(this.#lifecycle, input, "identity.authentication-indeterminate", async (signal) => {
      const preimage = this.#engine.identityDescriptorSigningPreimageV1(record.packet.slice(), relationshipId, input.message.slice());
      const outcome = await authenticator.verify({ relationship: copyRelationship(relationship), preimage: preimage.slice(), signature: input.signature.slice(), signal });
      if (outcome.kind !== "ok") return mapAdapter(outcome, outcome.kind === "rejected" && outcome.reason === "invalid-signature" ? "identity.signature-invalid" : "identity.relationship-denied", "identity.authentication-indeterminate");
      return Object.freeze({ kind: "ok", value: Object.freeze({ identity: input.identity, relationshipId, message: input.message.slice() }) as AuthenticatedIdentityMessage });
    });
  }
  async authenticateMessage(input: Readonly<{ identityPacket: Uint8Array; relationshipId?: string; message: Uint8Array; signature: Uint8Array; timeoutMs?: number; signal?: AbortSignal }>): Promise<IdentityResult<AuthenticatedIdentityMessage>> {
    input = { ...input, identityPacket: input.identityPacket.slice(), message: input.message.slice(), signature: input.signature.slice() };
    const decoded = this.decode(input.identityPacket); if (decoded.kind !== "ok") return decoded;
    const resolved = await this.resolve(decoded.value, input); if (resolved.kind !== "ok") return resolved;
    const validated = await this.validate(resolved.value, input); if (validated.kind !== "ok") return validated;
    return this.authenticate({ identity: validated.value, message: input.message, signature: input.signature, ...(input.relationshipId === undefined ? {} : { relationshipId: input.relationshipId }), ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }), ...(input.signal === undefined ? {} : { signal: input.signal }) });
  }
  close(options: LifecycleWaitOptions = {}): Promise<void> { return this.#lifecycle.close(options); }
  retryCleanup(options: LifecycleWaitOptions = {}): Promise<void> { return this.#lifecycle.retryCleanup(options); }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
  #assertOpen(): void { this.#lifecycle.assertOpen(); }
}

async function withAdapter<T>(lifecycle: ResourceLifecycle, options: IdentityOperationOptions, fallback: "identity.resolution-indeterminate" | "identity.validation-indeterminate" | "identity.authentication-indeterminate", operation: (signal: AbortSignal) => Promise<IdentityResult<T>>): Promise<IdentityResult<T>> {
  const timeout = options.timeoutMs ?? 10_000; if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300_000) throw new RangeError("identity timeout is outside bounds");
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeout); const abort = () => controller.abort(options.signal?.reason); options.signal?.addEventListener("abort", abort, { once: true });
  try { options.signal?.throwIfAborted(); return await lifecycle.run(() => operation(controller.signal), { signal: controller.signal }); } catch { return negative("indeterminate", fallback, [options.signal?.aborted ? "cancelled" : controller.signal.aborted ? "timeout" : "unavailable"]); } finally { clearTimeout(timer); options.signal?.removeEventListener("abort", abort); }
}
function mapAdapter<T>(outcome: Exclude<IdentityAdapterResult<T>, { kind: "ok" }>, rejectedCode: Parameters<typeof negative>[1], indeterminateCode: Parameters<typeof negative>[1]): IdentityResult<never> { return outcome.kind === "rejected" ? negative("rejected", rejectedCode) : negative("indeterminate", indeterminateCode, [outcome.reason]); }
function negative(kind: "rejected" | "indeterminate", code: Parameters<typeof issue>[0], causes: AuthsIssue["causes"] = []): IdentityResult<never> { const value = issue(code, { causes }); if (value.effect !== "not-applied") throw new TypeError("invalid identity issue axis"); return Object.freeze({ kind, issue: value as AuthsIssue & Readonly<{ effect: "not-applied" }> }); }
function descriptorFromEngine(value: ReturnType<DescriptorEngine["decodeIdentityDescriptorV1"]>): DecodedIdentityRecord { return Object.freeze({ methodId: value.methodId, identityId: value.identityId, methodMaterial: new Uint8Array(value.methodMaterial), relationships: Object.freeze(value.relationships.map((item) => Object.freeze({ id: item.relationshipId, purpose: item.purpose, suiteId: item.suiteId, verificationMaterial: Object.freeze(item.verificationMaterial.map((material) => Object.freeze({ id: material.materialId, bytes: new Uint8Array(material.bytes) }))) }))) }); }
function copyDescriptor(value: DecodedIdentityRecord): DecodedIdentityRecord { return Object.freeze({ methodId: value.methodId, identityId: value.identityId, methodMaterial: value.methodMaterial.slice(), relationships: Object.freeze(value.relationships.map(copyRelationship)) }); }
function copyResolved(value: ResolvedIdentityRecord): ResolvedIdentityRecord { return Object.freeze({ ...copyDescriptor(value), evidence: Object.freeze({ ...value.evidence, provenance: Object.freeze([...value.evidence.provenance]), history: Object.freeze([...value.evidence.history]) }) }); }
function copyRelationship(value: VerificationRelationship): VerificationRelationship { return Object.freeze({ ...value, verificationMaterial: Object.freeze(value.verificationMaterial.map((item) => Object.freeze({ id: item.id, bytes: item.bytes.slice() }))) }); }
function uniqueMap<T>(values: readonly T[], key: (value: T) => string): Map<string, T> { const output = new Map<string, T>(); for (const value of values) { const id = key(value); if (output.has(id)) throw new TypeError("duplicate identity adapter"); output.set(id, value); } return output; }
function parseToken(value: string): string { if (!/^[A-Za-z][A-Za-z0-9._:/-]{0,127}$/u.test(value)) throw new TypeError("invalid identity adapter token"); return value; }
function parseVersion(value: number): number { if (!Number.isSafeInteger(value) || value < 1 || value > 0x7fffffff) throw new RangeError("invalid identity adapter version"); return value; }

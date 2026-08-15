/**
 * Neutral identity exchange and message authentication.
 *
 * This entry point does not initialize authority, capability, approval, policy, profile, or
 * lifecycle workflows. Canonical bytes are produced by the packaged Rust/WASM implementation;
 * callers select concrete identity-method and signature-suite adapters explicitly.
 */

import { guardWasmBoundary } from "./verifier/wasm-boundary.js";

const DECODED_IDENTITY = Symbol("auths-decoded-identity");
const VALIDATED_IDENTITY = Symbol("auths-validated-identity");
const DECODED_MESSAGE = Symbol("auths-decoded-identity-message");
const AUTHENTICATED_MESSAGE = Symbol("auths-authenticated-identity-message");
const DECODED_DESCRIPTOR = Symbol("auths-decoded-identity-descriptor");
const RESOLVED_DESCRIPTOR = Symbol("auths-resolved-identity-descriptor");
const VALIDATED_DESCRIPTOR = Symbol("auths-validated-identity-descriptor");
const AUTHENTICATED_DESCRIPTOR = Symbol("auths-authenticated-identity-descriptor");

export interface VerificationMaterialInput {
  readonly materialId: string;
  readonly bytes: Uint8Array;
}

export interface VerificationRelationshipInput {
  readonly relationshipId: string;
  readonly purpose: string;
  readonly suiteId: string;
  readonly verificationMaterial: readonly VerificationMaterialInput[];
}

export interface IdentityDescriptorInput {
  readonly methodId: string;
  readonly identityId: string;
  readonly methodMaterial: Uint8Array;
  readonly relationships: readonly VerificationRelationshipInput[];
}

export interface ResolutionEvidence {
  readonly source: string;
  readonly fetchedAt: bigint;
  readonly expiresAt: bigint;
  readonly version: string;
}

interface DescriptorState extends IdentityDescriptorInput {
  readonly packet: Uint8Array;
}

export interface DecodedIdentityDescriptor extends DescriptorState {
  readonly [DECODED_DESCRIPTOR]: true;
  readonly state: "decoded";
}

export interface ResolvedIdentityDescriptor extends DescriptorState {
  readonly [RESOLVED_DESCRIPTOR]: true;
  readonly state: "resolved";
  readonly resolution: ResolutionEvidence;
}

export interface ValidatedIdentityDescriptor extends DescriptorState {
  readonly [VALIDATED_DESCRIPTOR]: true;
  readonly state: "validated";
  readonly resolution: ResolutionEvidence;
}

export interface AuthenticatedDescriptorMessage {
  readonly [AUTHENTICATED_DESCRIPTOR]: true;
  readonly identity: ValidatedIdentityDescriptor;
  readonly relationshipId: string;
  readonly purpose: string;
  readonly message: Uint8Array;
}

export interface IdentityMethodMetadata {
  readonly methodId: string;
  readonly version: string;
  readonly purposes: readonly string[];
}

export interface IdentityResolutionRequest {
  readonly descriptor: DecodedIdentityDescriptor;
  readonly signal?: AbortSignal;
  readonly maximumBytes: number;
  readonly maximumRedirects: number;
}

export interface IdentityResolutionResult {
  readonly descriptor: IdentityDescriptorInput;
  readonly evidence: ResolutionEvidence;
}

export interface IdentityDescriptorMethodAdapter {
  readonly metadata: IdentityMethodMetadata;
  resolve?(request: IdentityResolutionRequest): Promise<IdentityResolutionResult>;
  parse(descriptor: ResolvedIdentityDescriptor): IdentityDescriptorInput;
}

export interface SignatureSuiteMetadata {
  readonly suiteId: string;
  readonly version: string;
  readonly purposes: readonly string[];
}

export interface DescriptorAuthenticationRequest {
  readonly identity: ValidatedIdentityDescriptor;
  readonly relationship: VerificationRelationshipInput;
  readonly signingPreimage: Uint8Array;
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
  readonly signal?: AbortSignal;
}

export interface DescriptorAuthenticationResult {
  readonly identityId: string;
  readonly relationshipId: string;
  readonly message: Uint8Array;
}

export interface DescriptorSignatureSuiteAdapter {
  readonly metadata: SignatureSuiteMetadata;
  authenticate(request: DescriptorAuthenticationRequest): Promise<DescriptorAuthenticationResult>;
}

export class IdentityMethodRegistry {
  readonly #methods: ReadonlyMap<string, IdentityDescriptorMethodAdapter>;

  constructor(methods: readonly IdentityDescriptorMethodAdapter[]) {
    this.#methods = exactRegistry(methods, (method) => method.metadata.methodId, "identity method");
  }

  select(methodId: string): IdentityDescriptorMethodAdapter {
    const method = this.#methods.get(methodId);
    if (method === undefined) throw new TypeError(`unsupported identity method: ${methodId}`);
    return method;
  }
}

export class SignatureSuiteRegistry {
  readonly #suites: ReadonlyMap<string, DescriptorSignatureSuiteAdapter>;

  constructor(suites: readonly DescriptorSignatureSuiteAdapter[]) {
    this.#suites = exactRegistry(suites, (suite) => suite.metadata.suiteId, "signature suite");
  }

  select(suiteId: string): DescriptorSignatureSuiteAdapter {
    const suite = this.#suites.get(suiteId);
    if (suite === undefined) throw new TypeError(`unsupported signature suite: ${suiteId}`);
    return suite;
  }
}

function exactRegistry<T>(
  values: readonly T[],
  identifier: (value: T) => string,
  kind: string,
): ReadonlyMap<string, T> {
  const entries = new Map<string, T>();
  for (const value of values) {
    const id = identifier(value);
    if (id.length === 0 || entries.has(id)) throw new TypeError(`duplicate or empty ${kind}: ${id}`);
    entries.set(id, value);
  }
  return entries;
}

export interface DecodedIdentity {
  readonly [DECODED_IDENTITY]: true;
  readonly validation: "decoded";
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
  readonly packet: Uint8Array;
}

export interface ValidatedIdentity {
  readonly [VALIDATED_IDENTITY]: true;
  readonly validation: "validated";
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
  readonly packet: Uint8Array;
}

export interface DecodedSignedIdentityMessage {
  readonly [DECODED_MESSAGE]: true;
  readonly identity: DecodedIdentity;
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
  readonly packet: Uint8Array;
}

export interface AuthenticatedIdentityMessage {
  readonly [AUTHENTICATED_MESSAGE]: true;
  readonly identity: ValidatedIdentity;
  readonly message: Uint8Array;
}

export interface IdentityMethodParse {
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
}

export interface IdentityMethodAdapter {
  readonly methodId: string;
  parse(identity: DecodedIdentity): IdentityMethodParse;
}

export interface SignatureSuiteParse {
  readonly identityId: string;
  readonly message: Uint8Array;
}

export interface SignatureSuiteAdapter {
  readonly suiteId: string;
  parse(message: DecodedSignedIdentityMessage): SignatureSuiteParse;
}

interface WasmIdentityFields {
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
  free(): void;
}

interface WasmAuthenticatedIdentityMessage extends WasmIdentityFields {
  readonly message: Uint8Array;
}

interface WasmSignedIdentityMessage extends WasmAuthenticatedIdentityMessage {
  readonly signature: Uint8Array;
}

interface IdentityWasmEngine {
  identityAbiVersionV1(): number;
  encodeIdentityDescriptorV1(value: IdentityDescriptorInput): Uint8Array;
  decodeIdentityDescriptorV1(packet: Uint8Array): IdentityDescriptorInput;
  identityDescriptorSigningPreimageV1(
    packet: Uint8Array,
    relationshipId: string,
    message: Uint8Array,
  ): Uint8Array;
  encodePublicIdentityV2(
    methodId: string,
    identityId: string,
    suiteId: string,
    publicKey: Uint8Array,
  ): Uint8Array;
  createRawKeyPublicIdentityV2(suiteId: string, publicKey: Uint8Array): Uint8Array;
  decodePublicIdentityV2(packet: Uint8Array): WasmIdentityFields;
  decodeSignedIdentityMessageV2(packet: Uint8Array): WasmSignedIdentityMessage;
  validateRawKeyPublicIdentityV2(packet: Uint8Array): WasmIdentityFields;
  identityMessageSigningPreimageV2(packet: Uint8Array, message: Uint8Array): Uint8Array;
  encodeSignedIdentityMessageV2(
    packet: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Uint8Array;
  verifyEd25519IdentityMessageV2(packet: Uint8Array): WasmAuthenticatedIdentityMessage;
}

function copyMaterial(material: VerificationMaterialInput): VerificationMaterialInput {
  return Object.freeze({ materialId: material.materialId, bytes: new Uint8Array(material.bytes) });
}

function copyRelationship(
  relationship: VerificationRelationshipInput,
): VerificationRelationshipInput {
  return Object.freeze({
    relationshipId: relationship.relationshipId,
    purpose: relationship.purpose,
    suiteId: relationship.suiteId,
    verificationMaterial: Object.freeze(relationship.verificationMaterial.map(copyMaterial)),
  });
}

function copyDescriptorFields(descriptor: IdentityDescriptorInput): IdentityDescriptorInput {
  return Object.freeze({
    methodId: descriptor.methodId,
    identityId: descriptor.identityId,
    methodMaterial: new Uint8Array(descriptor.methodMaterial),
    relationships: Object.freeze(descriptor.relationships.map(copyRelationship)),
  });
}

function copyResolution(evidence: ResolutionEvidence): ResolutionEvidence {
  if (evidence.expiresAt < evidence.fetchedAt || evidence.source.length === 0 || evidence.version.length === 0) {
    throw new TypeError("identity resolution evidence is invalid");
  }
  return Object.freeze({ ...evidence });
}

function embeddedResolution(): ResolutionEvidence {
  return Object.freeze({
    source: "embedded",
    fetchedAt: 0n,
    expiresAt: 0xffff_ffff_ffff_ffffn,
    version: "1",
  });
}

function descriptorState<T extends object>(
  brand: T,
  state: "decoded" | "resolved" | "validated",
  descriptor: IdentityDescriptorInput,
  packet: Uint8Array,
  resolution?: ResolutionEvidence,
): T & DescriptorState & { readonly state: typeof state; readonly resolution?: ResolutionEvidence } {
  return Object.freeze({
    ...brand,
    state,
    ...copyDescriptorFields(descriptor),
    packet: packet.slice(),
    ...(resolution === undefined ? {} : { resolution: copyResolution(resolution) }),
  }) as unknown as T & DescriptorState & {
    readonly state: typeof state;
    readonly resolution?: ResolutionEvidence;
  };
}

function sameDescriptor(left: IdentityDescriptorInput, right: IdentityDescriptorInput): boolean {
  return left.methodId === right.methodId &&
    left.identityId === right.identityId &&
    equalBytes(left.methodMaterial, right.methodMaterial) &&
    left.relationships.length === right.relationships.length &&
    left.relationships.every((relationship, index) => {
      const candidate = right.relationships[index];
      return candidate !== undefined &&
        relationship.relationshipId === candidate.relationshipId &&
        relationship.purpose === candidate.purpose &&
        relationship.suiteId === candidate.suiteId &&
        relationship.verificationMaterial.length === candidate.verificationMaterial.length &&
        relationship.verificationMaterial.every((material, materialIndex) => {
          const candidateMaterial = candidate.verificationMaterial[materialIndex];
          return candidateMaterial !== undefined &&
            material.materialId === candidateMaterial.materialId &&
            equalBytes(material.bytes, candidateMaterial.bytes);
        });
    });
}

type IdentityFields = Pick<
  DecodedIdentity,
  "methodId" | "identityId" | "suiteId" | "publicKey"
>;

function copyFields(fields: WasmIdentityFields): IdentityFields {
  return {
    methodId: fields.methodId,
    identityId: fields.identityId,
    suiteId: fields.suiteId,
    publicKey: new Uint8Array(fields.publicKey),
  };
}

function decodedIdentity(fields: IdentityFields, packet: Uint8Array): DecodedIdentity {
  return Object.freeze({
    [DECODED_IDENTITY]: true as const,
    validation: "decoded",
    ...fields,
    publicKey: fields.publicKey.slice(),
    packet: packet.slice(),
  });
}

function validatedIdentity(fields: IdentityFields, packet: Uint8Array): ValidatedIdentity {
  return Object.freeze({
    [VALIDATED_IDENTITY]: true as const,
    validation: "validated",
    ...fields,
    publicKey: fields.publicKey.slice(),
    packet: packet.slice(),
  });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameIdentity(left: IdentityFields, right: IdentityFields): boolean {
  return left.methodId === right.methodId &&
    left.identityId === right.identityId &&
    left.suiteId === right.suiteId &&
    equalBytes(left.publicKey, right.publicKey);
}

/** Adapter-neutral canonical identity packet operations. */
export class IdentityClient {
  readonly #engine: IdentityWasmEngine;

  /** @internal Construct through {@link loadIdentity}. */
  constructor(engine: IdentityWasmEngine) {
    this.#engine = engine;
  }

  /** Encodes a general identity without assuming one key, one suite, or embedded resolution. */
  encodeDescriptor(descriptor: IdentityDescriptorInput): Uint8Array {
    return new Uint8Array(this.#engine.encodeIdentityDescriptorV1(copyDescriptorFields(descriptor)));
  }

  decodeDescriptor(packet: Uint8Array): DecodedIdentityDescriptor {
    const descriptor = copyDescriptorFields(this.#engine.decodeIdentityDescriptorV1(packet));
    return descriptorState(
      { [DECODED_DESCRIPTOR]: true as const },
      "decoded",
      descriptor,
      packet,
    ) as DecodedIdentityDescriptor;
  }

  async resolveDescriptor(
    descriptor: DecodedIdentityDescriptor,
    registry: IdentityMethodRegistry,
    options: Readonly<{
      signal?: AbortSignal;
      maximumBytes?: number;
      maximumRedirects?: number;
    }> = {},
  ): Promise<ResolvedIdentityDescriptor> {
    const method = registry.select(descriptor.methodId);
    if (method.resolve === undefined) {
      return descriptorState(
        { [RESOLVED_DESCRIPTOR]: true as const },
        "resolved",
        descriptor,
        descriptor.packet,
        embeddedResolution(),
      ) as ResolvedIdentityDescriptor;
    }
    options.signal?.throwIfAborted();
    const request: IdentityResolutionRequest = {
      descriptor,
      maximumBytes: options.maximumBytes ?? 131_072,
      maximumRedirects: options.maximumRedirects ?? 0,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    };
    if (!Number.isSafeInteger(request.maximumBytes) || request.maximumBytes < 1 ||
        request.maximumBytes > 1_048_576 || !Number.isSafeInteger(request.maximumRedirects) ||
        request.maximumRedirects < 0 || request.maximumRedirects > 4) {
      throw new TypeError("identity resolution limits are outside bounds");
    }
    const resolved = await method.resolve(request);
    options.signal?.throwIfAborted();
    if (resolved.descriptor.methodId !== descriptor.methodId ||
        resolved.descriptor.identityId !== descriptor.identityId) {
      throw new TypeError("identity resolver changed the stable identity");
    }
    const packet = this.encodeDescriptor(resolved.descriptor);
    const canonical = copyDescriptorFields(this.#engine.decodeIdentityDescriptorV1(packet));
    if (packet.length > request.maximumBytes) throw new TypeError("resolved identity exceeds byte limit");
    return descriptorState(
      { [RESOLVED_DESCRIPTOR]: true as const },
      "resolved",
      canonical,
      packet,
      resolved.evidence,
    ) as ResolvedIdentityDescriptor;
  }

  validateDescriptor(
    descriptor: ResolvedIdentityDescriptor,
    registry: IdentityMethodRegistry,
  ): ValidatedIdentityDescriptor {
    const method = registry.select(descriptor.methodId);
    const parsed = method.parse(descriptor);
    if (!sameDescriptor(descriptor, parsed)) {
      throw new TypeError("identity method changed canonical descriptor fields");
    }
    for (const relationship of descriptor.relationships) {
      if (!method.metadata.purposes.includes(relationship.purpose)) {
        throw new TypeError(`identity method does not support purpose: ${relationship.purpose}`);
      }
    }
    return descriptorState(
      { [VALIDATED_DESCRIPTOR]: true as const },
      "validated",
      descriptor,
      descriptor.packet,
      descriptor.resolution,
    ) as ValidatedIdentityDescriptor;
  }

  descriptorSigningPreimage(
    identity: DecodedIdentityDescriptor | ResolvedIdentityDescriptor | ValidatedIdentityDescriptor,
    relationshipId: string,
    message: Uint8Array,
  ): Uint8Array {
    return new Uint8Array(
      this.#engine.identityDescriptorSigningPreimageV1(identity.packet, relationshipId, message),
    );
  }

  async authenticateDescriptor(
    identity: ValidatedIdentityDescriptor,
    input: Readonly<{
      relationshipId: string;
      message: Uint8Array;
      signature: Uint8Array;
      suites: SignatureSuiteRegistry;
      signal?: AbortSignal;
    }>,
  ): Promise<AuthenticatedDescriptorMessage> {
    input.signal?.throwIfAborted();
    const relationship = identity.relationships.find(
      (candidate) => candidate.relationshipId === input.relationshipId,
    );
    if (relationship === undefined) throw new TypeError("unknown identity relationship");
    const suite = input.suites.select(relationship.suiteId);
    if (!suite.metadata.purposes.includes(relationship.purpose)) {
      throw new TypeError(`signature suite does not support purpose: ${relationship.purpose}`);
    }
    const signingPreimage = this.descriptorSigningPreimage(
      identity,
      relationship.relationshipId,
      input.message,
    );
    const result = await suite.authenticate({
      identity,
      relationship,
      signingPreimage,
      message: input.message.slice(),
      signature: input.signature.slice(),
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
    input.signal?.throwIfAborted();
    if (result.identityId !== identity.identityId ||
        result.relationshipId !== relationship.relationshipId ||
        !equalBytes(result.message, input.message)) {
      throw new TypeError("signature suite changed authenticated fields");
    }
    return Object.freeze({
      [AUTHENTICATED_DESCRIPTOR]: true as const,
      identity,
      relationshipId: relationship.relationshipId,
      purpose: relationship.purpose,
      message: input.message.slice(),
    });
  }

  /** Explicit lossless bridge from authenticated identity state into authority principal input. */
  principal(identity: ValidatedIdentityDescriptor): IdentityPrincipal {
    return Object.freeze({
      method: identity.methodId,
      principal: identity.identityId,
      evidence: identity.packet.slice(),
    });
  }

  /** Encodes structural identity data after an application-owned method derived its identifier. */
  encodePublicIdentity(
    methodId: string,
    identityId: string,
    suiteId: string,
    publicKey: Uint8Array,
  ): Uint8Array {
    return new Uint8Array(
      this.#engine.encodePublicIdentityV2(methodId, identityId, suiteId, publicKey),
    );
  }

  decodePublicIdentity(packet: Uint8Array): DecodedIdentity {
    const fields = this.#engine.decodePublicIdentityV2(packet);
    try {
      return decodedIdentity(copyFields(fields), packet);
    } finally {
      fields.free();
    }
  }

  parseIdentity(
    identity: DecodedIdentity,
    adapter: IdentityMethodAdapter,
  ): ValidatedIdentity {
    if (adapter.methodId !== identity.methodId) {
      throw new TypeError("identity method does not match the decoded packet");
    }
    const parsed = adapter.parse(identity);
    if (!sameIdentity(identity, parsed)) {
      throw new TypeError("identity method changed canonical identity fields");
    }
    return validatedIdentity(parsed, identity.packet);
  }

  decodeSignedMessage(packet: Uint8Array): DecodedSignedIdentityMessage {
    const decoded = this.#engine.decodeSignedIdentityMessageV2(packet);
    try {
      const fields = copyFields(decoded);
      const identityPacket = this.#engine.encodePublicIdentityV2(
        fields.methodId,
        fields.identityId,
        fields.suiteId,
        fields.publicKey,
      );
      return Object.freeze({
        [DECODED_MESSAGE]: true as const,
        identity: decodedIdentity(fields, identityPacket),
        message: new Uint8Array(decoded.message),
        signature: new Uint8Array(decoded.signature),
        packet: packet.slice(),
      });
    } finally {
      decoded.free();
    }
  }

  authenticate(
    message: DecodedSignedIdentityMessage,
    identity: ValidatedIdentity,
    adapter: SignatureSuiteAdapter,
  ): AuthenticatedIdentityMessage {
    if (!sameIdentity(message.identity, identity)) {
      throw new TypeError("signed message identity does not match the validated identity");
    }
    if (adapter.suiteId !== identity.suiteId) {
      throw new TypeError("signature suite does not match the validated identity");
    }
    const parsed = adapter.parse(message);
    if (parsed.identityId !== identity.identityId || !equalBytes(parsed.message, message.message)) {
      throw new TypeError("signature suite changed authenticated message fields");
    }
    return Object.freeze({
      [AUTHENTICATED_MESSAGE]: true as const,
      identity,
      message: message.message.slice(),
    });
  }

  /** Produces the exact domain-separated bytes that caller-owned custody must sign. */
  signingPreimage(identity: DecodedIdentity | ValidatedIdentity, message: Uint8Array): Uint8Array {
    return new Uint8Array(
      this.#engine.identityMessageSigningPreimageV2(identity.packet, message),
    );
  }

  /** Encodes a signature returned by external custody; this does not verify it. */
  encodeSignedMessage(
    identity: DecodedIdentity | ValidatedIdentity,
    message: Uint8Array,
    signature: Uint8Array,
  ): Uint8Array {
    return new Uint8Array(
      this.#engine.encodeSignedIdentityMessageV2(identity.packet, message, signature),
    );
  }
}

export interface IdentityPrincipal {
  readonly method: string;
  readonly principal: string;
  readonly evidence: Uint8Array;
}

/** Explicit opt-in adapter for suite-labelled self-certifying raw-key identities. */
export class RawKeyIdentityAdapter {
  readonly methodId = "raw-key-v2";
  readonly #engine: IdentityWasmEngine;

  /** @internal Construct through {@link loadRawKeyIdentityAdapter}. */
  constructor(engine: IdentityWasmEngine) {
    this.#engine = engine;
  }

  /** Derives, validates, and canonically encodes a raw-key identity for any suite/key shape. */
  create(suiteId: string, publicKey: Uint8Array): ValidatedIdentity {
    const packet = new Uint8Array(
      this.#engine.createRawKeyPublicIdentityV2(suiteId, publicKey),
    );
    const decoded = this.#engine.decodePublicIdentityV2(packet);
    try {
      return validatedIdentity(this.parse(decodedIdentity(copyFields(decoded), packet)), packet);
    } finally {
      decoded.free();
    }
  }

  parse(identity: DecodedIdentity): IdentityMethodParse {
    const fields = this.#engine.validateRawKeyPublicIdentityV2(identity.packet);
    try {
      return copyFields(fields);
    } finally {
      fields.free();
    }
  }
}

/** Explicit opt-in authentication adapter for raw-key Ed25519 signed messages. */
export class Ed25519RawKeyAuthentication {
  readonly suiteId = "ed25519-v1";
  readonly #engine: IdentityWasmEngine;

  /** @internal Construct through {@link loadEd25519RawKeyAuthentication}. */
  constructor(engine: IdentityWasmEngine) {
    this.#engine = engine;
  }

  parse(message: DecodedSignedIdentityMessage): SignatureSuiteParse {
    const authenticated = this.#engine.verifyEd25519IdentityMessageV2(message.packet);
    try {
      return {
        identityId: authenticated.identityId,
        message: new Uint8Array(authenticated.message),
      };
    } finally {
      authenticated.free();
    }
  }

  verify(packet: Uint8Array): AuthenticatedIdentityMessage {
    const authenticated = this.#engine.verifyEd25519IdentityMessageV2(packet);
    try {
      const fields = copyFields(authenticated);
      const identityPacket = this.#engine.encodePublicIdentityV2(
        fields.methodId,
        fields.identityId,
        fields.suiteId,
        fields.publicKey,
      );
      return Object.freeze({
        [AUTHENTICATED_MESSAGE]: true as const,
        identity: validatedIdentity(fields, identityPacket),
        message: new Uint8Array(authenticated.message),
      });
    } finally {
      authenticated.free();
    }
  }
}

let packaged: Promise<IdentityWasmEngine> | undefined;

async function loadPackagedIdentityEngine(): Promise<IdentityWasmEngine> {
  packaged ??= (async () => {
    const moduleUrl = new URL("../wasm/auths_proof_wasm.js", import.meta.url).href;
    const loaded = (await import(moduleUrl)) as IdentityWasmEngine & {
      default?: (input?: {
        module_or_path: RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
      }) => Promise<unknown>;
    };
    if (loaded.default !== undefined) {
      const wasmUrl = new URL("../wasm/auths_proof_wasm_bg.wasm", import.meta.url);
      if (wasmUrl.protocol === "file:") {
        const { readFile } = await import("node:fs/promises");
        await loaded.default({ module_or_path: await readFile(wasmUrl) });
      } else {
        await loaded.default({ module_or_path: wasmUrl });
      }
    }
    for (const name of [
      "identityAbiVersionV1",
      "encodeIdentityDescriptorV1",
      "decodeIdentityDescriptorV1",
      "identityDescriptorSigningPreimageV1",
      "encodePublicIdentityV2",
      "createRawKeyPublicIdentityV2",
      "decodePublicIdentityV2",
      "decodeSignedIdentityMessageV2",
      "validateRawKeyPublicIdentityV2",
      "identityMessageSigningPreimageV2",
      "encodeSignedIdentityMessageV2",
      "verifyEd25519IdentityMessageV2",
    ] as const) {
      if (typeof loaded[name] !== "function") {
        throw new TypeError(`Auths WASM module omitted neutral identity export ${name}`);
      }
    }
    if (loaded.identityAbiVersionV1() !== 1) {
      throw new TypeError("Auths WASM module has an unsupported neutral identity ABI");
    }
    // Same guard, same WASM namespace object, therefore the same proxy the
    // workflow loader hands out: a failure on this path is an AuthsError too.
    return guardWasmBoundary(loaded);
  })();
  return packaged;
}

/** Loads only the adapter-neutral identity client surface. */
export async function loadIdentity(): Promise<IdentityClient> {
  return new IdentityClient(await loadPackagedIdentityEngine());
}

/** Loads the raw-key identity-method adapter explicitly. */
export async function loadRawKeyIdentityAdapter(): Promise<RawKeyIdentityAdapter> {
  return new RawKeyIdentityAdapter(await loadPackagedIdentityEngine());
}

/** Loads the raw-key plus Ed25519 message-authentication composition explicitly. */
export async function loadEd25519RawKeyAuthentication(): Promise<Ed25519RawKeyAuthentication> {
  return new Ed25519RawKeyAuthentication(await loadPackagedIdentityEngine());
}

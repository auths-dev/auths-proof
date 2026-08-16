/**
 * Neutral identity exchange and message authentication.
 *
 * This entry point does not initialize authority, capability, approval, policy, profile, or
 * lifecycle workflows. Canonical bytes are produced by the packaged Rust/WASM implementation;
 * callers select concrete identity-method and signature-suite adapters explicitly.
 */

import { guardWasmBoundary } from "./internal/wasm-boundary.js";

const DECODED_IDENTITY = Symbol("auths-decoded-identity");
const VALIDATED_IDENTITY = Symbol("auths-validated-identity");
const DECODED_MESSAGE = Symbol("auths-decoded-identity-message");
const AUTHENTICATED_MESSAGE = Symbol("auths-authenticated-identity-message");
const DECODED_DESCRIPTOR = Symbol("auths-decoded-identity-descriptor");
const RESOLVED_DESCRIPTOR = Symbol("auths-resolved-identity-descriptor");
const VALIDATED_DESCRIPTOR = Symbol("auths-validated-identity-descriptor");
const AUTHENTICATED_DESCRIPTOR = Symbol("auths-authenticated-identity-descriptor");

/*
 * The identity DESCRIPTOR tier is deleted (contract 6.2 / 11.6, ruling 10A).
 *
 * This module used to publish two complete identity APIs: a descriptor tier
 * (multi-key, multi-relationship, resolver-backed, with its own method and
 * suite registries) and the packet tier below. Python ships only the packet
 * tier, so a "semantic parity across T3 languages" claim covering the
 * descriptor tier was never true. Collapsing to one tier is the ruling; the
 * descriptor tier returns only if Python gains it in the same change.
 */

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

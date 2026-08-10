/**
 * Neutral identity exchange and message authentication.
 *
 * This entry point does not initialize authority, capability, approval, policy, profile, or
 * lifecycle workflows. Canonical bytes are produced by the packaged Rust/WASM implementation;
 * callers select concrete identity-method and signature-suite adapters explicitly.
 */

/** Structurally decoded identity data. It is safe to inspect or forward, but not yet trust. */
export interface DecodedIdentity {
  readonly validation: "decoded";
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
  readonly packet: Uint8Array;
}

/** Identity data whose method-specific identifier/material relationship has been validated. */
export interface ValidatedIdentity {
  readonly validation: "validated";
  readonly methodId: string;
  readonly identityId: string;
  readonly suiteId: string;
  readonly publicKey: Uint8Array;
  readonly packet: Uint8Array;
}

/** Exact application bytes authenticated by a validated public identity. */
export interface AuthenticatedIdentityMessage {
  readonly identity: ValidatedIdentity;
  readonly message: Uint8Array;
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
  validateRawKeyPublicIdentityV2(packet: Uint8Array): WasmIdentityFields;
  identityMessageSigningPreimageV2(packet: Uint8Array, message: Uint8Array): Uint8Array;
  encodeSignedIdentityMessageV2(
    packet: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Uint8Array;
  verifyEd25519IdentityMessageV2(packet: Uint8Array): WasmAuthenticatedIdentityMessage;
}

type IdentityFields = Omit<DecodedIdentity, "validation" | "packet">;

function copyFields(fields: WasmIdentityFields): IdentityFields {
  return {
    methodId: fields.methodId,
    identityId: fields.identityId,
    suiteId: fields.suiteId,
    publicKey: new Uint8Array(fields.publicKey),
  };
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

  /** Decodes canonical bytes without claiming identity validation. */
  decodePublicIdentity(packet: Uint8Array): DecodedIdentity {
    const fields = this.#engine.decodePublicIdentityV2(packet);
    try {
      return {
        validation: "decoded",
        ...copyFields(fields),
        packet: new Uint8Array(packet),
      };
    } finally {
      fields.free();
    }
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

/** Explicit opt-in adapter for suite-labelled self-certifying raw-key identities. */
export class RawKeyIdentityAdapter {
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
    return this.validate(packet);
  }

  /** Validates the raw-key identifier against the suite and public key. */
  validate(packet: Uint8Array): ValidatedIdentity {
    const fields = this.#engine.validateRawKeyPublicIdentityV2(packet);
    try {
      return {
        validation: "validated",
        ...copyFields(fields),
        packet: new Uint8Array(packet),
      };
    } finally {
      fields.free();
    }
  }
}

/** Explicit opt-in authentication adapter for raw-key Ed25519 signed messages. */
export class Ed25519RawKeyAuthentication {
  readonly #engine: IdentityWasmEngine;

  /** @internal Construct through {@link loadEd25519RawKeyAuthentication}. */
  constructor(engine: IdentityWasmEngine) {
    this.#engine = engine;
  }

  /** Verifies the identity relationship and signature, returning exact authenticated bytes. */
  verify(packet: Uint8Array): AuthenticatedIdentityMessage {
    const authenticated = this.#engine.verifyEd25519IdentityMessageV2(packet);
    try {
      return {
        identity: {
          validation: "validated",
          ...copyFields(authenticated),
          packet: new Uint8Array(packet),
        },
        message: new Uint8Array(authenticated.message),
      };
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
    return loaded;
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

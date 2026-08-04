import {
  type LoadWorkflowOptions,
  type WorkflowWasmEngine,
  createWorkflowClient,
} from "./workflow.js";

export {
  AuthsClient,
  AuthsWorkflowError,
  ProviderOperationError,
  type AgentIdentity,
  type ApprovalConfiguration,
  type ApprovalMode,
  type ApprovalPolicyReference,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type PrincipalDescriptor,
  type ProviderFailureKind,
  type ReviewField,
  type Signer,
  type SignerLifecycle,
  type SigningObjectKind,
  type SigningRequest,
  type SigningResponse,
  type TrustedAuthority,
  type TrustedAuthoritySnapshot,
  type WorkflowErrorCode,
} from "./workflow.js";

const MAX_RESULT_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 64;
const AUTHORIZED_TOKEN: unique symbol = Symbol("auths-authorized");

export type VerdictKind = "authorized" | "denied" | "indeterminate";
export type VerificationStage =
  | "decode"
  | "resolve"
  | "principal-control"
  | "authority"
  | "complete";

export interface Explanation {
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
}

export interface VerificationMetrics {
  readonly proofBytes: bigint;
  readonly actionBytes: bigint;
  readonly contextBytes: bigint;
  readonly objectCount: bigint;
  readonly planLeaves: bigint;
  readonly planDepth: bigint;
  readonly workUnits: bigint;
}

export class VerifiedAction {
  readonly #canonicalAction: Uint8Array;

  private constructor(
    token: typeof AUTHORIZED_TOKEN,
    canonicalAction: Uint8Array,
  ) {
    if (token !== AUTHORIZED_TOKEN) throw new TypeError("sealed Auths action");
    this.#canonicalAction = canonicalAction.slice();
  }

  static fromEngine(
    token: typeof AUTHORIZED_TOKEN,
    canonicalAction: Uint8Array,
  ): VerifiedAction {
    return new VerifiedAction(token, canonicalAction);
  }

  canonicalBytes(): Uint8Array {
    return this.#canonicalAction.slice();
  }
}

interface CommonResult {
  readonly code: string;
  readonly stage: VerificationStage;
  readonly explanation: Explanation;
  readonly metrics: VerificationMetrics;
  readonly requiredConfiguration: Uint8Array | undefined;
  readonly localConfiguration: Uint8Array;
  readonly resultCbor: Uint8Array;
}

export interface AuthorizedResult extends CommonResult {
  readonly kind: "authorized";
  readonly action: VerifiedAction;
}

export interface DeniedResult extends CommonResult {
  readonly kind: "denied";
}

export interface IndeterminateResult extends CommonResult {
  readonly kind: "indeterminate";
}

export type VerificationResult =
  | AuthorizedResult
  | DeniedResult
  | IndeterminateResult;

export interface PortableWasmEngine {
  verifyV1(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): Uint8Array;
}

export class Auths {
  readonly #engine: PortableWasmEngine;

  constructor(engine: PortableWasmEngine) {
    this.#engine = engine;
  }

  verify(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): VerificationResult {
    const bytes = this.#engine.verifyV1(
      proofCbor,
      canonicalActionCbor,
      trustedContextCbor,
    );
    const decoded = decodeResult(bytes);
    const explanation = explain(decoded.kind, decoded.code);
    const common = {
      code: decoded.code,
      stage: decoded.stage,
      explanation,
      metrics: decoded.metrics,
      requiredConfiguration: decoded.requiredConfiguration?.slice(),
      localConfiguration: decoded.localConfiguration.slice(),
      resultCbor: bytes.slice(),
    };
    if (decoded.kind === "authorized") {
      return {
        ...common,
        kind: "authorized",
        action: VerifiedAction.fromEngine(
          AUTHORIZED_TOKEN,
          canonicalActionCbor,
        ),
      };
    }
    return { ...common, kind: decoded.kind };
  }
}

export interface LoadPortableAuthsOptions {
  readonly moduleUrl?: string;
  readonly wasmInput?:
    | RequestInfo
    | URL
    | Response
    | BufferSource
    | WebAssembly.Module;
}

export async function loadPortableAuths(
  options: LoadPortableAuthsOptions = {},
): Promise<Auths> {
  if (options.moduleUrl === undefined && options.wasmInput === undefined) {
    const packaged = await loadPackagedWorkflowEngine();
    return new Auths({ verifyV1: packaged.verifyV1 });
  }
  const moduleUrl =
    options.moduleUrl ??
    new URL("../wasm/auths_proof_wasm.js", import.meta.url).href;
  const loaded = (await import(moduleUrl)) as {
    default?: (
      input?: { module_or_path: LoadPortableAuthsOptions["wasmInput"] },
    ) => Promise<unknown>;
    verifyV1: PortableWasmEngine["verifyV1"];
  };
  if (loaded.default !== undefined) {
    if (options.wasmInput === undefined) await loaded.default();
    else await loaded.default({ module_or_path: options.wasmInput });
  }
  if (typeof loaded.verifyV1 !== "function") {
    throw new TypeError("Auths WASM module omitted verifyV1");
  }
  return new Auths({ verifyV1: loaded.verifyV1 });
}

export type LoadAuthsOptions = LoadWorkflowOptions;

export async function loadAuths(options: LoadAuthsOptions) {
  const engine = await loadPackagedWorkflowEngine();
  return createWorkflowClient(options, engine);
}

async function loadPackagedWorkflowEngine(): Promise<
  WorkflowWasmEngine & PortableWasmEngine
> {
  const moduleUrl = new URL(
    "../wasm/auths_proof_wasm.js",
    import.meta.url,
  ).href;
  const loaded = (await import(moduleUrl)) as WorkflowWasmEngine &
    PortableWasmEngine & {
    default?: (input?: {
      module_or_path: RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
    }) => Promise<unknown>;
  };
  if (loaded.default !== undefined) {
    const wasmUrl = new URL(
      "../wasm/auths_proof_wasm_bg.wasm",
      import.meta.url,
    );
    if (wasmUrl.protocol === "file:") {
      const { readFile } = await import("node:fs/promises");
      await loaded.default({ module_or_path: await readFile(wasmUrl) });
    } else {
      await loaded.default({ module_or_path: wasmUrl });
    }
  }
  if (
    typeof loaded.authoringAbiVersionV1 !== "function" ||
    typeof loaded.canonicalPrincipalV1 !== "function" ||
    typeof loaded.configurationV1 !== "function" ||
    typeof loaded.prepareGrantSigningV1 !== "function" ||
    typeof loaded.prepareActionSigningV1 !== "function" ||
    typeof loaded.preparePrincipalStatusSigningV1 !== "function" ||
    typeof loaded.prepareGrantStatusSigningV1 !== "function" ||
    typeof loaded.completeGrantSigningV1 !== "function" ||
    typeof loaded.completeActionSigningV1 !== "function" ||
    typeof loaded.completePrincipalStatusSigningV1 !== "function" ||
    typeof loaded.completeGrantStatusSigningV1 !== "function" ||
    typeof loaded.verifyV1 !== "function"
  ) {
    throw new TypeError("Auths WASM module omitted workflow authoring exports");
  }
  return loaded;
}

type DecodedResult = {
  kind: VerdictKind;
  code: string;
  stage: VerificationStage;
  metrics: VerificationMetrics;
  requiredConfiguration: Uint8Array | undefined;
  localConfiguration: Uint8Array;
};

class Reader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    if (bytes.length === 0 || bytes.length > MAX_RESULT_BYTES) {
      throw new RangeError("Auths result exceeds byte bounds");
    }
    this.#bytes = bytes;
  }

  get complete(): boolean {
    return this.#offset === this.#bytes.length;
  }

  head(): [number, bigint] {
    const initial = this.#take();
    const major = initial >>> 5;
    const additional = initial & 31;
    if (additional < 24) return [major, BigInt(additional)];
    const width =
      additional === 24 ? 1 :
      additional === 25 ? 2 :
      additional === 26 ? 4 :
      additional === 27 ? 8 : 0;
    if (width === 0) throw new TypeError("indefinite CBOR is not canonical");
    let value = 0n;
    for (let index = 0; index < width; index += 1) {
      value = (value << 8n) | BigInt(this.#take());
    }
    if (
      (width === 1 && value < 24n) ||
      (width === 2 && value <= 0xffn) ||
      (width === 4 && value <= 0xffffn) ||
      (width === 8 && value <= 0xffff_ffffn)
    ) {
      throw new TypeError("non-minimal CBOR integer");
    }
    return [major, value];
  }

  uint(): bigint {
    const [major, value] = this.head();
    if (major !== 0) throw new TypeError("expected CBOR unsigned integer");
    return value;
  }

  text(): string {
    const [major, length] = this.head();
    if (major !== 3 || length > BigInt(this.#bytes.length - this.#offset)) {
      throw new TypeError("invalid CBOR text");
    }
    const size = Number(length);
    const value = new TextDecoder("utf-8", { fatal: true }).decode(
      this.#bytes.subarray(this.#offset, this.#offset + size),
    );
    this.#offset += size;
    return value;
  }

  nullableBytes(expectedLength: number): Uint8Array | undefined {
    const [major, length] = this.head();
    if (major === 7 && length === 22n) return undefined;
    if (
      major !== 2 ||
      length !== BigInt(expectedLength) ||
      length > BigInt(this.#bytes.length - this.#offset)
    ) {
      throw new TypeError("invalid CBOR bytes");
    }
    const size = Number(length);
    const value = this.#bytes.slice(this.#offset, this.#offset + size);
    this.#offset += size;
    return value;
  }

  bytes(expectedLength: number): Uint8Array {
    const value = this.nullableBytes(expectedLength);
    if (value === undefined) throw new TypeError("unexpected CBOR null");
    return value;
  }

  map(): number {
    const [major, length] = this.head();
    if (major !== 5 || length > 1_000_000n) {
      throw new TypeError("invalid CBOR map");
    }
    return Number(length);
  }

  skip(depth = 0): void {
    if (depth > MAX_DEPTH) throw new RangeError("CBOR depth exceeded");
    const [major, argument] = this.head();
    if (major === 0 || major === 1) return;
    if (major === 2 || major === 3) {
      const size = Number(argument);
      if (argument > BigInt(this.#bytes.length - this.#offset)) {
        throw new TypeError("truncated CBOR value");
      }
      this.#offset += size;
      return;
    }
    if (major === 4) {
      for (let index = 0; index < Number(argument); index += 1) {
        this.skip(depth + 1);
      }
      return;
    }
    if (major === 5) {
      for (let index = 0; index < Number(argument); index += 1) {
        this.skip(depth + 1);
        this.skip(depth + 1);
      }
      return;
    }
    if (major === 7 && [20n, 21n, 22n].includes(argument)) return;
    throw new TypeError("unsupported CBOR result value");
  }

  #take(): number {
    const value = this.#bytes[this.#offset];
    if (value === undefined) throw new TypeError("truncated CBOR result");
    this.#offset += 1;
    return value;
  }
}

function decodeResult(bytes: Uint8Array): DecodedResult {
  const reader = new Reader(bytes);
  if (reader.map() !== 16) throw new TypeError("invalid Auths result shape");
  let decision = -1;
  let stage = -1;
  let code = "";
  let metrics: bigint[] = [];
  let requiredConfiguration: Uint8Array | undefined;
  let localConfiguration: Uint8Array | undefined;
  let abiVersion = -1n;
  for (let index = 0; index < 16; index += 1) {
    const key = Number(reader.uint());
    if (key !== index) {
      throw new TypeError("result map keys are not the exact canonical sequence");
    }
    if (key === 0) decision = Number(reader.uint());
    else if (key === 1) stage = Number(reader.uint());
    else if (key === 2) {
      if (reader.map() !== 2 || reader.uint() !== 0n) {
        throw new TypeError("invalid Auths result code");
      }
      reader.uint();
      if (reader.uint() !== 1n) throw new TypeError("invalid result code key");
      code = reader.text();
    } else if (key === 11) {
      if (reader.map() !== 7) throw new TypeError("invalid result metrics");
      metrics = [];
      for (let metric = 0; metric < 7; metric += 1) {
        if (reader.uint() !== BigInt(metric)) {
          throw new TypeError("non-canonical result metrics");
        }
        metrics.push(reader.uint());
      }
    } else if (key === 13) {
      requiredConfiguration = reader.nullableBytes(32);
    } else if (key === 14) {
      localConfiguration = reader.bytes(32);
    } else if (key === 15) {
      abiVersion = reader.uint();
    } else {
      reader.skip();
    }
  }
  if (!reader.complete) throw new TypeError("trailing CBOR result bytes");
  if (abiVersion !== 2n) {
    throw new TypeError("unsupported Auths result ABI version");
  }
  if (
    !code ||
    metrics.length !== 7 ||
    localConfiguration === undefined
  ) {
    throw new TypeError("incomplete Auths result");
  }
  const kinds: VerdictKind[] = ["authorized", "denied", "indeterminate"];
  const stages: VerificationStage[] = [
    "decode",
    "resolve",
    "principal-control",
    "authority",
    "complete",
  ];
  const kind = kinds[decision];
  const stageName = stages[stage];
  if (kind === undefined || stageName === undefined) {
    throw new TypeError("unknown Auths result discriminator");
  }
  return {
    kind,
    code,
    stage: stageName,
    requiredConfiguration,
    localConfiguration,
    metrics: {
      proofBytes: metrics[0]!,
      actionBytes: metrics[1]!,
      contextBytes: metrics[2]!,
      objectCount: metrics[3]!,
      planLeaves: metrics[4]!,
      planDepth: metrics[5]!,
      workUnits: metrics[6]!,
    },
  };
}

function explain(kind: VerdictKind, code: string): Explanation {
  if (kind === "authorized") {
    return {
      code,
      message: "the proof establishes exact authority for this action",
      retryable: false,
    };
  }
  if (kind === "indeterminate") {
    return {
      code,
      message: "a required trustworthy fact or implementation is unavailable",
      retryable: true,
    };
  }
  return {
    code,
    message: "the supplied proof does not authorize this exact action",
    retryable: false,
  };
}

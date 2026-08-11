import { interpretVerification } from "./decode-common.js";
import { isPackagedEngine } from "./packaged-registry.js";
import { emitAuthsEvent, type TelemetryPort } from "../observability.js";

const AUTHORIZED_TOKEN: unique symbol = Symbol("auths-authorized");
const PACKAGED_VERIFIER_TOKEN: unique symbol = Symbol("auths-packaged-verifier");
const MAX_VERIFICATION_BATCH_BYTES = 16_777_216;
let mintVerifiedAction: (canonicalAction: Uint8Array) => VerifiedAction;
let mintPackagedVerifier: (engine: PortableWasmEngine) => Auths;

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

  private constructor(token: typeof AUTHORIZED_TOKEN, canonicalAction: Uint8Array) {
    if (token !== AUTHORIZED_TOKEN) throw new TypeError("sealed Auths action");
    this.#canonicalAction = canonicalAction.slice();
  }

  private static fromEngine(
    token: typeof AUTHORIZED_TOKEN,
    canonicalAction: Uint8Array,
  ): VerifiedAction {
    return new VerifiedAction(token, canonicalAction);
  }

  static {
    mintVerifiedAction = (canonicalAction) =>
      VerifiedAction.fromEngine(AUTHORIZED_TOKEN, canonicalAction);
  }

  canonicalBytes(): Uint8Array {
    return this.#canonicalAction.slice();
  }
}

interface CommonResult {
  readonly correlationId: string;
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

export type VerificationResult = AuthorizedResult | DeniedResult | IndeterminateResult;

export interface PortableWasmEngine {
  verifyV1(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): Uint8Array;
  verifyBatchV1?(
    items: readonly VerificationInput[],
  ): readonly Uint8Array[];
}

export interface VerificationInput {
  readonly proofCbor: Uint8Array;
  readonly canonicalActionCbor: Uint8Array;
  readonly trustedContextCbor: Uint8Array;
}

export interface VerificationBatchOptions {
  readonly signal?: AbortSignal;
  readonly chunkSize?: number;
  readonly correlationId?: () => string;
  readonly telemetry?: TelemetryPort;
}

export interface VerificationOptions {
  readonly correlationId?: string;
  readonly telemetry?: TelemetryPort;
}

/**
 * Capability-minting verifier bound to the SDK-packaged WASM subject.
 *
 * Application code cannot construct one and cannot supply the engine whose
 * output selects the authorized branch. Caller-supplied engines belong on
 * `@auths-dev/sdk/diagnostics`, whose results are never effect-capable.
 */
export class Auths {
  readonly #engine: PortableWasmEngine;

  private constructor(token: typeof PACKAGED_VERIFIER_TOKEN, engine: PortableWasmEngine) {
    if (token !== PACKAGED_VERIFIER_TOKEN) throw new TypeError("sealed Auths verifier");
    if (!isPackagedEngine(engine)) {
      throw new TypeError("Auths verification requires the packaged WASM engine");
    }
    this.#engine = engine;
    Object.freeze(this);
  }

  private static create(
    token: typeof PACKAGED_VERIFIER_TOKEN,
    engine: PortableWasmEngine,
  ): Auths {
    return new Auths(token, engine);
  }

  static {
    mintPackagedVerifier = (engine) => Auths.create(PACKAGED_VERIFIER_TOKEN, engine);
  }

  verify(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
    options: VerificationOptions = {},
  ): VerificationResult {
    const correlationId = parseCorrelationId(options.correlationId ?? nextCorrelationId());
    const started = performance.now();
    const bytes = this.#engine.verifyV1(proofCbor, canonicalActionCbor, trustedContextCbor);
    const result = verificationResult(bytes, canonicalActionCbor, correlationId);
    void emitAuthsEvent(options.telemetry, {
      name: "auths.verification.completed",
      timestamp: Date.now(),
      correlationId,
      operation: "verify",
      stage: "verification",
      outcome: result.kind === "authorized" ? "succeeded" : result.kind,
      durationMs: performance.now() - started,
      attributes: { code: result.code, stage: result.stage },
    });
    return result;
  }

  /**
   * Verifies a bounded collection through the native batch entry point.
   * Each item is interpreted and capability-minted exactly as an independent call to `verify`.
   */
  async verifyMany(
    items: readonly VerificationInput[],
    options: VerificationBatchOptions = {},
  ): Promise<readonly VerificationResult[]> {
    if (items.length === 0 || items.length > 256) {
      throw new RangeError("verification batch must contain between 1 and 256 items");
    }
    let totalBytes = 0;
    for (const item of items) {
      if (!(item.proofCbor instanceof Uint8Array) ||
          !(item.canonicalActionCbor instanceof Uint8Array) ||
          !(item.trustedContextCbor instanceof Uint8Array)) {
        throw new TypeError("verification batch contains non-byte input");
      }
      totalBytes += item.proofCbor.length + item.canonicalActionCbor.length +
        item.trustedContextCbor.length;
      if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_VERIFICATION_BATCH_BYTES) {
        throw new RangeError("verification batch exceeds the aggregate byte bound");
      }
    }
    const chunkSize = options.chunkSize ?? 32;
    if (!Number.isSafeInteger(chunkSize) || chunkSize < 1 || chunkSize > 256) {
      throw new RangeError("verification batch chunk size is outside bounds");
    }
    const verifyBatch = this.#engine.verifyBatchV1;
    if (verifyBatch === undefined) throw new TypeError("packaged verifier omitted batch support");
    const output: VerificationResult[] = [];
    for (let start = 0; start < items.length; start += chunkSize) {
      options.signal?.throwIfAborted();
      const chunk = items.slice(start, start + chunkSize).map((item) => ({
        proofCbor: item.proofCbor.slice(),
        canonicalActionCbor: item.canonicalActionCbor.slice(),
        trustedContextCbor: item.trustedContextCbor.slice(),
      }));
      const encoded = verifyBatch.call(this.#engine, chunk);
      if (encoded.length !== chunk.length) throw new TypeError("native verifier changed batch cardinality");
      encoded.forEach((bytes, index) => {
        const item = chunk[index];
        if (item === undefined) throw new TypeError("native verifier returned an invalid batch");
        const correlationId = parseCorrelationId(
          options.correlationId?.() ?? nextCorrelationId(),
        );
        const result = verificationResult(
          new Uint8Array(bytes),
          item.canonicalActionCbor,
          correlationId,
        );
        output.push(result);
        void emitAuthsEvent(options.telemetry, {
          name: "auths.verification.completed",
          timestamp: Date.now(),
          correlationId,
          operation: "verify-many",
          stage: "verification",
          outcome: result.kind === "authorized" ? "succeeded" : result.kind,
          attributes: { code: result.code, stage: result.stage },
        });
      });
      await Promise.resolve();
    }
    options.signal?.throwIfAborted();
    return Object.freeze(output);
  }
}

let correlationSequence = 0;

function nextCorrelationId(): string {
  correlationSequence = (correlationSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `auths-${Date.now().toString(36)}-${correlationSequence.toString(36)}`;
}

function parseCorrelationId(value: string): string {
  if (value.length === 0 || value.length > 128 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError("verification correlation ID is invalid");
  }
  return value;
}

function verificationResult(
  bytes: Uint8Array,
  canonicalActionCbor: Uint8Array,
  correlationId: string,
): VerificationResult {
  const { kind, ...common } = interpretVerification(bytes);
  if (kind === "authorized") {
    return {
      ...common,
      correlationId,
      kind,
      action: mintVerifiedAction(canonicalActionCbor),
    };
  }
  return { ...common, correlationId, kind };
}

/**
 * Package-private constructor for the capability-minting verifier.
 *
 * It is intentionally absent from every published entry point, and it refuses
 * any engine that the packaged loader did not produce.
 */
export function mintPackagedVerifierEngine(engine: PortableWasmEngine): Auths {
  return mintPackagedVerifier(engine);
}

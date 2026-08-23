import type { VerificationInput, VerificationResult } from "./verify.js";
import { authsErrorFromIssue } from "./product-errors.js";
import { issue } from "./internal/issues.js";
import { runtimeInfo } from "./index.js";
import { decodeDeterministic, encodeDeterministic } from "./internal/cbor.js";

const mediaType = "application/vnd.auths.remote-verification.v1+cbor" as const;

export interface BoundedTransportRequest {
  readonly url: URL;
  readonly method: "POST";
  readonly mediaType: typeof mediaType;
  readonly accept: typeof mediaType;
  readonly body: Uint8Array;
  readonly deadlineUnixMs: number;
  readonly signal: AbortSignal;
  readonly maximumResponseBytes: number;
}
export interface BoundedTransportResponse { readonly status: number; readonly mediaType: string; readonly body: Uint8Array }
export interface BoundedTransport extends AsyncDisposable {
  readonly contract: "bounded-byte-transport/2";
  send(request: BoundedTransportRequest): Promise<BoundedTransportResponse>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export interface RemoteVerifier extends AsyncDisposable {
  verify(input: VerificationInput & Readonly<{ signal?: AbortSignal }>): Promise<VerificationResult>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
interface RemoteVerifierCommonOptions {
  readonly endpoint: string | URL;
  readonly timeoutMs?: number;
  readonly maximumResponseBytes?: number;
  readonly allowInsecureLoopback?: boolean;
}
export type RemoteVerifierOptions = RemoteVerifierCommonOptions & (
  | Readonly<{ accessToken: string; transport?: never; transportOwnership?: never }>
  | Readonly<{ accessToken?: never; transport: BoundedTransport; transportOwnership?: "borrowed" | "owned" }>
);

export async function connectRemoteVerifier(options: RemoteVerifierOptions): Promise<RemoteVerifier> {
  const endpoint = parseEndpoint(options.endpoint, options.allowInsecureLoopback ?? false);
  const timeoutMs = boundedInteger(options.timeoutMs ?? 30_000, 1, 300_000, "timeout");
  const maximumResponseBytes = boundedInteger(options.maximumResponseBytes ?? 8 * 1024 * 1024, 1024, 16 * 1024 * 1024, "response limit");
  const injected = "transport" in options && options.transport !== undefined;
  const transport = injected ? options.transport : builtinTransport(options.accessToken);
  const owned = injected ? options.transportOwnership === "owned" : true;
  return new RemoteVerifierImpl(endpoint, timeoutMs, maximumResponseBytes, transport, owned);
}

class RemoteVerifierImpl implements RemoteVerifier {
  #state: "open" | "closing" | "closed" = "open";
  readonly #endpoint: URL;
  readonly #timeoutMs: number;
  readonly #maximumResponseBytes: number;
  readonly #transport: BoundedTransport;
  readonly #owned: boolean;

  constructor(endpoint: URL, timeoutMs: number, maximumResponseBytes: number, transport: BoundedTransport, owned: boolean) {
    this.#endpoint = endpoint;
    this.#timeoutMs = timeoutMs;
    this.#maximumResponseBytes = maximumResponseBytes;
    this.#transport = transport;
    this.#owned = owned;
  }

  async verify(input: VerificationInput & Readonly<{ signal?: AbortSignal }>): Promise<VerificationResult> {
    if (this.#state !== "open") throw new TypeError("Auths remote verifier is not open");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new DOMException("Auths verification timed out", "TimeoutError")), this.#timeoutMs);
    const abort = () => controller.abort(input.signal?.reason);
    input.signal?.addEventListener("abort", abort, { once: true });
    try {
      const correlationId = `auths-${crypto.randomUUID()}`;
      const registryDigest = (await runtimeInfo()).errorRegistryDigest;
      const body = encodeRequest(input, correlationId, registryDigest);
      const response = await this.#transport.send({
        url: new URL("/v2/verification/authorize", this.#endpoint),
        method: "POST",
        mediaType,
        accept: mediaType,
        body,
        deadlineUnixMs: Date.now() + this.#timeoutMs,
        signal: controller.signal,
        maximumResponseBytes: this.#maximumResponseBytes,
      });
      if (response.status !== 200 || response.mediaType.split(";", 1)[0]?.trim() !== mediaType || response.body.length > this.#maximumResponseBytes) {
        throw authsErrorFromIssue(issue("remote.response-malformed", { causes: ["invalid-response"] }));
      }
      return decodeResult(response.body, correlationId, registryDigest);
    } catch (error) {
      if (error instanceof Error && error.name === "AuthsError") throw error;
      if (controller.signal.aborted) throw authsErrorFromIssue(issue("remote.timeout", { causes: ["timeout"] }));
      throw authsErrorFromIssue(issue("remote.transport-unavailable", { causes: ["unavailable"] }));
    } finally {
      clearTimeout(timer);
      input.signal?.removeEventListener("abort", abort);
    }
  }

  async close(): Promise<void> {
    if (this.#state === "closed") return;
    this.#state = "closing";
    if (this.#owned) await this.#transport.close();
    this.#state = "closed";
  }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
}

function builtinTransport(accessToken: string): BoundedTransport {
  if (typeof accessToken !== "string" || accessToken.length < 1 || accessToken.length > 8192 || /[\u0000-\u001f\u007f]/u.test(accessToken)) throw new TypeError("invalid Auths access token");
  let closed = false;
  return {
    contract: "bounded-byte-transport/2",
    async send(request) {
      if (closed) throw new TypeError("transport is closed");
      const response = await fetch(request.url, {
        method: request.method,
        redirect: "error",
        headers: { "authorization": `Bearer ${accessToken}`, "content-type": request.mediaType, "accept": request.accept, "auths-error-registry-sha256": (await runtimeInfo()).errorRegistryDigest },
        body: request.body.slice().buffer as ArrayBuffer,
        signal: request.signal,
      });
      const declared = Number(response.headers.get("content-length") ?? "0");
      if (Number.isFinite(declared) && declared > request.maximumResponseBytes) throw new RangeError("remote response exceeds bound");
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.length > request.maximumResponseBytes) throw new RangeError("remote response exceeds bound");
      return Object.freeze({ status: response.status, mediaType: response.headers.get("content-type") ?? "", body: bytes });
    },
    async close() { closed = true; },
    async [Symbol.asyncDispose]() { closed = true; },
  };
}

function parseEndpoint(value: string | URL, allowInsecureLoopback: boolean): URL {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) throw new TypeError("endpoint must be an origin");
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost";
  if (url.protocol !== "https:" && !(allowInsecureLoopback && loopback && url.protocol === "http:")) throw new TypeError("Auths endpoint must use HTTPS");
  return new URL(url.origin);
}

function boundedInteger(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new RangeError(`${name} is outside bounds`);
  return value;
}

function encodeRequest(input: VerificationInput, correlationId: string, registryDigest: string): Uint8Array {
  if (!(input.proof instanceof Uint8Array) || !(input.action instanceof Uint8Array) || !(input.trustedContext instanceof Uint8Array)) throw new TypeError("verification input must contain bytes");
  return encodeDeterministic(new Map<unknown, unknown>([
    [0, 1], [1, input.proof], [2, input.action], [3, input.trustedContext],
    [4, correlationId], [5, hexBytes(registryDigest)],
  ]));
}

function decodeResult(bytes: Uint8Array, correlationId: string, registryDigest: string): VerificationResult {
  const value = decodeDeterministic(bytes);
  if (!(value instanceof Map) || value.size !== 11 || value.get(0) !== 1 || value.get(4) !== correlationId || !equalBytes(asBytes(value.get(10)), hexBytes(registryDigest))) throw new TypeError("malformed remote verification result");
  const kinds = ["authorized", "denied", "indeterminate"] as const;
  const stages = ["decode", "resolve", "principal-control", "authority", "complete"] as const;
  const kind = kinds[asNumber(value.get(1))]; const stage = stages[asNumber(value.get(3))];
  const metrics = value.get(5);
  if (kind === undefined || stage === undefined || !(metrics instanceof Map)) throw new TypeError("malformed remote verification result");
  const common = {
    code: asString(value.get(2)), stage, correlationId,
    metrics: Object.freeze({ proofBytes: asBigInt(metrics.get(0)), actionBytes: asBigInt(metrics.get(1)), contextBytes: asBigInt(metrics.get(2)), objectCount: asBigInt(metrics.get(3)), planLeaves: asBigInt(metrics.get(4)), planDepth: asBigInt(metrics.get(5)), workUnits: asBigInt(metrics.get(6)) }),
    ...(value.get(6) === null ? {} : { requiredConfiguration: asBytes(value.get(6)) }),
    executedConfiguration: asBytes(value.get(7)), decisionBytes: asBytes(value.get(8)),
  };
  if (kind === "authorized") return Object.freeze({ ...common, kind: "authorized" as const });
  const envelope = value.get(9); const code = envelope instanceof Map && typeof envelope.get("code") === "string" ? envelope.get("code") as string : kind === "denied" ? "core.authorization-denied" : "core.authorization-indeterminate";
  if (kind === "denied") return Object.freeze({ ...common, kind: "denied" as const, issue: issue(code as never) }) as VerificationResult;
  return Object.freeze({ ...common, kind: "indeterminate" as const, issue: issue(code as never) }) as VerificationResult;
}

function hexBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new TypeError("invalid registry digest");
  return Uint8Array.from({ length: 32 }, (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
}
function asBytes(value: unknown): Uint8Array { if (!(value instanceof Uint8Array)) throw new TypeError("expected bytes"); return value; }
function asString(value: unknown): string { if (typeof value !== "string") throw new TypeError("expected string"); return value; }
function asNumber(value: unknown): number { if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new TypeError("expected integer"); return value; }
function asBigInt(value: unknown): bigint { return typeof value === "bigint" ? value : BigInt(asNumber(value)); }
function equalBytes(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]); }

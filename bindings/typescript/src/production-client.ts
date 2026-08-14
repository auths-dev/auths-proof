import type { ProductionProfile } from "./profiles.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

const CONTENT_TYPE = "application/auths+cbor";
const MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_TIMEOUT_MS = 15_000;
const authorityBytes = new WeakMap<ProductionAuthority, Uint8Array>();
const receiptBytes = new WeakMap<ProductionReceipt, Uint8Array>();
const referenceValues = new WeakMap<ProductionRecoveryReference, string>();

export type ProductStep = "create" | "delegate" | "execute" | "resume" | "verify";
export type RetryClass = "never" | "backoff" | "resume" | "reconcile";

export interface ProductionTransportRequest {
  readonly url: URL;
  readonly body: Uint8Array;
  readonly contentType: typeof CONTENT_TYPE;
  readonly timeoutMs: number;
}

export interface ProductionTransportResponse {
  readonly status: number;
  readonly contentType: string;
  readonly body: Uint8Array;
}

export interface ProductionTransport {
  send(request: ProductionTransportRequest): Promise<ProductionTransportResponse>;
}

export interface ProductionAuthsOptions {
  readonly endpoint: string | URL;
  readonly identity: Uint8Array;
  readonly profile: ProductionProfile;
  readonly transport?: ProductionTransport;
  readonly timeoutMs?: number;
}

export interface ProductionAuthority {
  readonly kind: "authority";
  toJSON(): never;
}

class ProductionAuthorityValue implements ProductionAuthority {
  readonly kind = "authority" as const;

  constructor(bytes: Uint8Array) {
    authorityBytes.set(this, bytes.slice());
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths authority is opaque");
  }
}

export interface ProductionReceipt {
  readonly kind: "receipt";
  toJSON(): never;
}

class ProductionReceiptValue implements ProductionReceipt {
  readonly kind = "receipt" as const;

  constructor(bytes: Uint8Array) {
    receiptBytes.set(this, bytes.slice());
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths receipt bytes require an explicit disclosure operation");
  }
}

export interface ProductionRecoveryReference {
  readonly kind: "recovery-reference";
  toJSON(): never;
}

class ProductionRecoveryReferenceValue implements ProductionRecoveryReference {
  readonly kind = "recovery-reference" as const;

  constructor(value: string) {
    referenceValues.set(this, value);
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths recovery references are opaque");
  }
}

export interface ProductionDenied {
  readonly kind: "denied";
  readonly step: ProductStep;
  readonly code: string;
  readonly retry: "never";
}

export interface ProductionIndeterminate {
  readonly kind: "indeterminate";
  readonly step: ProductStep;
  readonly code: string;
  readonly retry: "backoff" | "reconcile";
}

export interface ProductionRecoverable {
  readonly kind: "recoverable";
  readonly step: "execute" | "resume";
  readonly code: string;
  readonly retry: "resume";
  readonly reference: ProductionRecoveryReference;
}

export interface ProductionCompleted {
  readonly kind: "completed";
  readonly step: "execute" | "resume";
  readonly value?: Uint8Array;
  readonly receipt: ProductionReceipt;
}

export interface ProductionVerified {
  readonly kind: "verified";
  readonly step: "verify";
  readonly value?: Uint8Array;
}

export interface ProductionRejected {
  readonly kind: "rejected";
  readonly step: "verify";
  readonly code: string;
  readonly retry: "never";
}

export type ProductionAuthorityResult = ProductionAuthority | ProductionDenied | ProductionIndeterminate;
export type ProductionExecutionResult = ProductionCompleted | ProductionDenied | ProductionIndeterminate | ProductionRecoverable;
export type ProductionVerificationResult = ProductionVerified | ProductionRejected | ProductionIndeterminate;

export interface ProductionAuths {
  create(request: Uint8Array): Promise<ProductionAuthorityResult>;
  delegate(
    authority: ProductionAuthority,
    subject: Uint8Array,
    attenuation?: Uint8Array,
  ): Promise<ProductionAuthorityResult>;
  execute(authority: ProductionAuthority, action: Uint8Array): Promise<ProductionExecutionResult>;
  resume(reference: ProductionRecoveryReference): Promise<ProductionExecutionResult>;
  verify(value: ProductionAuthority | ProductionReceipt | Uint8Array): Promise<ProductionVerificationResult>;
}

interface NativeProductionEngine {
  productionClientContractVersionV1(): number;
  encodeProductionRequestV1(input: Readonly<{
    readonly verb: ProductStep;
    readonly profile: string;
    readonly identity: Uint8Array;
    readonly authority?: Uint8Array;
    readonly body?: Uint8Array;
    readonly recoveryReference?: string;
  }>): Uint8Array;
  decodeProductionResponseV1(input: Uint8Array): string;
  decodeProductionRequestV1(input: Uint8Array): string;
  encodeProductionDelegationV1(subject: Uint8Array, attenuation: Uint8Array): Uint8Array;
}

interface NativeProjection {
  readonly contractVersion: number;
  readonly kind: "completed" | "denied" | "indeterminate" | "recoverable" | "verified" | "rejected";
  readonly code: string | null;
  readonly retry: RetryClass;
  readonly recoveryReference: string | null;
  readonly value: string | null;
  readonly receipt: string | null;
}

class ProductionAuthsClient implements ProductionAuths {
  readonly #endpoint: URL;
  readonly #identity: Uint8Array;
  readonly #profile: ProductionProfile;
  readonly #transport: ProductionTransport;
  readonly #timeoutMs: number;

  constructor(options: ProductionAuthsOptions) {
    this.#endpoint = parseEndpoint(options.endpoint);
    if (!(options.identity instanceof Uint8Array) || options.identity.length === 0 || options.identity.length > 65_536) {
      throw new TypeError("Auths identity bytes are outside production bounds");
    }
    if (!isProductionProfile(options.profile)) throw new TypeError("Auths production profile is unsupported");
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
      throw new TypeError("Auths production timeout is outside bounds");
    }
    this.#identity = options.identity.slice();
    this.#profile = options.profile;
    this.#transport = options.transport ?? fetchProductionTransport;
    this.#timeoutMs = timeoutMs;
  }

  async create(request: Uint8Array): Promise<ProductionAuthorityResult> {
    const projection = await this.#call("create", request);
    if (projection.kind === "completed") {
      return productionAuthority(requiredValue(projection));
    }
    return projectAuthorityFailure("create", projection);
  }

  async delegate(
    authority: ProductionAuthority,
    subject: Uint8Array,
    attenuation: Uint8Array = new Uint8Array([0x80]),
  ): Promise<ProductionAuthorityResult> {
    const authorityValue = readAuthority(authority);
    const body = await encodeDelegationInput(subject, attenuation);
    const projection = await this.#call("delegate", body, authorityValue);
    if (projection.kind === "completed") {
      return productionAuthority(requiredValue(projection));
    }
    return projectAuthorityFailure("delegate", projection);
  }

  async execute(authority: ProductionAuthority, action: Uint8Array): Promise<ProductionExecutionResult> {
    return projectExecution("execute", await this.#call("execute", action, readAuthority(authority)));
  }

  async resume(reference: ProductionRecoveryReference): Promise<ProductionExecutionResult> {
    const value = referenceValues.get(reference);
    if (value === undefined) throw new TypeError("forged Auths recovery reference");
    return projectExecution("resume", await this.#call("resume", undefined, undefined, value));
  }

  async verify(value: ProductionAuthority | ProductionReceipt | Uint8Array): Promise<ProductionVerificationResult> {
    const bytes = value instanceof Uint8Array
      ? value
      : value.kind === "authority"
        ? readAuthority(value)
        : readReceipt(value);
    const projection = await this.#call("verify", bytes);
    if (projection.kind === "verified") {
      return Object.freeze({
        kind: "verified" as const,
        step: "verify" as const,
        ...(projection.value === null ? {} : { value: decodeBase64Url(projection.value) }),
      });
    }
    if (projection.kind === "rejected") {
      return Object.freeze({ kind: "rejected" as const, step: "verify" as const, code: requiredCode(projection), retry: "never" as const });
    }
    if (projection.kind === "indeterminate") return projectIndeterminate("verify", projection);
    throw new TypeError("native response outcome does not match verify");
  }

  async #call(
    step: ProductStep,
    body?: Uint8Array,
    authority?: Uint8Array,
    recoveryReference?: string,
  ): Promise<NativeProjection> {
    const engine = await productionEngine();
    const requestBody = engine.encodeProductionRequestV1({
      verb: step,
      profile: this.#profile.id,
      identity: this.#identity,
      ...(authority === undefined ? {} : { authority }),
      ...(body === undefined ? {} : { body }),
      ...(recoveryReference === undefined ? {} : { recoveryReference }),
    });
    const path = endpointPath(step, this.#profile.id);
    let response: ProductionTransportResponse;
    try {
      response = await this.#transport.send(Object.freeze({
        url: new URL(path, this.#endpoint),
        body: requestBody,
        contentType: CONTENT_TYPE,
        timeoutMs: this.#timeoutMs,
      }));
    } catch {
      return Object.freeze({
        contractVersion: 1,
        kind: "indeterminate",
        code: "core.runtime-unavailable",
        retry: "backoff",
        recoveryReference: null,
        value: null,
        receipt: null,
      });
    }
    if (response.status < 200 || response.status >= 300 || normalizeContentType(response.contentType) !== CONTENT_TYPE) {
      return Object.freeze({
        contractVersion: 1,
        kind: "indeterminate",
        code: "core.malformed-input",
        retry: "backoff",
        recoveryReference: null,
        value: null,
        receipt: null,
      });
    }
    if (!(response.body instanceof Uint8Array) || response.body.length === 0 || response.body.length > MAX_RESPONSE_BYTES) {
      throw new TypeError("Auths production response is outside bounds");
    }
    return parseProjection(engine.decodeProductionResponseV1(response.body));
  }
}

export function createProductionAuths(options: ProductionAuthsOptions): ProductionAuths {
  return new ProductionAuthsClient(options);
}

const fetchProductionTransport: ProductionTransport = Object.freeze({
  async send(request: ProductionTransportRequest): Promise<ProductionTransportResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), request.timeoutMs);
    try {
      const response = await fetch(request.url, {
        method: "POST",
        body: request.body as BodyInit,
        headers: Object.freeze({ "content-type": request.contentType, accept: request.contentType }),
        redirect: "error",
        credentials: "omit",
        signal: controller.signal,
      });
      const declared = Number(response.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
        throw new TypeError("Auths production response is outside bounds");
      }
      const body = await readBoundedBody(response);
      return Object.freeze({
        status: response.status,
        contentType: response.headers.get("content-type") ?? "",
        body,
      });
    } finally {
      clearTimeout(timeout);
    }
  },
});

async function productionEngine(): Promise<NativeProductionEngine> {
  const engine = await loadPackagedWorkflowEngine();
  const native = engine as unknown as NativeProductionEngine;
  if (native.productionClientContractVersionV1() !== 1) {
    throw new TypeError("Auths production client contract mismatch");
  }
  return native;
}

async function encodeDelegationInput(subject: Uint8Array, attenuation: Uint8Array): Promise<Uint8Array> {
  if (!(subject instanceof Uint8Array) || subject.length === 0 || subject.length > 65_536
      || !(attenuation instanceof Uint8Array) || attenuation.length === 0 || attenuation.length > 65_536) {
    throw new TypeError("Auths delegation input is outside bounds");
  }
  return (await productionEngine()).encodeProductionDelegationV1(subject, attenuation);
}

function parseEndpoint(value: string | URL): URL {
  const endpoint = new URL(value);
  if (endpoint.protocol !== "https:" || endpoint.username !== "" || endpoint.password !== ""
      || endpoint.search !== "" || endpoint.hash !== "" || !["", "/"].includes(endpoint.pathname)) {
    throw new TypeError("Auths production endpoint must be an HTTPS origin");
  }
  return endpoint;
}

function isProductionProfile(value: ProductionProfile): boolean {
  return value !== null && typeof value === "object" && [
    "auths.opentofu.saved-plan-apply/1",
    "auths.postgresql.bounded-update/1",
    "auths.github.issue-address/1",
  ].includes(value.id);
}

function endpointPath(step: ProductStep, profile: ProductionProfile["id"]): string {
  if (step === "create") return "/v1/authority/create";
  if (step === "delegate") return "/v1/authority/delegate";
  if (step === "resume") return "/v1/workflows/resume";
  if (step === "verify") return "/v1/authority/verify";
  if (profile === "auths.opentofu.saved-plan-apply/1") return "/v1/profiles/opentofu/saved-plan-apply/execute";
  if (profile === "auths.postgresql.bounded-update/1") return "/v1/profiles/postgresql/bounded-update/execute";
  return "/v1/profiles/github/issue-address/execute";
}

function parseProjection(value: string): NativeProjection {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object") throw new TypeError("native response projection is invalid");
  const projection = parsed as Record<string, unknown>;
  if (projection.contractVersion !== 1
      || !["completed", "denied", "indeterminate", "recoverable", "verified", "rejected"].includes(String(projection.kind))
      || !["never", "backoff", "resume", "reconcile"].includes(String(projection.retry))) {
    throw new TypeError("native response projection is invalid");
  }
  return projection as unknown as NativeProjection;
}

function projectAuthorityFailure(step: "create" | "delegate", projection: NativeProjection): ProductionDenied | ProductionIndeterminate {
  if (projection.kind === "denied") {
    return Object.freeze({ kind: "denied", step, code: requiredCode(projection), retry: "never" });
  }
  if (projection.kind === "indeterminate") return projectIndeterminate(step, projection);
  throw new TypeError(`native response outcome does not match ${step}`);
}

function projectExecution(step: "execute" | "resume", projection: NativeProjection): ProductionExecutionResult {
  if (projection.kind === "completed") {
    if (projection.receipt === null) throw new TypeError("native response omitted receipt bytes");
    return Object.freeze({
      kind: "completed",
      step,
      ...(projection.value === null ? {} : { value: decodeBase64Url(projection.value) }),
      receipt: productionReceipt(decodeBase64Url(projection.receipt)),
    });
  }
  if (projection.kind === "denied") {
    return Object.freeze({ kind: "denied", step, code: requiredCode(projection), retry: "never" });
  }
  if (projection.kind === "indeterminate") return projectIndeterminate(step, projection);
  if (projection.kind === "recoverable" && projection.recoveryReference !== null) {
    return Object.freeze({
      kind: "recoverable",
      step,
      code: requiredCode(projection),
      retry: "resume",
      reference: productionRecoveryReference(projection.recoveryReference),
    });
  }
  throw new TypeError(`native response outcome does not match ${step}`);
}

function projectIndeterminate(step: ProductStep, projection: NativeProjection): ProductionIndeterminate {
  if (projection.retry !== "backoff" && projection.retry !== "reconcile") {
    throw new TypeError("native indeterminate result has invalid retry class");
  }
  return Object.freeze({ kind: "indeterminate", step, code: requiredCode(projection), retry: projection.retry });
}

function productionAuthority(bytes: Uint8Array): ProductionAuthority {
  if (bytes.length === 0) throw new TypeError("native response omitted authority bytes");
  return new ProductionAuthorityValue(bytes);
}

function productionReceipt(bytes: Uint8Array): ProductionReceipt {
  if (bytes.length === 0) throw new TypeError("native response omitted receipt bytes");
  return new ProductionReceiptValue(bytes);
}

function productionRecoveryReference(value: string): ProductionRecoveryReference {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError("native response returned an invalid recovery reference");
  }
  return new ProductionRecoveryReferenceValue(value);
}

function requiredValue(projection: NativeProjection): Uint8Array {
  if (projection.value === null) throw new TypeError("native response omitted value bytes");
  return decodeBase64Url(projection.value);
}

function requiredCode(projection: NativeProjection): string {
  if (projection.code === null) throw new TypeError("native response omitted stable error code");
  return projection.code;
}

function readAuthority(authority: ProductionAuthority): Uint8Array {
  const value = authorityBytes.get(authority);
  if (value === undefined) throw new TypeError("forged Auths authority");
  return value.slice();
}

function readReceipt(receipt: ProductionReceipt): Uint8Array {
  const value = receiptBytes.get(receipt);
  if (value === undefined) throw new TypeError("forged Auths receipt");
  return value.slice();
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new TypeError("native response encoding is invalid");
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function normalizeContentType(value: string): string {
  return value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
}

async function readBoundedBody(response: Response): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new TypeError("Auths production response is outside bounds");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}
